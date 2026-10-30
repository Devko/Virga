// Usage: node scripts/deploy.ts [--dry-run]
//
// Sets up and deploys a Virga instance into the tool account: runs the apps'
// builds, checks the Wrangler configs against each other, creates missing D1
// databases and applies their migrations, checks the master key (D-15), then
// deploys virga-broker, virga-core and virga-web in that order. Safe to run
// again. Wrangler always gets the checked config as --config, and only while
// it holds the bytes that were checked; it never gets a named environment,
// loads no .env file, gets only allowlisted variables of the operator's
// environment, and runs only while its files are those recorded before the
// builds (R6-01).
//
// A real deploy uses CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID of the
// tool account. --dry-run runs `wrangler deploy --dry-run` for each Worker,
// passes no credentials to Wrangler and changes nothing.
// See docs/operator/guide.md.
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { ConfigError, checkAppDir, readWorkerConfig, type WorkerConfig } from "./lib/config.ts";
import { loadExports } from "./lib/exports.ts";
import {
  API_VARS,
  apiOverrides,
  configOverrides,
  droppedSettings,
  processRunner,
  proxyNotice,
  RefusedError,
  redact,
  UNSAFE_VARS,
  unsafeVars,
} from "./lib/run.ts";
import {
  build,
  type Context,
  checkMasterKey,
  checkWebSettings,
  DeployError,
  deploy,
  describeDatabases,
  describeMasterKey,
  ensureDatabases,
  planWebSettings,
  reportWebSettings,
  WEB_SETTINGS,
  withSecretsFile,
} from "./lib/steps.ts";
import { checkTopology, WORKERS } from "./lib/topology.ts";
import {
  describeChanges,
  recordWranglers,
  WranglerError,
  wranglerChanges,
} from "./lib/wrangler.ts";

const ACCOUNT_ID = /^[0-9a-f]{32}$/;

/** Values that never reach the output: the API token and uploaded settings. */
const secrets: string[] = [];

const USAGE = "usage: node scripts/deploy.ts [--dry-run]";

async function main(): Promise<number> {
  let values: { "dry-run"?: boolean; help?: boolean };
  try {
    ({ values } = parseArgs({
      options: { "dry-run": { type: "boolean", default: false }, help: { type: "boolean" } },
    }));
  } catch {
    console.error(USAGE);
    return 2;
  }
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  const dryRun = values["dry-run"] === true;
  const root = fileURLToPath(new URL("..", import.meta.url));

  const unsafe = unsafeVars(process.env);
  if (unsafe.length > 0) {
    for (const name of unsafe) {
      console.error(`error: unset ${name}: ${UNSAFE_VARS[name.toUpperCase()]}`);
    }
    return 1;
  }

  const overrides = configOverrides(process.env);
  if (overrides.length > 0) {
    console.error(
      `error: unset ${overrides.join(" and ")}; the deploy checks and deploys only the top-level configuration of each Worker`,
    );
    return 1;
  }
  const redirects = apiOverrides(process.env);
  if (redirects.length > 0) {
    console.error(
      `error: unset ${redirects.join(" and ")}; the deploy sends the token only to ${API_VARS.CLOUDFLARE_API_BASE_URL}`,
    );
    return 1;
  }

  const token = process.env.CLOUDFLARE_API_TOKEN ?? "";
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID ?? "";
  if (!dryRun) {
    if (token === "") {
      console.error("error: set CLOUDFLARE_API_TOKEN to the deploy token of the tool account");
      return 1;
    }
    if (!ACCOUNT_ID.test(accountId)) {
      console.error("error: set CLOUDFLARE_ACCOUNT_ID to the 32-character ID of the tool account");
      return 1;
    }
  }

  secrets.push(token);
  const credentials = dryRun ? "none" : "token";
  for (const line of proxyNotice(process.env)) console.log(line);
  const dropped = droppedSettings(process.env, credentials);
  if (dropped.length > 0) {
    console.log(
      `Wrangler does not get ${dropped.join(", ")}: the deploy passes it only the variables in the operator guide`,
    );
  }

  // Before the builds: what needs no parsed config, and the Wrangler each app runs.
  const present = WORKERS.filter(({ app, optional }) => {
    if (checkAppDir(root, app) !== null) return true;
    if (optional) console.log(`apps/${app}: no Wrangler config, skipped`);
    return false;
  });
  const dirOf = (app: string) => join(root, "apps", app);
  const wranglers = recordWranglers(present.map(({ app }) => dirOf(app)));
  for (const install of new Map([...wranglers.values()].map((w) => [w.bin, w])).values()) {
    console.log(
      `Wrangler ${install.version}: ${install.bin}, ${install.files.size} files recorded before the builds`,
    );
  }
  const ctx: Context = {
    run: processRunner({ credentials, secrets: () => secrets, wranglers }),
    log: (line) => console.log(line),
    todo: [],
  };

  // Every build runs before any config is read, so that the checks below see
  // what the builds left. Builds get no credentials (R3-05), but their code
  // can write anywhere the operator can (R6-01).
  for (const { app, name } of present) await build(ctx, { name, dir: dirOf(app) });

  const cache = new Map<string, Map<string, string>>();
  for (const [dir, install] of wranglers) {
    const changed = describeChanges(dir, wranglerChanges(install, cache));
    if (changed !== null) throw new WranglerError(changed);
  }
  const workers: WorkerConfig[] = [];
  for (const { app } of present) {
    checkAppDir(root, app);
    const config = readWorkerConfig(root, app);
    if (config === null) {
      throw new ConfigError(`apps/${app}: its Wrangler config was removed during the builds`);
    }
    workers.push(config);
  }

  const issues = checkTopology(workers, loadExports);
  for (const issue of issues) console.error(`${issue.level}: ${issue.message}`);
  if (issues.some((i) => i.level === "error")) return 1;
  ctx.log(`Configs: ${workers.map((w) => w.name).join(", ")}; service bindings match`);

  const broker = workers.find((w) => w.app === "broker") as WorkerConfig;
  const web = workers.find((w) => w.app === "web");
  ctx.log(dryRun ? "Plan (dry run, nothing is changed):" : `Plan for account ${accountId}:`);
  describeDatabases(ctx, workers);
  const keySetup = describeMasterKey(ctx, broker, dryRun);
  const webPlan = web ? planWebSettings(web, process.env) : null;
  if (web && webPlan) {
    const fromEnv = Object.keys(webPlan.upload);
    ctx.log(
      `  ${web.name} settings ${WEB_SETTINGS.join(", ")}: ${fromEnv.length > 0 ? `${fromEnv.join(", ")} from the environment; ` : ""}others as existing secrets or vars`,
    );
    secrets.push(...Object.values(webPlan.upload));
    for (const name of webPlan.placeholders) {
      ctx.todo.push(`${web.displayPath}: var ${name} still holds a placeholder`);
    }
  }

  if (!dryRun) {
    await ensureDatabases(ctx, workers);
    await checkMasterKey(ctx, broker, keySetup);
    if (web && webPlan) await checkWebSettings(ctx, web, webPlan);
  }

  for (const worker of workers) {
    const upload = worker === web && webPlan && !dryRun ? webPlan.upload : {};
    await withSecretsFile(upload, (secretsFile) => deploy(ctx, worker, { dryRun, secretsFile }));
  }

  if (!dryRun && web && webPlan) await reportWebSettings(ctx, web, webPlan);
  if (!dryRun && web) {
    ctx.todo.push(
      `Check that Worker-level Access protects ${web.name} (operator guide, "Access for the UI")`,
    );
  }

  ctx.log(dryRun ? "Dry run complete." : "Deploy complete.");
  for (const item of ctx.todo) console.log(`ACTION: ${item}`);
  return 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  if (
    error instanceof DeployError ||
    error instanceof ConfigError ||
    error instanceof RefusedError ||
    error instanceof WranglerError
  ) {
    console.error(`error: ${redact(error.message, secrets)}`);
  } else {
    const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
    console.error(`error: ${redact(detail, secrets)}`);
  }
  process.exitCode = 1;
}
