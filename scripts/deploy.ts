// Usage: node scripts/deploy.ts [--dry-run]
//
// Sets up and deploys a Virga instance into the tool account: checks the
// Wrangler configs against each other, creates missing D1 databases and
// applies their migrations, checks the master key (D-15), then deploys
// virga-broker, virga-core and virga-web in that order. Safe to run again.
//
// A real deploy uses CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID of the
// tool account. --dry-run runs `wrangler deploy --dry-run` for each Worker,
// passes no credentials to Wrangler and changes nothing.
// See docs/operator/guide.md.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { ConfigError, readWorkerConfig, type WorkerConfig } from "./lib/config.ts";
import { loadExports } from "./lib/exports.ts";
import { processRunner, redact } from "./lib/run.ts";
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
} from "./lib/steps.ts";
import { checkTopology, WORKERS } from "./lib/topology.ts";

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
  const ctx: Context = {
    run: processRunner({ credentials: dryRun ? "none" : "token", secrets: () => secrets }),
    log: (line) => console.log(line),
    todo: [],
  };

  const workers: WorkerConfig[] = [];
  for (const { app, optional } of WORKERS) {
    const config = readWorkerConfig(root, app);
    if (config) workers.push(config);
    else if (optional) ctx.log(`apps/${app}: no Wrangler config, skipped`);
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
    await build(ctx, worker);
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

/**
 * Writes the values to a private temporary file for `wrangler deploy
 * --secrets-file` and removes it afterwards. No file without values.
 */
async function withSecretsFile(
  values: Record<string, string>,
  fn: (path: string | undefined) => Promise<void>,
) {
  if (Object.keys(values).length === 0) return fn(undefined);
  const dir = mkdtempSync(join(tmpdir(), "virga-deploy-"));
  try {
    const path = join(dir, "secrets.json");
    writeFileSync(path, JSON.stringify(values), { mode: 0o600 });
    await fn(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

try {
  process.exitCode = await main();
} catch (error) {
  if (error instanceof DeployError || error instanceof ConfigError) {
    console.error(`error: ${redact(error.message, secrets)}`);
  } else {
    const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
    console.error(`error: ${redact(detail, secrets)}`);
  }
  process.exitCode = 1;
}
