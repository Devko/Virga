import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assetsDirectoryProblem, assetsLinkProblem, type WorkerConfig } from "./config.ts";
import {
  MASTER_KEY_SECRET,
  type MasterKeySetup,
  masterKeySetup,
  parseSecretTable,
  type StoreSecret,
} from "./master-key.ts";
import { parseJsonOutput, type Runner, type WranglerCommand } from "./run.ts";

export class DeployError extends Error {}

export interface Context {
  run: Runner;
  log: (line: string) => void;
  /** Things the operator still has to do; printed at the end. */
  todo: string[];
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function json(stdout: string, command: string): unknown {
  try {
    return parseJsonOutput(stdout);
  } catch {
    throw new DeployError(`${command} printed no JSON; is Wrangler up to date (pnpm install)?`);
  }
}

/**
 * A Wrangler call on the config the script checked, never one Wrangler finds
 * itself, and only while the file holds the bytes that were checked (R6-01).
 */
const wrangler = (worker: WorkerConfig, args: string[], capture = false): WranglerCommand => ({
  bin: "wrangler",
  cwd: worker.dir,
  config: worker.configPath,
  configSha256: worker.configSha256,
  args,
  capture,
});

async function must(ctx: Context, worker: WorkerConfig, args: string[], what: string) {
  const result = await ctx.run(wrangler(worker, args));
  if (result.code !== 0)
    throw new DeployError(`${what} failed (wrangler exited with ${result.code})`);
}

export interface D1Database {
  uuid: string;
  name: string;
}

export function parseD1List(stdout: string): D1Database[] {
  const parsed = json(stdout, "wrangler d1 list --json");
  if (!Array.isArray(parsed))
    throw new DeployError("wrangler d1 list --json did not return a list");
  return parsed.flatMap((db) =>
    isRecord(db) && typeof db.uuid === "string" && typeof db.name === "string"
      ? [{ uuid: db.uuid, name: db.name }]
      : [],
  );
}

const migrationFiles = (worker: WorkerConfig, dir: string) => {
  const path = join(worker.dir, dir);
  return existsSync(path) ? readdirSync(path).filter((f) => f.endsWith(".sql")) : [];
};

/** Prints which databases a deploy would create or migrate. Reads nothing remote. */
export function describeDatabases(ctx: Context, workers: readonly WorkerConfig[]) {
  for (const worker of workers) {
    for (const db of worker.d1) {
      const files = migrationFiles(worker, db.migrationsDir).length;
      ctx.log(
        `  ${worker.name}: D1 ${db.databaseName ?? db.databaseId} (${db.binding}), created if missing, ${files} migration file(s)`,
      );
    }
  }
}

/**
 * Checks the D1 bindings against the account's databases. Wrangler binds and
 * migrates by database_id, so a database_id must name the database of its
 * database_name, and each database, by UUID, belongs to one Worker (D-08,
 * R3-06). Otherwise a binding named after the index could reach the vault.
 */
export function checkDatabaseIds(
  workers: readonly WorkerConfig[],
  existing: readonly D1Database[],
) {
  const owners = new Map<string, string>();
  for (const worker of workers) {
    for (const db of worker.d1) {
      let found: D1Database | undefined;
      if (db.databaseId !== null) {
        found = existing.find((e) => e.uuid === db.databaseId);
        if (!found) {
          throw new DeployError(
            `${worker.displayPath}: D1 database_id ${db.databaseId} does not exist in this account`,
          );
        }
        if (found.name !== db.databaseName) {
          throw new DeployError(
            `${worker.displayPath}: D1 binding ${db.binding} has database_id ${db.databaseId}, which is ${found.name}, not ${db.databaseName ?? "(no database_name)"}`,
          );
        }
      } else {
        found = existing.find((e) => e.name === db.databaseName);
      }
      if (!found) continue;
      const owner = owners.get(found.uuid);
      if (owner !== undefined && owner !== worker.name) {
        throw new DeployError(
          `${worker.displayPath}: D1 database ${found.uuid} (${found.name}) is also bound by ${owner}; each database belongs to one Worker (D-08)`,
        );
      }
      owners.set(found.uuid, worker.name);
    }
  }
}

/**
 * Creates every D1 database that does not exist yet, by name, and applies
 * its migrations. Both steps are no-ops when nothing is missing. Nothing is
 * created or migrated unless every binding passes checkDatabaseIds.
 */
export async function ensureDatabases(ctx: Context, workers: readonly WorkerConfig[]) {
  const first = workers[0];
  if (!first || workers.every((w) => w.d1.length === 0)) return;
  const listed = await ctx.run(wrangler(first, ["d1", "list", "--json"], true));
  if (listed.code !== 0) throw new DeployError("wrangler d1 list failed");
  const existing = parseD1List(listed.stdout);
  checkDatabaseIds(workers, existing);

  for (const worker of workers) {
    for (const db of worker.d1) {
      if (db.databaseId === null && db.databaseName !== null) {
        if (existing.some((e) => e.name === db.databaseName)) {
          ctx.log(`D1 ${db.databaseName} exists`);
        } else {
          ctx.log(`Creating D1 ${db.databaseName}`);
          await must(
            ctx,
            worker,
            ["d1", "create", db.databaseName, "--update-config=false"],
            `creating D1 ${db.databaseName}`,
          );
        }
      }
      const target = db.databaseName ?? db.binding;
      if (migrationFiles(worker, db.migrationsDir).length === 0) continue;
      ctx.log(`Applying migrations to ${target}`);
      await must(
        ctx,
        worker,
        ["d1", "migrations", "apply", target, "--remote"],
        `migrating D1 ${target}`,
      );
    }
  }
}

/** Secret names of a deployed Worker, or null when the Worker does not exist yet. */
export async function workerSecrets(ctx: Context, worker: WorkerConfig): Promise<string[] | null> {
  const result = await ctx.run(wrangler(worker, ["secret", "list", "--format", "json"], true));
  if (result.code !== 0) {
    if (/not found/i.test(result.stderr + result.stdout)) return null;
    throw new DeployError(`listing the secrets of ${worker.name} failed`);
  }
  const parsed = json(result.stdout, "wrangler secret list");
  if (!Array.isArray(parsed)) throw new DeployError(`unexpected secret list for ${worker.name}`);
  return parsed.flatMap((s) => (isRecord(s) && typeof s.name === "string" ? [s.name] : []));
}

const PER_PAGE = 100;
const MAX_PAGES = 20;

async function storeSecrets(ctx: Context, broker: WorkerConfig, storeId: string) {
  const all: StoreSecret[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const result = await ctx.run(
      wrangler(
        broker,
        [
          "secrets-store",
          "secret",
          "list",
          storeId,
          "--remote",
          "--per-page",
          String(PER_PAGE),
          "--page",
          String(page),
        ],
        true,
      ),
    );
    // Wrangler exits non-zero on an empty page ("List request returned no secrets").
    if (result.code !== 0) {
      if (/no secrets/i.test(result.stderr + result.stdout)) break;
      throw new DeployError(`listing the secrets of Secrets Store ${storeId} failed`);
    }
    const rows = parseSecretTable(result.stdout);
    all.push(...rows);
    if (rows.length < PER_PAGE) break;
  }
  return all;
}

const KEY_HOWTO = {
  store: (storeId: string, name: string) =>
    `openssl rand -base64 32 | npx wrangler secrets-store secret create ${storeId} --name ${name} --scopes workers --remote   (in apps/broker)`,
  secret: `openssl rand -base64 32 | npx wrangler secret put ${MASTER_KEY_SECRET}   (in apps/broker)`,
};

/** Static part of the master key check: what the broker config says (D-15). */
export function describeMasterKey(ctx: Context, broker: WorkerConfig, dryRun: boolean) {
  const setup = masterKeySetup(broker);
  if (setup.mode === "worker_secret") {
    ctx.log(`  master key: Worker secret ${MASTER_KEY_SECRET} on ${broker.name} (fallback, D-15)`);
    return setup;
  }
  ctx.log(`  master key: Secrets Store ${setup.storeId}, secret ${setup.secretName} (D-15)`);
  if (setup.placeholder) {
    const message = `${broker.displayPath}: store_id is a placeholder; set it to your Secrets Store ID (npx wrangler secrets-store store list --remote), or remove the secrets_store_secrets entry to use the ${MASTER_KEY_SECRET} fallback`;
    if (!dryRun) throw new DeployError(message);
    ctx.todo.push(message);
  } else if (setup.unusualId) {
    ctx.log(`  warning: store_id ${setup.storeId} is not 32 hex characters; check it`);
  }
  return setup;
}

/**
 * Remote part of the master key check. The broker deploys only when its key
 * exists, so it never starts without one.
 */
export async function checkMasterKey(ctx: Context, broker: WorkerConfig, setup: MasterKeySetup) {
  const brokerSecrets = await workerSecrets(ctx, broker);
  if (setup.mode === "worker_secret") {
    if (!brokerSecrets?.includes(MASTER_KEY_SECRET)) {
      throw new DeployError(
        `${broker.name} has no ${MASTER_KEY_SECRET} secret. Create it, then run the deploy again:\n  ${KEY_HOWTO.secret}`,
      );
    }
    ctx.log(`Master key: secret ${MASTER_KEY_SECRET} is set on ${broker.name}`);
    return;
  }
  const secret = (await storeSecrets(ctx, broker, setup.storeId)).find(
    (s) => s.name === setup.secretName,
  );
  if (!secret) {
    throw new DeployError(
      `Secrets Store ${setup.storeId} has no secret ${setup.secretName}. Create it, then run the deploy again:\n  ${KEY_HOWTO.store(setup.storeId, setup.secretName)}`,
    );
  }
  if (!secret.scopes.includes("workers")) {
    throw new DeployError(
      `secret ${setup.secretName} lacks the workers scope; Workers cannot bind it. Add the scope in the Secrets Store dashboard`,
    );
  }
  if (secret.status !== "active") {
    throw new DeployError(`secret ${setup.secretName} is ${secret.status || "not active"}`);
  }
  ctx.log(`Master key: ${setup.secretName} exists in Secrets Store ${setup.storeId}`);
  if (brokerSecrets?.includes(MASTER_KEY_SECRET)) {
    ctx.todo.push(
      `${broker.name} has a ${MASTER_KEY_SECRET} secret, which is ignored while the Secrets Store binding exists; delete it with npx wrangler secret delete ${MASTER_KEY_SECRET} (in apps/broker)`,
    );
  }
}

/**
 * Settings the web Worker reads (operator guide, Access for the UI). The only
 * values the deploy takes from its environment and uploads (R3-04).
 */
export const WEB_SETTINGS = ["ACCESS_TEAM_DOMAIN", "ACCESS_AUD", "ADMIN_EMAILS"] as const;

const isWebSetting = (name: string) => (WEB_SETTINGS as readonly string[]).includes(name);

export interface SettingsPlan {
  /** Web settings from the environment, uploaded as secrets with the deploy. */
  upload: Record<string, string>;
  /** Names that must already be secrets on the Worker. */
  expected: string[];
  /** Names that are vars in the config but still hold a placeholder. */
  placeholders: string[];
}

/**
 * Decides where each web setting comes from: a var in the config, a value in
 * the deploy environment (uploaded as a secret), or an existing secret. Other
 * names in secrets.required are never read from the environment, so a name
 * added there cannot copy the deploy token or any other variable into the
 * internet-facing Worker; they must already be secrets.
 */
export function planWebSettings(
  web: WorkerConfig,
  env: Readonly<Record<string, string | undefined>>,
): SettingsPlan {
  const plan: SettingsPlan = { upload: {}, expected: [], placeholders: [] };
  for (const name of new Set<string>([...WEB_SETTINGS, ...web.requiredSecrets])) {
    if (Object.hasOwn(web.vars, name)) {
      const value = web.vars[name];
      if (typeof value !== "string" || value.trim() === "" || /[<>]/.test(value)) {
        plan.placeholders.push(name);
      }
      continue;
    }
    const value = isWebSetting(name) ? env[name] : undefined;
    if (value !== undefined && value.trim() !== "") plan.upload[name] = value.trim();
    else plan.expected.push(name);
  }
  return plan;
}

const putHint = (names: readonly string[]) =>
  names.map((n) => `npx wrangler secret put ${n}   (in apps/web)`).join("\n  ");

function missingHint(names: readonly string[]) {
  const settings = names.filter(isWebSetting);
  return settings.length > 0
    ? `Set ${settings.join(", ")} as environment variables of the deploy, or create the secrets:\n  ${putHint(names)}`
    : `Create the secrets, then run the deploy again:\n  ${putHint(names)}`;
}

/** Before the web deploy: fail early where Wrangler would refuse the deploy anyway. */
export async function checkWebSettings(ctx: Context, web: WorkerConfig, plan: SettingsPlan) {
  const mandatory = plan.expected.filter((n) => web.requiredSecrets.includes(n));
  if (mandatory.length === 0) return;
  const existing = await workerSecrets(ctx, web);
  const missing = mandatory.filter((n) => !existing?.includes(n));
  if (missing.length === 0) return;
  throw new DeployError(
    `${web.name} ${existing === null ? "does not exist yet and " : ""}requires the secrets ${missing.join(", ")}. ${missingHint(missing)}`,
  );
}

/** After the web deploy: settings that are still missing, so that the UI cannot check Access. */
export async function reportWebSettings(ctx: Context, web: WorkerConfig, plan: SettingsPlan) {
  if (plan.expected.length === 0) return;
  const existing = (await workerSecrets(ctx, web)) ?? [];
  const missing = plan.expected.filter((n) => !existing.includes(n));
  if (missing.length > 0) {
    ctx.todo.push(
      `${web.name} still needs ${missing.join(", ")} (operator guide, "Access for the UI"):\n  ${putHint(missing)}`,
    );
  }
}

/**
 * Writes the values to a private temporary file for `wrangler deploy
 * --secrets-file` and removes it afterwards. No file without values, and
 * nothing but web settings in it.
 */
export async function withSecretsFile(
  values: Record<string, string>,
  fn: (path: string | undefined) => Promise<void>,
) {
  const other = Object.keys(values).filter((name) => !isWebSetting(name));
  if (other.length > 0) {
    throw new DeployError(
      `refusing to upload ${other.join(", ")}; the deploy uploads only ${WEB_SETTINGS.join(", ")}`,
    );
  }
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

/**
 * Runs the app's build script, if it has one. The deploy runs every build
 * before it reads any config (R6-01).
 */
export async function build(ctx: Context, worker: Pick<WorkerConfig, "name" | "dir">) {
  const pkgPath = join(worker.dir, "package.json");
  if (!existsSync(pkgPath)) return;
  const pkg: unknown = JSON.parse(readFileSync(pkgPath, "utf8"));
  const scripts = isRecord(pkg) && isRecord(pkg.scripts) ? pkg.scripts : {};
  if (typeof scripts.build !== "string") return;
  ctx.log(`Building ${worker.name}`);
  const result = await ctx.run({ bin: "pnpm", cwd: worker.dir, args: ["run", "build"] });
  if (result.code !== 0) throw new DeployError(`building ${worker.name} failed`);
}

/**
 * Runs `wrangler deploy`. The assets directory is checked again first: the
 * build has filled it by now and may have replaced it with a link (R5-03).
 */
export async function deploy(
  ctx: Context,
  worker: WorkerConfig,
  options: { dryRun: boolean; secretsFile?: string },
) {
  const assets = assetsDirectoryProblem(worker) ?? assetsLinkProblem(worker);
  if (assets !== null) throw new DeployError(`${worker.displayPath}: ${assets}`);
  const args = ["deploy", "--autoconfig=false"];
  if (options.dryRun) args.push("--dry-run");
  if (options.secretsFile) args.push("--secrets-file", options.secretsFile);
  ctx.log(`${options.dryRun ? "Dry run" : "Deploying"}: ${worker.name}`);
  await must(ctx, worker, args, `${options.dryRun ? "dry run of" : "deploying"} ${worker.name}`);
}
