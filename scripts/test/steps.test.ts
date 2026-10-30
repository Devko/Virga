import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { WorkerConfig } from "../lib/config.ts";
import { masterKeySetup } from "../lib/master-key.ts";
import type { Command, Result } from "../lib/run.ts";
import {
  type Context,
  checkMasterKey,
  checkWebSettings,
  DeployError,
  deploy,
  describeMasterKey,
  ensureDatabases,
  planWebSettings,
  reportWebSettings,
  withSecretsFile,
} from "../lib/steps.ts";
import { worker } from "./helpers.ts";

const ok = (stdout = ""): Result => ({ code: 0, stdout, stderr: "" });
const fail = (stderr: string): Result => ({ code: 1, stdout: "", stderr });

/** A runner that answers from a table keyed by the joined arguments and records every call. */
function fakeContext(answers: Record<string, Result>) {
  const calls: string[] = [];
  const commands: Command[] = [];
  const ctx: Context = {
    run: async (command: Command) => {
      const key = command.args.join(" ");
      calls.push(`${command.cwd.split("/").pop()}: ${key}`);
      commands.push(command);
      return answers[key] ?? ok();
    },
    log: () => {},
    todo: [],
  };
  return { ctx, calls, commands };
}

let root = "";
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "virga-steps-"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

/** A Worker directory with one migration file per D1 binding. */
function app(
  name: string,
  d1: { binding: string; databaseName: string | null; databaseId?: string }[],
) {
  const dir = join(root, name);
  mkdirSync(join(dir, "migrations"), { recursive: true });
  writeFileSync(join(dir, "migrations", "0001_init.sql"), "SELECT 1;");
  return worker(name, {
    dir,
    d1: d1.map((d) => ({ databaseId: null, migrationsDir: "migrations", ...d })),
  });
}

describe("ensureDatabases", () => {
  it("creates only missing databases and migrates all of them", async () => {
    const broker = app("broker", [{ binding: "VAULT", databaseName: "virga-vault" }]);
    const core = app("core", [{ binding: "INDEX", databaseName: "virga-index" }]);
    const list = JSON.stringify([
      { uuid: "1", name: "virga-index" },
      { uuid: "2", name: "other" },
    ]);
    const { ctx, calls } = fakeContext({ "d1 list --json": ok(`banner\n${list}`) });
    await ensureDatabases(ctx, [broker, core]);
    expect(calls).toEqual([
      "broker: d1 list --json",
      "broker: d1 create virga-vault --update-config=false",
      "broker: d1 migrations apply virga-vault --remote",
      "core: d1 migrations apply virga-index --remote",
    ]);
  });

  it("creates nothing on a second run", async () => {
    const broker = app("broker", [{ binding: "VAULT", databaseName: "virga-vault" }]);
    const list = JSON.stringify([{ uuid: "1", name: "virga-vault" }]);
    const { ctx, calls } = fakeContext({ "d1 list --json": ok(list) });
    await ensureDatabases(ctx, [broker]);
    expect(calls.some((c) => c.includes("d1 create"))).toBe(false);
  });

  it("fails when a configured database_id does not exist", async () => {
    const broker = app("broker", [
      { binding: "VAULT", databaseName: "virga-vault", databaseId: "abc" },
    ]);
    const { ctx } = fakeContext({ "d1 list --json": ok("[]") });
    await expect(ensureDatabases(ctx, [broker])).rejects.toThrow(/database_id abc does not exist/);
  });

  it("stops when Wrangler fails", async () => {
    const broker = app("broker", [{ binding: "VAULT", databaseName: "virga-vault" }]);
    const { ctx } = fakeContext({
      "d1 list --json": ok("[]"),
      "d1 create virga-vault --update-config=false": fail("Authentication error"),
    });
    await expect(ensureDatabases(ctx, [broker])).rejects.toThrow(DeployError);
  });

  const VAULT_ID = "6f1c3a52-0b7e-4f38-9d0a-5c2e8b7a4d11";
  const INDEX_ID = "a9e2d4b0-7c31-4e5f-8a26-0f4b9c1d3e72";
  const LIST = ok(
    JSON.stringify([
      { uuid: VAULT_ID, name: "virga-vault" },
      { uuid: INDEX_ID, name: "virga-index" },
    ]),
  );

  it("R3-06: refuses a database_id of another database before creating or migrating anything", async () => {
    const broker = app("broker", [{ binding: "VAULT", databaseName: "virga-vault" }]);
    // Names the index, points at the vault: Wrangler binds and migrates by database_id.
    const core = app("core", [
      { binding: "INDEX", databaseName: "virga-index", databaseId: VAULT_ID },
    ]);
    const { ctx, calls } = fakeContext({ "d1 list --json": LIST });
    await expect(ensureDatabases(ctx, [broker, core])).rejects.toThrow(
      `apps/core/wrangler.jsonc: D1 binding INDEX has database_id ${VAULT_ID}, which is virga-vault, not virga-index`,
    );
    expect(calls).toEqual(["broker: d1 list --json"]);
  });

  it("R3-06: refuses a database that two Workers bind, by UUID", async () => {
    const broker = app("broker", [{ binding: "VAULT", databaseName: "virga-vault" }]);
    const core = app("core", [
      { binding: "INDEX", databaseName: "virga-index", databaseId: INDEX_ID },
      { binding: "COPY", databaseName: "virga-vault", databaseId: VAULT_ID },
    ]);
    const { ctx, calls } = fakeContext({ "d1 list --json": LIST });
    await expect(ensureDatabases(ctx, [broker, core])).rejects.toThrow(
      `apps/core/wrangler.jsonc: D1 database ${VAULT_ID} (virga-vault) is also bound by virga-broker`,
    );
    expect(calls).toEqual(["broker: d1 list --json"]);
  });

  it("R3-06: accepts a database_id that matches its database_name", async () => {
    const core = app("core", [
      { binding: "INDEX", databaseName: "virga-index", databaseId: INDEX_ID },
    ]);
    const { ctx, calls } = fakeContext({ "d1 list --json": LIST });
    await ensureDatabases(ctx, [core]);
    expect(calls).toEqual([
      "core: d1 list --json",
      "core: d1 migrations apply virga-index --remote",
    ]);
  });
});

const TABLE = (rows: string[]) =>
  ["│ Name │ ID │ Comment │ Scopes │ Status │ Created │ Modified │", ...rows].join("\n");
const STORE = "023e105f4ecef8ad9ca31a8372d0c353";
const LIST_STORE = `secrets-store secret list ${STORE} --remote --per-page 100 --page 1`;
const storeBroker = () =>
  worker("broker", {
    secretsStore: [{ binding: "MASTER_KEY_STORE", storeId: STORE, secretName: "virga-master-key" }],
  });

describe("master key", () => {
  it("passes when the store holds an active secret with the workers scope", async () => {
    const broker = storeBroker();
    const { ctx } = fakeContext({
      "secret list --format json": ok("[]"),
      [LIST_STORE]: ok(TABLE(["│ virga-master-key │ id │ │ workers │ active │ x │ x │"])),
    });
    await checkMasterKey(ctx, broker, masterKeySetup(broker));
    expect(ctx.todo).toEqual([]);
  });

  it("fails with the command to create a missing secret", async () => {
    const broker = storeBroker();
    const { ctx } = fakeContext({
      "secret list --format json": fail('Worker "virga-broker" not found.'),
      [LIST_STORE]: fail("List request returned no secrets."),
    });
    await expect(checkMasterKey(ctx, broker, masterKeySetup(broker))).rejects.toThrow(
      /secrets-store secret create 023e105f4ecef8ad9ca31a8372d0c353 --name virga-master-key --scopes workers/,
    );
  });

  it("fails when the secret lacks the workers scope", async () => {
    const broker = storeBroker();
    const { ctx } = fakeContext({
      "secret list --format json": ok("[]"),
      [LIST_STORE]: ok(TABLE(["│ virga-master-key │ id │ │ ai_gateway │ active │ x │ x │"])),
    });
    await expect(checkMasterKey(ctx, broker, masterKeySetup(broker))).rejects.toThrow(
      /workers scope/,
    );
  });

  it("stops on output it cannot read", async () => {
    const broker = storeBroker();
    const { ctx } = fakeContext({ "secret list --format json": ok("Secret Name: X") });
    await expect(checkMasterKey(ctx, broker, masterKeySetup(broker))).rejects.toThrow(
      /wrangler secret list printed no JSON/,
    );
  });

  it("asks to delete an ignored MASTER_KEY secret", async () => {
    const broker = storeBroker();
    const { ctx } = fakeContext({
      "secret list --format json": ok('[{ "name": "MASTER_KEY", "type": "secret_text" }]'),
      [LIST_STORE]: ok(TABLE(["│ virga-master-key │ id │ │ workers │ active │ x │ x │"])),
    });
    await checkMasterKey(ctx, broker, masterKeySetup(broker));
    expect(ctx.todo).toEqual([
      expect.stringContaining("is ignored while the Secrets Store binding exists"),
    ]);
  });

  it("requires the MASTER_KEY secret in fallback mode, also before the first deploy", async () => {
    const broker = worker("broker");
    const missing = fakeContext({
      "secret list --format json": fail('Worker "virga-broker" not found.'),
    });
    await expect(checkMasterKey(missing.ctx, broker, masterKeySetup(broker))).rejects.toThrow(
      /openssl rand -base64 32 \| npx wrangler secret put MASTER_KEY/,
    );
    const present = fakeContext({
      "secret list --format json": ok('[{ "name": "MASTER_KEY", "type": "secret_text" }]'),
    });
    await checkMasterKey(present.ctx, broker, masterKeySetup(broker));
  });

  it("blocks a deploy with the placeholder store ID but not a dry run", () => {
    const broker = worker("broker", {
      secretsStore: [
        { binding: "MASTER_KEY_STORE", storeId: "<SECRETS_STORE_ID>", secretName: "k" },
      ],
    });
    const { ctx } = fakeContext({});
    expect(() => describeMasterKey(ctx, broker, false)).toThrow(/placeholder/);
    describeMasterKey(ctx, broker, true);
    expect(ctx.todo).toEqual([expect.stringContaining("placeholder")]);
  });
});

describe("web settings", () => {
  const web = (o: Partial<WorkerConfig> = {}) => worker("web", o);

  it("takes values from the environment, vars from the config, and expects the rest as secrets", () => {
    const plan = planWebSettings(
      web({ vars: { ADMIN_EMAILS: "a@example.com" }, requiredSecrets: ["EXTRA"] }),
      { ACCESS_AUD: " aud-tag ", ACCESS_TEAM_DOMAIN: "" },
    );
    expect(plan).toEqual({
      upload: { ACCESS_AUD: "aud-tag" },
      expected: ["ACCESS_TEAM_DOMAIN", "EXTRA"],
      placeholders: [],
    });
  });

  it("R3-04: never uploads the deploy token, even when secrets.required names it", () => {
    const plan = planWebSettings(web({ requiredSecrets: ["CLOUDFLARE_API_TOKEN"] }), {
      CLOUDFLARE_API_TOKEN: "cfat_0123456789abcdefghij",
      ACCESS_AUD: "aud-tag",
    });
    expect(plan.upload).toEqual({ ACCESS_AUD: "aud-tag" });
  });

  it("R3-04: uploads only the web settings; other required secrets must already exist", async () => {
    const config = web({ requiredSecrets: ["EXTRA"] });
    const plan = planWebSettings(config, { EXTRA: "from-the-shell" });
    expect(plan.upload).toEqual({});
    expect(plan.expected).toContain("EXTRA");
    const { ctx } = fakeContext({ "secret list --format json": ok("[]") });
    await expect(checkWebSettings(ctx, config, plan)).rejects.toThrow(
      /requires the secrets EXTRA. Create the secrets, then run the deploy again:\n {2}npx wrangler secret put EXTRA/,
    );
  });

  it("R3-04: writes only web settings into a private secrets file and removes it", async () => {
    let path = "";
    await withSecretsFile({ ACCESS_AUD: "aud-tag" }, async (p) => {
      path = p ?? "";
      expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ ACCESS_AUD: "aud-tag" });
      expect(statSync(path).mode & 0o777).toBe(0o600);
    });
    expect(existsSync(path)).toBe(false);
    await withSecretsFile({}, async (p) => expect(p).toBeUndefined());
    await expect(
      withSecretsFile({ CLOUDFLARE_API_TOKEN: "cfat_0123456789abcdefghij" }, async () => {}),
    ).rejects.toThrow(/refusing to upload CLOUDFLARE_API_TOKEN/);
  });

  it("flags placeholder vars", () => {
    const plan = planWebSettings(web({ vars: { ACCESS_AUD: "<AUD>", ADMIN_EMAILS: "" } }), {});
    expect(plan.placeholders).toEqual(["ACCESS_AUD", "ADMIN_EMAILS"]);
  });

  it("fails before a first deploy that lacks required secrets", async () => {
    const config = web({ requiredSecrets: ["ACCESS_AUD"] });
    const { ctx } = fakeContext({
      "secret list --format json": fail('Worker "virga-web" not found.'),
    });
    await expect(checkWebSettings(ctx, config, planWebSettings(config, {}))).rejects.toThrow(
      /does not exist yet and requires the secrets ACCESS_AUD/,
    );
  });

  it("does not block on optional settings, but reports them after the deploy", async () => {
    const config = web();
    const { ctx, calls } = fakeContext({
      "secret list --format json": ok('[{ "name": "ACCESS_AUD", "type": "secret_text" }]'),
    });
    const plan = planWebSettings(config, {});
    await checkWebSettings(ctx, config, plan);
    expect(calls).toEqual([]);
    await reportWebSettings(ctx, config, plan);
    expect(ctx.todo).toEqual([
      expect.stringContaining("still needs ACCESS_TEAM_DOMAIN, ADMIN_EMAILS"),
    ]);
  });
});

describe("Wrangler config", () => {
  it("R3-03: names the checked config in every Wrangler call", async () => {
    const broker = {
      ...app("broker", [{ binding: "VAULT", databaseName: "virga-vault" }]),
      secretsStore: storeBroker().secretsStore,
    };
    const core = app("core", [{ binding: "INDEX", databaseName: "virga-index" }]);
    const web = worker("web", { requiredSecrets: ["ACCESS_AUD"] });
    const { ctx, commands } = fakeContext({
      "d1 list --json": ok(JSON.stringify([{ uuid: "1", name: "virga-index" }])),
      [LIST_STORE]: ok(TABLE(["│ virga-master-key │ id │ │ workers │ active │ x │ x │"])),
      "secret list --format json": ok('[{ "name": "ACCESS_AUD", "type": "secret_text" }]'),
    });
    await ensureDatabases(ctx, [broker, core]);
    await checkMasterKey(ctx, broker, masterKeySetup(broker));
    const plan = planWebSettings(web, {});
    await checkWebSettings(ctx, web, plan);
    await reportWebSettings(ctx, web, plan);
    for (const w of [broker, core, web]) await deploy(ctx, w, { dryRun: false });

    const configOf = new Map([broker, core, web].map((w) => [w.dir, w.configPath]));
    expect(commands.length).toBeGreaterThan(8);
    for (const command of commands) {
      expect(command.bin).toBe("wrangler");
      expect(command.bin === "wrangler" && command.config).toBe(configOf.get(command.cwd));
    }
  });
});

describe("deploy", () => {
  it("runs a dry run without config autodetection", async () => {
    const { ctx, calls } = fakeContext({});
    await deploy(ctx, worker("core"), { dryRun: true });
    expect(calls).toEqual(["core: deploy --autoconfig=false --dry-run"]);
  });

  it("passes the secrets file", async () => {
    const { ctx, calls } = fakeContext({});
    await deploy(ctx, worker("web"), { dryRun: false, secretsFile: "/tmp/x/secrets.json" });
    expect(calls).toEqual(["web: deploy --autoconfig=false --secrets-file /tmp/x/secrets.json"]);
  });

  it("fails when Wrangler fails", async () => {
    const { ctx } = fakeContext({
      "deploy --autoconfig=false": fail("Authentication error [code: 10000]"),
    });
    await expect(deploy(ctx, worker("broker"), { dryRun: false })).rejects.toThrow(
      /deploying virga-broker failed/,
    );
  });
});
