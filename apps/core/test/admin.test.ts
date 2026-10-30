import { createExecutionContext, introspectWorkflow } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { createReader } from "@virga/cf-api";
import { fixtureTransport } from "@virga/cf-api/testing";
import { SCHEMA_VERSION } from "@virga/graph";
import { describe, expect, it } from "vitest";
import { Admin } from "../src/admin.ts";
import { d1ScanIndex, getAccount } from "../src/index-db.ts";
import { runScan } from "../src/scan/run.ts";
import type { ScanSummary } from "../src/scan/types.ts";
import { fakeStep } from "./fake-step.ts";
import { apiRoutes, initialState } from "./fixtures/api.ts";
import {
  allDue,
  type GraphStub,
  graphOf,
  graphsWith,
  indexWith,
  newAccountId,
  rejection,
  runningScanRow,
  setupAccount,
  sql,
} from "./helpers.ts";
import { dnsStub, storageStub } from "./stubs.ts";

const admin = exports.Admin;

describe("Admin", () => {
  it("adds and updates accounts and validates input", async () => {
    const id = newAccountId();
    expect(await admin.addAccount({ id, name: "  Production  " })).toMatchObject({
      id,
      name: "Production",
      status: "active",
      cadenceHours: 24,
      profile: "inventory",
      lastScanAt: null,
    });
    expect(await admin.addAccount({ id, name: "Prod", cadenceHours: 1 })).toMatchObject({
      name: "Prod",
      cadenceHours: 1,
    });
    expect(await rejection(admin.addAccount({ id: "nope", name: "x" }))).toMatch(/account ID/);
    expect(await rejection(admin.addAccount({ id, name: "a\nb" }))).toMatch(/name/);
    expect(await rejection(admin.addAccount({ id, name: "x".repeat(201) }))).toMatch(/name/);
    expect(await rejection(admin.addAccount({ id, name: "x", cadenceHours: 0 }))).toMatch(
      /cadence/,
    );
    expect(
      await rejection(admin.addAccount({ id, name: "x", profile: "admin" as "inventory" })),
    ).toMatch(/profile/);
  });

  it("starts a scan by hand unless the account is unknown or a scan is running", async () => {
    const accountId = newAccountId();
    expect(await admin.triggerScan(accountId)).toEqual({
      started: false,
      reason: "unknown_account",
      id: null,
    });
    await setupAccount(accountId);

    // The scan would run the real collectors; stop it at the begin step.
    await using scans = await introspectWorkflow(env.SCAN_WORKFLOW);
    await scans.modifyAll(async (m) => {
      await m.mockStepResult({ name: "begin" }, { started: false, running: "test" });
    });
    const minute = Math.floor(Date.now() / 60_000);
    const started = await admin.triggerScan(accountId);
    expect(started).toMatchObject({ started: true });
    expect(started.id).toMatch(new RegExp(`^scan-${accountId}-\\d{12}-manual$`));
    const again = await admin.triggerScan(accountId);
    if (Math.floor(Date.now() / 60_000) === minute) {
      expect(again).toEqual({ started: false, reason: "exists", id: started.id });
    }
    for (const instance of await scans.get()) await instance.waitForStatus("complete");

    await runningScanRow(accountId, Date.now());
    expect(await admin.triggerScan(accountId)).toEqual({
      started: false,
      reason: "running",
      id: `running-${accountId}`,
    });
  });
});

describe("Admin.removeAccount", () => {
  const AT = Date.UTC(2026, 9, 30, 9, 17);
  const node = { type: "worker_script" as const, nativeId: "api", name: "api" };
  const runs = (accountId: string) =>
    env.INDEX.prepare("SELECT id, status FROM scan_runs WHERE account_id = ? ORDER BY id")
      .bind(accountId)
      .all()
      .then((r) => r.results);

  /** An account with a finished scan: index rows and a graph with a node. */
  async function scannedAccount() {
    const accountId = newAccountId();
    const { stub } = await setupAccount(accountId);
    const index = d1ScanIndex(env.INDEX);
    const scanId = `scan-${accountId}-done`;
    await stub.beginScan(scanId, "full", AT);
    await index.beginRun({ id: scanId, accountId, startedAt: AT });
    await stub.writeChunk(scanId, "workers", { nodes: [node], edges: [] }, { singleChunk: true });
    await stub.finishScan(scanId, "complete", AT + 1);
    const summary = { scanId, accountId, status: "complete" } as ScanSummary;
    await index.finishRun({
      id: scanId,
      accountId,
      startedAt: AT,
      finishedAt: AT + 1,
      status: "complete",
      summary,
    });
    return { accountId, stub, index };
  }

  it("deletes the account's index rows and its graph, and leaves other accounts alone", async () => {
    const { accountId, stub } = await scannedAccount();
    const other = await scannedAccount();
    expect(await runs(accountId)).toHaveLength(1);

    expect(await admin.removeAccount(accountId)).toEqual({ removed: true });

    expect(await getAccount(env.INDEX, accountId)).toBeNull();
    expect(await runs(accountId)).toEqual([]);
    expect(await exports.GraphReader.getScanSummary(accountId)).toBeNull();
    expect((await exports.GraphReader.listAccounts()).map((a) => a.id)).not.toContain(accountId);
    // The graph object is empty: no scan, node or row of any table is left,
    // only the schema version and the marker that refuses new scans.
    const tables = await sql<{ name: string }>(
      stub,
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'",
    );
    for (const { name } of tables) {
      const kept = name === "meta" ? "WHERE key NOT IN ('schema_version', 'removed')" : "";
      expect(await sql(stub, `SELECT count(*) AS n FROM "${name}" ${kept}`), name).toEqual([
        { n: 0 },
      ]);
    }
    expect(await sql(stub, "SELECT key, value FROM meta ORDER BY key")).toEqual([
      { key: "removed", value: expect.stringMatching(/^\d+$/) },
      { key: "schema_version", value: String(SCHEMA_VERSION) },
    ]);

    expect(await getAccount(env.INDEX, other.accountId)).not.toBeNull();
    expect(await runs(other.accountId)).toHaveLength(1);
    expect(await sql(other.stub, "SELECT id FROM nodes")).toEqual([{ id: "worker_script:api" }]);
  });

  it("is idempotent and validates the account ID", async () => {
    const { accountId } = await scannedAccount();
    expect(await admin.removeAccount(accountId)).toEqual({ removed: true });
    expect(await admin.removeAccount(accountId)).toEqual({ removed: false });
    expect(await admin.removeAccount(newAccountId())).toEqual({ removed: false });
    expect(await rejection(admin.removeAccount("../accounts"))).toMatch(/invalid account ID/);
  });

  it("refuses the writes of a scan that still runs, and gives it no index row back", async () => {
    const { accountId, stub, index } = await scannedAccount();
    const scanId = `scan-${accountId}-running`;
    await stub.beginScan(scanId, "full", AT + 3_600_000);
    await index.beginRun({ id: scanId, accountId, startedAt: AT + 3_600_000 });

    await admin.removeAccount(accountId);

    const write = stub.writeChunk(
      scanId,
      "workers",
      { nodes: [node], edges: [] },
      {
        singleChunk: true,
      },
    );
    expect(await rejection(write)).toMatch(/StaleScanError/);
    await index.finishRun({
      id: scanId,
      accountId,
      startedAt: AT + 3_600_000,
      finishedAt: AT + 3_600_001,
      status: "failed",
      summary: { scanId, accountId, status: "failed" } as ScanSummary,
    });
    expect(await runs(accountId)).toEqual([]);
    expect(await sql(stub, "SELECT count(*) AS n FROM nodes")).toEqual([{ n: 0 }]);
  });

  it("R4-03: the graph refuses to begin a scan after the removal until the account is added again", async () => {
    const { accountId, stub } = await scannedAccount();
    await admin.removeAccount(accountId);

    const late = `scan-${accountId}-late`;
    expect(await stub.beginScan(late, "full", AT + 7_200_000)).toEqual({
      started: false,
      removed: true,
    });
    expect(await sql(stub, "SELECT count(*) AS n FROM scans")).toEqual([{ n: 0 }]);
    expect(await sql(stub, "SELECT count(*) AS n FROM meta WHERE key = 'current_scan'")).toEqual([
      { n: 0 },
    ]);

    await admin.addAccount({ id: accountId, name: "Production" });
    expect(await sql(stub, "SELECT count(*) AS n FROM meta WHERE key = 'removed'")).toEqual([
      { n: 0 },
    ]);
    expect(await stub.beginScan(late, "full", AT + 7_200_000)).toEqual({ started: true });
  });

  describe("R5-08: a partial removal never hides an account whose graph is left", () => {
    const LATER = AT + 3_600_000;
    const fail = (message: string) => async () => {
      throw new Error(message);
    };
    /** Admin with other bindings, so one step of the removal fails or something runs before it. */
    const adminWith = (bindings: Partial<Env>) =>
      new Admin(createExecutionContext(), { ...env, ...bindings });

    /** How the account is listed, and what is left of it in the index and in its graph. */
    async function state(accountId: string, stub: GraphStub) {
      const listed = (await exports.GraphReader.listAccounts()).find((a) => a.id === accountId);
      return {
        listed: listed?.status ?? null,
        summary: (await exports.GraphReader.getScanSummary(accountId))?.account.status ?? null,
        runs: (await runs(accountId)).length,
        nodes: (await sql<{ id: string }>(stub, "SELECT id FROM nodes")).map((r) => r.id),
      };
    }
    const gone = { listed: null, summary: null, runs: 0, nodes: [] };

    /** A scan of the account with stub collectors, run to its end. */
    async function scan(accountId: string, name: string) {
      const steps = fakeStep();
      let readers = 0;
      const summary = await runScan(
        {
          step: steps.step,
          graph: () => graphOf(accountId),
          index: d1ScanIndex(env.INDEX),
          reader: (id) => {
            readers++;
            return createReader(fixtureTransport(apiRoutes(id, initialState())));
          },
          collectors: [dnsStub, storageStub],
        },
        { accountId, scanId: `scan-${accountId}-${name}`, now: LATER },
      );
      return { status: summary.status, steps: steps.names(), readers };
    }
    const skipped = { status: "skipped", steps: ["begin"], readers: 0 };

    /** Neither the dispatcher, nor triggerScan, nor a scan instance that begins scans the account. */
    async function noScanBegins(accountId: string) {
      expect(await allDue(LATER + 60 * 24 * 3_600_000)).not.toContain(accountId);
      expect(await admin.triggerScan(accountId)).toEqual({
        started: false,
        reason: "removing",
        id: null,
      });
      expect(await scan(accountId, "late")).toEqual(skipped);
    }

    it("R5-08: when marking the account fails, nothing is removed and a retry removes it", async () => {
      const { accountId, stub } = await scannedAccount();
      const before = await state(accountId, stub);
      const broken = adminWith({ INDEX: indexWith(/SET removing_at/, fail("D1_ERROR: offline")) });

      expect(await rejection(broken.removeAccount(accountId))).toMatch(/D1_ERROR: offline/);
      expect(before).toEqual({
        listed: "active",
        summary: "active",
        runs: 1,
        nodes: ["worker_script:api"],
      });
      expect(await state(accountId, stub)).toEqual(before);

      expect(await admin.removeAccount(accountId)).toEqual({ removed: true });
      expect(await state(accountId, stub)).toEqual(gone);
    });

    it("R5-08: when the graph deletion fails, the account stays listed as removing with its data, and a retry removes it", async () => {
      const { accountId, stub } = await scannedAccount();
      const broken = adminWith({ ACCOUNT_GRAPH: graphsWith(fail("Durable Object reset")) });

      expect(await rejection(broken.removeAccount(accountId))).toMatch(/Durable Object reset/);
      const pending = {
        listed: "removing",
        summary: "removing",
        runs: 1,
        nodes: ["worker_script:api"],
      };
      expect(await state(accountId, stub)).toEqual(pending);
      await noScanBegins(accountId);
      expect(await state(accountId, stub)).toEqual(pending);

      expect(await admin.removeAccount(accountId)).toEqual({ removed: true });
      expect(await state(accountId, stub)).toEqual(gone);
    });

    it("R5-08: when the index deletion fails, the account stays listed as removing with an empty graph, and a retry removes it", async () => {
      const { accountId, stub } = await scannedAccount();
      const broken = adminWith({ INDEX: indexWith(/^DELETE FROM/, fail("D1_ERROR: offline")) });

      expect(await rejection(broken.removeAccount(accountId))).toMatch(/D1_ERROR: offline/);
      const pending = { listed: "removing", summary: "removing", runs: 1, nodes: [] };
      expect(await state(accountId, stub)).toEqual(pending);
      await noScanBegins(accountId);
      expect(await state(accountId, stub)).toEqual(pending);
      expect(await sql(stub, "SELECT count(*) AS n FROM scans")).toEqual([{ n: 0 }]);

      expect(await admin.removeAccount(accountId)).toEqual({ removed: true });
      expect(await state(accountId, stub)).toEqual(gone);
    });

    it("R5-08: a scan that begins after the account is marked and before its graph is deleted stops at its begin step", async () => {
      const { accountId, stub } = await scannedAccount();
      let late: Awaited<ReturnType<typeof scan>> | undefined;
      const paused = adminWith({
        ACCOUNT_GRAPH: graphsWith(async () => {
          late = await scan(accountId, "between");
        }),
      });

      expect(await paused.removeAccount(accountId)).toEqual({ removed: true });
      expect(late).toEqual(skipped);
      expect(await state(accountId, stub)).toEqual(gone);
      expect(await sql(stub, "SELECT count(*) AS n FROM scans")).toEqual([{ n: 0 }]);
    });

    it("R5-08: a scan that begins after the graph is deleted and before the index rows are stops at its begin step", async () => {
      const { accountId, stub } = await scannedAccount();
      let late: Awaited<ReturnType<typeof scan>> | undefined;
      const paused = adminWith({
        INDEX: indexWith(/^DELETE FROM/, async () => {
          late ??= await scan(accountId, "between");
        }),
      });

      expect(await paused.removeAccount(accountId)).toEqual({ removed: true });
      expect(late).toEqual(skipped);
      expect(await state(accountId, stub)).toEqual(gone);
      expect(await sql(stub, "SELECT count(*) AS n FROM scans")).toEqual([{ n: 0 }]);
    });
  });
});
