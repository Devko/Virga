import { introspectWorkflow } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { SCHEMA_VERSION } from "@virga/graph";
import { describe, expect, it } from "vitest";
import { d1ScanIndex, getAccount } from "../src/index-db.ts";
import type { ScanSummary } from "../src/scan/types.ts";
import { newAccountId, rejection, runningScanRow, setupAccount, sql } from "./helpers.ts";

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
});
