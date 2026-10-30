import { introspectWorkflow, introspectWorkflowInstance } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { runDispatch } from "../src/scan/dispatch.ts";
import { scanInstanceId } from "../src/scan/ids.ts";
import type { ScanSummary } from "../src/scan/types.ts";
import { fakeStep } from "./fake-step.ts";
import {
  allDue,
  type GraphStub,
  lastScanAt,
  newAccountId,
  scanRun,
  setupAccount,
  sql,
} from "./helpers.ts";

// Scans through the Workflow engine of the vitest plugin: the production
// ScanWorkflow with stub collectors (TestScanWorkflow in test/worker.ts), its
// reader going through the BROKER service binding to the fixture broker.

describe("ScanWorkflow", () => {
  it("runs a full scan: chunked collection, coverage, sweep, exposure, rules, index", async () => {
    const accountId = newAccountId();
    const { stub, evaluators } = await setupAccount(accountId);
    const id = `scan-${accountId}-wf1`;

    await using instance = await introspectWorkflowInstance(env.TEST_SCAN_WORKFLOW, id);
    await env.TEST_SCAN_WORKFLOW.create({ id, params: { accountId } });
    await instance.waitForStatus("complete");

    expect(await instance.waitForStepResult({ name: "plan:dns" })).toMatchObject({
      status: "ok",
      chunks: [["023e105f4ecef8ad9ca31a8372d0c353"], ["372e67954025e0ba6aaa6d586b9e0b59"]],
    });
    expect(await instance.waitForStepResult({ name: "collect:dns:2" })).toEqual({
      status: "ok",
      nodes: 1,
      edges: 0,
      changed: 1,
      signals: 0,
      insights: 0,
    });
    expect(await instance.waitForStepResult({ name: "collect:storage:1" })).toMatchObject({
      status: "no_permission",
    });

    const output = (await instance.getOutput()) as ScanSummary;
    expect(output).toMatchObject({ scanId: id, accountId, status: "partial" });
    expect(output.classes.dns).toMatchObject({ status: "complete", chunks: 2, done: 2, nodes: 3 });
    expect(output.classes.storage).toMatchObject({ status: "no_permission", done: 0 });
    expect(output.classes.storage?.detail).toMatch(/403 on \/accounts\/[0-9a-f]{32}\/r2\/buckets/);
    // Evaluators run inside the graph object; the fakes there saw this scan.
    expect(evaluators.calls).toEqual({ exposure: 1, rules: [id] });

    expect(
      await sql(stub, "SELECT resource_class, status FROM coverage ORDER BY resource_class"),
    ).toEqual([
      { resource_class: "dns", status: "complete" },
      { resource_class: "exposure", status: "complete" },
      { resource_class: "storage", status: "no_permission" },
    ]);
    expect(await sql(stub, "SELECT count(*) AS n FROM nodes WHERE deleted_at IS NULL")).toEqual([
      { n: 3 },
    ]);
    expect((await scanRun(id))?.status).toBe("partial");
    expect(await lastScanAt(accountId)).toBe(output.startedAt);
  });

  it("retries a failing step, then records partial coverage and skips the sweep", async () => {
    const accountId = newAccountId();
    const { stub } = await setupAccount(accountId);
    const id = `scan-${accountId}-wf2`;

    await using instance = await introspectWorkflowInstance(env.TEST_SCAN_WORKFLOW, id);
    await instance.modify(async (m) => {
      await m.disableRetryDelays();
      await m.mockStepError({ name: "collect:dns:2" }, new Error("upstream 502"));
    });
    await env.TEST_SCAN_WORKFLOW.create({ id, params: { accountId } });
    await instance.waitForStatus("complete");

    const output = (await instance.getOutput()) as ScanSummary;
    expect(output.classes.dns).toMatchObject({ status: "partial", chunks: 2, done: 1 });
    expect(output.classes.dns?.detail).toMatch(/upstream 502/);
    expect(output.classes.dns?.swept).toBeUndefined();
    expect(
      await sql(
        stub,
        "SELECT status, chunks_total, chunks_done FROM coverage WHERE resource_class = 'dns'",
      ),
    ).toEqual([{ status: "partial", chunks_total: 2, chunks_done: 1 }]);
  });

  it("R4-03: an instance that starts after removeAccount stops at its begin step, without writing", async () => {
    const accountId = newAccountId();
    const { stub, evaluators } = await setupAccount(accountId);
    const id = `scan-${accountId}-wf4`;
    // As for an instance that was still queued when the account was removed.
    await exports.Admin.removeAccount(accountId);

    await using instance = await introspectWorkflowInstance(env.TEST_SCAN_WORKFLOW, id);
    await env.TEST_SCAN_WORKFLOW.create({ id, params: { accountId } });
    await instance.waitForStatus("complete");

    expect(await instance.waitForStepResult({ name: "begin" })).toEqual({
      started: false,
      removed: true,
    });
    const output = (await instance.getOutput()) as ScanSummary;
    expect(output).toMatchObject({ scanId: id, accountId, status: "skipped", classes: {} });
    expect(output.detail).toMatch(/not in the index/);
    expect(evaluators.calls).toEqual({ exposure: 0, rules: [] });
    expect(await removedLeftovers(accountId, stub)).toEqual(NOTHING);
  });

  it("fails fast on an invalid account ID", async () => {
    const id = "scan-invalid-wf3";
    await using instance = await introspectWorkflowInstance(env.TEST_SCAN_WORKFLOW, id);
    await env.TEST_SCAN_WORKFLOW.create({ id, params: { accountId: "../../zones" } });
    await instance.waitForStatus("errored");
    expect((await instance.getError()).message).toMatch(/invalid account ID/);
  });
});

/** What is left of a removed account, in the index and in its graph. */
async function removedLeftovers(accountId: string, stub: GraphStub) {
  const runs = await env.INDEX.prepare("SELECT id FROM scan_runs WHERE account_id = ?")
    .bind(accountId)
    .all();
  return {
    runs: runs.results,
    scans: await sql(stub, "SELECT id FROM scans"),
    nodes: await sql(stub, "SELECT id FROM nodes"),
  };
}
const NOTHING = { runs: [], scans: [], nodes: [] };

describe("DispatchWorkflow", () => {
  it("R4-03: a dispatched scan that begins after removeAccount stops without writing", async () => {
    const accountId = newAccountId();
    const { stub } = await setupAccount(accountId);
    const at = Date.UTC(2026, 9, 30, 9, 17);
    const id = scanInstanceId(accountId, at);
    await using instance = await introspectWorkflowInstance(env.TEST_SCAN_WORKFLOW, id);

    // The dispatcher reads the index before the removal and creates the instance after it.
    const dispatched = await runDispatch(
      {
        step: fakeStep().step,
        dueAccounts: async (time) => {
          const due = (await allDue(time)).filter((due) => due === accountId);
          await exports.Admin.removeAccount(accountId);
          return due;
        },
        scans: env.TEST_SCAN_WORKFLOW,
      },
      at,
    );
    expect(dispatched).toEqual({ due: 1, created: 1, existing: 0, failed: 0 });
    await instance.waitForStatus("complete");

    expect(await instance.getOutput()).toMatchObject({ scanId: id, status: "skipped" });
    expect(await removedLeftovers(accountId, stub)).toEqual(NOTHING);
  });

  it("starts one scan per due account with deterministic IDs and skips existing ones", async () => {
    const accounts = [newAccountId(), newAccountId()];
    for (const accountId of accounts) await setupAccount(accountId);

    // The dispatched scans run the real collectors; stop them at the begin step.
    await using scans = await introspectWorkflow(env.SCAN_WORKFLOW);
    await scans.modifyAll(async (m) => {
      await m.mockStepResult({ name: "begin" }, { started: false, running: "test" });
    });

    const hour = Math.floor(Date.now() / 3_600_000);
    await using first = await introspectWorkflowInstance(env.DISPATCH_WORKFLOW, "dispatch-1");
    await env.DISPATCH_WORKFLOW.create({ id: "dispatch-1" });
    await first.waitForStatus("complete");
    const created = (await first.getOutput()) as { due: number; created: number };
    expect(created.created).toBe(created.due);
    expect(created.due).toBeGreaterThanOrEqual(accounts.length);

    for (const accountId of accounts) {
      const scan = await env.SCAN_WORKFLOW.get(scanInstanceId(accountId, hour * 3_600_000));
      expect(scan.id).toBe(scanInstanceId(accountId, hour * 3_600_000));
    }
    const instances = await scans.get();
    expect(instances).toHaveLength(created.created);
    for (const scan of instances) {
      await scan.waitForStatus("complete");
      expect(await scan.getOutput()).toMatchObject({ status: "skipped", running: "test" });
    }

    // A second dispatch in the same hour finds every ID taken (createBatch code 10405).
    // Locally, workerd logs a canceled request for those IDs; the result is as documented.
    await using second = await introspectWorkflowInstance(env.DISPATCH_WORKFLOW, "dispatch-2");
    await env.DISPATCH_WORKFLOW.create({ id: "dispatch-2" });
    await second.waitForStatus("complete");
    const again = (await second.getOutput()) as { due: number; created: number; existing: number };
    if (Math.floor(Date.now() / 3_600_000) === hour) {
      expect(again).toMatchObject({ due: created.due, created: 0, existing: created.due });
    }
  });
});
