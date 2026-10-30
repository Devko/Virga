import { introspectWorkflow, introspectWorkflowInstance } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import {
  AUDIT_RETENTION_MS,
  checkToolCall,
  listToolCalls,
  PURGE_BATCH,
  purgeToolCalls,
  recordToolCall,
  runAuditPurge,
  type ToolCall,
} from "../src/audit.ts";
import { fakeStep } from "./fake-step.ts";
import { newAccountId, rejection } from "./helpers.ts";

const admin = exports.Admin;
// Right-to-left override: written as a code point, so the source shows no bidi character.
const RLO = String.fromCodePoint(0x202e);
const DAY = 24 * 60 * 60 * 1000;

const entry = (overrides: Partial<ToolCall> = {}): ToolCall => ({
  identity: "viewer@example.com",
  identityType: "email",
  channel: "api",
  action: "GET /api/accounts/{id}/findings",
  accountId: newAccountId(),
  outcome: "200",
  ...overrides,
});

const count = async (where: string, ...params: unknown[]) =>
  (
    await env.INDEX.prepare(`SELECT count(*) AS n FROM tool_audit WHERE ${where}`)
      .bind(...params)
      .first<{ n: number }>()
  )?.n ?? 0;

describe("tool audit trail", () => {
  it("records a call through Admin, at the time of the call", async () => {
    const before = Date.now();
    const call = entry({ channel: "ui", outcome: "403" });
    await admin.recordToolCall(call);
    const page = await admin.listToolCalls({ limit: 1 });
    const [newest] = page.entries;
    expect(newest).toMatchObject(call);
    expect(newest?.at).toBeGreaterThanOrEqual(before);
    expect(newest?.at).toBeLessThanOrEqual(Date.now());

    const service = entry({
      identity: "e367826f93b8d71185e03fe518aff3b4.access",
      identityType: "service_token",
      channel: "mcp",
      action: "list_accounts",
      accountId: null,
      outcome: "ok",
    });
    await admin.recordToolCall(service);
    expect((await admin.listToolCalls({ limit: 1 })).entries[0]).toMatchObject(service);
  });

  it("lists newest first in pages", async () => {
    const accountId = newAccountId();
    for (const outcome of ["200", "404", "502"]) {
      await recordToolCall(env.INDEX, entry({ accountId, outcome }), Date.now());
    }
    const first = await admin.listToolCalls({ limit: 2 });
    expect(first.entries.map((e) => e.outcome)).toEqual(["502", "404"]);
    expect(first.cursor).toBe(String(first.entries[1]?.id));
    const second = await admin.listToolCalls({ limit: 1, cursor: first.cursor ?? undefined });
    expect(second.entries.map((e) => [e.accountId, e.outcome])).toEqual([[accountId, "200"]]);
    expect(second.entries[0]?.id).toBeLessThan(first.entries[1]?.id ?? 0);

    const all = await listToolCalls(env.INDEX, { limit: 200 });
    const ids = all.entries.map((e) => e.id);
    expect(ids).toEqual([...ids].sort((a, b) => b - a));

    expect(await rejection(admin.listToolCalls({ limit: 0 }))).toMatch(/limit/);
    expect(await rejection(admin.listToolCalls({ limit: 201 }))).toMatch(/limit/);
    for (const cursor of ["", "0", "-1", "1.5", "1 OR 1=1", "x".repeat(20)]) {
      expect(await rejection(admin.listToolCalls({ cursor })), cursor).toMatch(/cursor/);
    }
  });

  it("refuses fields that do not fit their shape, and writes nothing", async () => {
    const bad: [Partial<ToolCall>, RegExp][] = [
      [{ identity: "" }, /identity/],
      [{ identity: `${"a".repeat(309)}@example.com` }, /identity/],
      [{ identity: "eve@example.com\nadmin@example.com" }, /identity/],
      [{ identity: `eve${RLO}@example.com` }, /identity/],
      [{ identity: "eve @example.com" }, /identity/],
      [{ identityType: "user" as "email" }, /identity type/],
      [{ channel: "web" as "ui" }, /channel/],
      [{ action: "" }, /action/],
      [{ action: "GET /api/accounts/x/finding?fingerprint=secret" }, /action/],
      [{ action: `GET /api/${"x".repeat(100)}` }, /action/],
      [{ action: "GET /api/</script>" }, /action/],
      [{ accountId: "0123456789ABCDEF0123456789ABCDEF" }, /account ID/],
      [{ accountId: "../../etc" }, /account ID/],
      [{ outcome: "" }, /outcome/],
      [{ outcome: "x".repeat(33) }, /outcome/],
      [{ outcome: "Error: token cfat_abc" }, /outcome/],
    ];
    const rows = await count("1");
    for (const [overrides, message] of bad) {
      expect(() => checkToolCall(entry(overrides)), JSON.stringify(overrides)).toThrow(message);
      expect(await rejection(admin.recordToolCall(entry(overrides)))).toMatch(message);
    }
    expect(await count("1")).toBe(rows);

    // 320 characters is the bound, as for emails in the Access check.
    const longest = `${"a".repeat(308)}@example.com`;
    expect(longest).toHaveLength(320);
    await admin.recordToolCall(entry({ identity: longest }));
    expect(await count("identity = ?", longest)).toBe(1);
  });

  it("checks the bounds in the table too", async () => {
    const insert = (identity: string, channel: string, accountId: string | null) =>
      env.INDEX.prepare(
        `INSERT INTO tool_audit (at, identity, identity_type, channel, action, account_id, outcome)
         VALUES (1, ?, 'email', ?, 'GET /api/me', ?, '200')`,
      )
        .bind(identity, channel, accountId)
        .run();
    expect(await rejection(insert("x".repeat(321), "api", null))).toMatch(/CHECK/);
    expect(await rejection(insert("a@example.com", "web", null))).toMatch(/CHECK/);
    expect(await rejection(insert("a@example.com", "api", "../x"))).toMatch(/CHECK/);
  });

  it("purges rows older than 90 days, in batches", async () => {
    const now = Date.UTC(2026, 9, 30, 9, 17);
    const old = entry({ outcome: "old" });
    const kept = entry({ outcome: "kept" });
    await recordToolCall(env.INDEX, old, now - AUDIT_RETENTION_MS - 1);
    await recordToolCall(env.INDEX, kept, now - AUDIT_RETENTION_MS);
    await recordToolCall(env.INDEX, kept, now - DAY);
    // More old rows than one batch deletes.
    await env.INDEX.prepare(
      `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
       INSERT INTO tool_audit (at, identity, identity_type, channel, action, account_id, outcome)
       SELECT ? - i, 'bulk@example.com', 'email', 'api', 'GET /api/me', NULL, 'bulk' FROM n`,
    )
      .bind(PURGE_BATCH + 10, now - AUDIT_RETENTION_MS - DAY)
      .run();
    expect(await count("outcome = 'bulk'")).toBe(PURGE_BATCH + 10);

    const deleted = await purgeToolCalls(env.INDEX, now - AUDIT_RETENTION_MS);
    expect(deleted).toBeGreaterThanOrEqual(PURGE_BATCH + 11);
    expect(await count("outcome IN ('old', 'bulk')")).toBe(0);
    expect(await count("outcome = 'kept'")).toBe(2);
    expect(await purgeToolCalls(env.INDEX, now - AUDIT_RETENTION_MS)).toBe(0);
  });

  it("runs the purge as a dispatcher step, and a failed purge does not fail it", async () => {
    const at = Date.UTC(2026, 9, 30, 10, 17);
    await recordToolCall(env.INDEX, entry({ outcome: "stale" }), at - AUDIT_RETENTION_MS - DAY);
    const steps = fakeStep();
    const purged = await runAuditPurge(
      steps.step,
      (before) => purgeToolCalls(env.INDEX, before),
      at,
    );
    expect(purged).toBeGreaterThanOrEqual(1);
    expect(steps.names()).toEqual(["audit:purge"]);
    expect(await count("outcome = 'stale'")).toBe(0);

    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const failing = fakeStep();
    const result = await runAuditPurge(
      failing.step,
      async () => {
        throw new Error("D1 unavailable");
      },
      at,
    );
    expect(result).toBeNull();
    expect(failing.record("audit:purge")?.attempts).toBe(6);
    expect(error).toHaveBeenCalledWith("audit purge failed", "Error");
    error.mockRestore();
  });

  it("is purged by the hourly DispatchWorkflow", async () => {
    await recordToolCall(env.INDEX, entry({ outcome: "expired" }), Date.now() - 91 * DAY);
    await recordToolCall(env.INDEX, entry({ outcome: "recent" }), Date.now() - 89 * DAY);
    // Scans the dispatcher starts stop at their begin step.
    await using scans = await introspectWorkflow(env.SCAN_WORKFLOW);
    await scans.modifyAll(async (m) => {
      await m.mockStepResult({ name: "begin" }, { started: false, running: "test" });
    });
    await using instance = await introspectWorkflowInstance(
      env.DISPATCH_WORKFLOW,
      "dispatch-audit",
    );
    await env.DISPATCH_WORKFLOW.create({ id: "dispatch-audit" });
    await instance.waitForStatus("complete");
    const output = (await instance.getOutput()) as { auditPurged: number | null };
    expect(output.auditPurged).toBeGreaterThanOrEqual(1);
    expect(await count("outcome = 'expired'")).toBe(0);
    expect(await count("outcome = 'recent'")).toBe(1);
    for (const scan of await scans.get()) await scan.waitForStatus("complete");
  });
});
