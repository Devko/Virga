import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
import {
  d1ScanIndex,
  deleteAccount,
  dueAccounts,
  getAccount,
  latestRun,
  listAccounts,
  markRemoving,
  runningScan,
  upsertAccount,
} from "../src/index-db.ts";
import { STALE_SCAN_MS } from "../src/scan/policy.ts";
import type { ScanSummary } from "../src/scan/types.ts";
import { allDue, indexAccount, lastScanAt, newAccountId, runningScanRow } from "./helpers.ts";

const HOUR = 3_600_000;
// The dispatcher's cron fires at minute 17 (wrangler.jsonc).
const AT = Date.UTC(2026, 9, 29, 7, 17);

const seeded: Record<string, string> = {};

beforeAll(async () => {
  seeded.neverScanned = await indexAccount();
  seeded.scannedRecently = await indexAccount({ lastScanAt: AT - 23 * HOUR });
  seeded.scannedADayAgo = await indexAccount({ lastScanAt: AT - 24 * HOUR - 5 * 60_000 });
  // Hourly: last scan started in the previous hour slot, even if less than 60 minutes ago.
  seeded.hourly = await indexAccount({ cadenceHours: 1, lastScanAt: AT - 40 * 60_000 });
  seeded.hourlyThisHour = await indexAccount({ cadenceHours: 1, lastScanAt: AT - 10 * 60_000 });
  seeded.paused = await indexAccount({ status: "paused" });
  seeded.running = await indexAccount();
  await runningScanRow(seeded.running, AT - HOUR);
  seeded.stale = await indexAccount();
  await runningScanRow(seeded.stale, AT - STALE_SCAN_MS - 1);
});

describe("dueAccounts", () => {
  it("selects active accounts by cadence in UTC hour slots, without running scans", async () => {
    const due = new Set(await allDue(AT));
    const picked = Object.entries(seeded)
      .filter(([, id]) => due.has(id))
      .map(([name]) => name)
      .sort();
    expect(picked).toEqual(["hourly", "neverScanned", "scannedADayAgo", "stale"]);
  });

  it("pages by account ID", async () => {
    const due = await allDue(AT);
    expect(due).toEqual([...due].sort());
    const [first, second] = due;
    expect(await dueAccounts(env.INDEX, AT, { limit: 1 })).toEqual([first]);
    expect(await dueAccounts(env.INDEX, AT, { after: first, limit: 1 })).toEqual([second]);
  });
});

describe("scan runs", () => {
  it("records start and end, and never moves last_scan_at back", async () => {
    const accountId = await indexAccount();
    const index = d1ScanIndex(env.INDEX);
    const id = `scan-${accountId}-2026102907`;
    await index.beginRun({ id, accountId, startedAt: AT });
    expect(await runningScan(env.INDEX, accountId, AT + HOUR)).toBe(id);
    expect(await runningScan(env.INDEX, accountId, AT + STALE_SCAN_MS)).toBeNull();

    const summary = { scanId: id, accountId, status: "partial" } as ScanSummary;
    await index.finishRun({
      id,
      accountId,
      startedAt: AT,
      finishedAt: AT + 60_000,
      status: "partial",
      summary,
    });
    expect(await latestRun(env.INDEX, accountId)).toEqual({
      id,
      accountId,
      startedAt: AT,
      finishedAt: AT + 60_000,
      status: "partial",
      summary,
    });
    expect(await runningScan(env.INDEX, accountId, AT + HOUR)).toBeNull();
    expect((await getAccount(env.INDEX, accountId))?.lastScanAt).toBe(AT);

    // An older scan that finishes late does not move the schedule back.
    const older = `scan-${accountId}-2026102906`;
    await index.finishRun({
      id: older,
      accountId,
      startedAt: AT - HOUR,
      finishedAt: AT + 120_000,
      status: "complete",
      summary,
    });
    expect(await lastScanAt(accountId)).toBe(AT);
  });
});

describe("removal marker", () => {
  it("R5-08: an account being removed stays listed as removing, is never due and gets no scan run", async () => {
    const accountId = await indexAccount();
    const index = d1ScanIndex(env.INDEX);
    expect(await index.hasAccount(accountId)).toBe(true);
    expect(await allDue(AT)).toContain(accountId);

    expect(await markRemoving(env.INDEX, accountId, AT)).toBe(true);
    // A repeat keeps the time the removal began.
    expect(await markRemoving(env.INDEX, accountId, AT + HOUR)).toBe(true);
    expect(await markRemoving(env.INDEX, newAccountId(), AT)).toBe(false);

    expect(await getAccount(env.INDEX, accountId)).toMatchObject({ status: "removing" });
    expect((await listAccounts(env.INDEX)).find((a) => a.id === accountId)).toMatchObject({
      status: "removing",
    });
    expect(
      await env.INDEX.prepare("SELECT removing_at FROM accounts WHERE id = ?")
        .bind(accountId)
        .first(),
    ).toEqual({ removing_at: AT });
    expect(await allDue(AT)).not.toContain(accountId);
    expect(await index.hasAccount(accountId)).toBe(false);
    const id = `scan-${accountId}-2026102907`;
    await index.beginRun({ id, accountId, startedAt: AT });
    expect(await latestRun(env.INDEX, accountId)).toBeNull();

    // Adding the account again does not end the removal; Admin.addAccount finishes it first.
    await upsertAccount(env.INDEX, { id: accountId, name: "Example" }, AT);
    expect(await getAccount(env.INDEX, accountId)).toMatchObject({ status: "removing" });

    expect(await deleteAccount(env.INDEX, accountId)).toBe(true);
    expect(await getAccount(env.INDEX, accountId)).toBeNull();
  });
});

// Runs last: it adds 1,001 accounts to the index this file shares.
describe("listAccounts", () => {
  const byNameThenId = (a: { name: string; id: string }, b: { name: string; id: string }) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

  it("lists every account by name, then ID, with its schedule", async () => {
    const [low, high] = [newAccountId(), newAccountId()].sort();
    const other = newAccountId();
    await upsertAccount(env.INDEX, { id: other, name: "Beta", cadenceHours: 6 }, AT);
    await upsertAccount(env.INDEX, { id: high ?? "", name: "Alpha" }, AT);
    await upsertAccount(env.INDEX, { id: low ?? "", name: "Alpha", profile: "workload" }, AT);

    const accounts = await listAccounts(env.INDEX);
    expect(accounts).toEqual([...accounts].sort(byNameThenId));
    const mine = accounts.filter((a) => [low, high, other].includes(a.id));
    expect(mine).toEqual([
      {
        id: low,
        name: "Alpha",
        status: "active",
        cadenceHours: 24,
        profile: "workload",
        createdAt: AT,
        lastScanAt: null,
      },
      expect.objectContaining({ id: high, name: "Alpha", profile: "inventory" }),
      expect.objectContaining({ id: other, name: "Beta", cadenceHours: 6 }),
    ]);
    expect(accounts.find((a) => a.id === seeded.paused)).toMatchObject({ status: "paused" });
  });

  it("returns at most 1,000 accounts", async () => {
    await env.INDEX.prepare(
      `INSERT INTO accounts (id, name, status, created_at)
       WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1001)
       SELECT lower(hex(randomblob(16))), printf('Bulk %04d', i), 'paused', ? FROM n`,
    )
      .bind(AT)
      .run();
    const total = await env.INDEX.prepare("SELECT count(*) AS n FROM accounts").first<{
      n: number;
    }>();
    expect(total?.n).toBeGreaterThan(1000);

    const accounts = await listAccounts(env.INDEX);
    expect(accounts).toHaveLength(1000);
    expect(accounts).toEqual([...accounts].sort(byNameThenId));
  });
});
