import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
import { d1ScanIndex, dueAccounts, getAccount, latestRun, runningScan } from "../src/index-db.ts";
import { STALE_SCAN_MS } from "../src/scan/policy.ts";
import type { ScanSummary } from "../src/scan/types.ts";
import { allDue, indexAccount, lastScanAt, runningScanRow } from "./helpers.ts";

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
