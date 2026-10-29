import { introspectWorkflow } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { newAccountId, rejection, runningScanRow, setupAccount } from "./helpers.ts";

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
