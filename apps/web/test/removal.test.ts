import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountRow } from "../src/rpc.ts";
import { ADMIN, ORIGIN, VIEWER } from "./config.ts";
import {
  ACCOUNT,
  ACCOUNT_REMOVAL_FAILS,
  REMOVING_ACCOUNT,
  REMOVING_UNREADABLE,
  TOKEN_REMOVAL_FAILS,
  UNKNOWN_ACCOUNT,
} from "./fixtures.ts";
import { call, captureLogs, serveCerts, signer, tokenFor } from "./helpers.ts";
import { calls } from "./worker.ts";

let viewer: string;
let admin: string;

beforeEach(async () => {
  serveCerts(await signer());
  viewer = await tokenFor(VIEWER);
  admin = await tokenFor(ADMIN);
  calls.length = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
});

/** DELETE /api/accounts/{id}, confirmed with the account ID like the SPA does. */
function remove(
  accountId: string,
  options: { token?: string; body?: unknown; headers?: Record<string, string> } = {},
) {
  return call(`/api/accounts/${accountId}`, {
    method: "DELETE",
    token: options.token ?? admin,
    body: "body" in options ? options.body : { confirm: accountId },
    headers: options.headers,
  });
}

describe("account removal", () => {
  it("removes the token in the broker, then the account in core, and reports both", async () => {
    const response = await remove(ACCOUNT);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      token: { removed: true },
      account: { removed: true },
    });
    expect(calls).toEqual([
      { method: "remove", args: [ACCOUNT] },
      { method: "removeAccount", args: [ACCOUNT] },
    ]);
  });

  it("reports an account that has nothing left to remove, so a retry is safe", async () => {
    const response = await remove(UNKNOWN_ACCOUNT);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      token: { removed: false },
      account: { removed: false },
    });
    expect(calls.map((c) => c.method)).toEqual(["remove", "removeAccount"]);
  });

  it("finishes the removal of an account that is `removing` when it is repeated (R5-08)", async () => {
    const response = await remove(REMOVING_ACCOUNT);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      token: { removed: false },
      account: { removed: true },
    });
    expect(calls).toEqual([
      { method: "remove", args: [REMOVING_ACCOUNT] },
      { method: "removeAccount", args: [REMOVING_ACCOUNT] },
    ]);
  });

  it("lets an admin finish the removal of a `removing` account whose summary fails with 502", async () => {
    // The SPA learns the status from the list, which reads only core's index.
    const logs = captureLogs();
    const summary = await call(`/api/accounts/${REMOVING_UNREADABLE}`, { token: admin });
    logs.restore();
    expect(summary.status).toBe(502);
    expect(await summary.json()).toEqual({ error: "upstream_error" });
    expect(logs.text()).not.toContain("half deleted");
    const list = (await (await call("/api/accounts", { token: admin })).json()) as AccountRow[];
    expect(list.find((a) => a.id === REMOVING_UNREADABLE)?.status).toBe("removing");

    // The offer is only UI: the route still checks the admin.
    expect((await remove(REMOVING_UNREADABLE, { token: viewer })).status).toBe(403);
    expect(calls.map((c) => c.method)).toEqual(["getScanSummary", "listAccounts"]);

    const response = await remove(REMOVING_UNREADABLE);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      token: { removed: false },
      account: { removed: true },
    });
    expect(calls.slice(2)).toEqual([
      { method: "remove", args: [REMOVING_UNREADABLE] },
      { method: "removeAccount", args: [REMOVING_UNREADABLE] },
    ]);
  });

  it("refuses a non-admin before reading the body", async () => {
    const response = await remove(ACCOUNT, { token: viewer });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "admin_required" });
    const service = await remove(ACCOUNT, {
      token: await tokenFor(null, { common_name: "client.access" }),
    });
    expect(service.status).toBe(403);
    expect(calls).toEqual([]);
  });

  it("requires a JSON body from the same origin (CSRF)", async () => {
    const status = async (headers: Record<string, string>) =>
      (await remove(ACCOUNT, { headers })).status;
    expect(await status({ "content-type": "text/plain" })).toBe(415);
    expect(await status({ "content-type": "application/x-www-form-urlencoded" })).toBe(415);
    expect(await status({ origin: "https://evil.example.com" })).toBe(403);
    expect(await status({ origin: "null" })).toBe(403);
    expect(await status({ origin: ORIGIN.replace("https:", "http:") })).toBe(403);
    expect(await status({ "sec-fetch-site": "cross-site" })).toBe(403);
    expect(await status({ "sec-fetch-site": "same-site" })).toBe(403);
    const noOrigin = await call(`/api/accounts/${ACCOUNT}`, {
      method: "DELETE",
      token: admin,
      body: { confirm: ACCOUNT },
      noOrigin: true,
    });
    expect(noOrigin.status).toBe(403);
    const noBody = await call(`/api/accounts/${ACCOUNT}`, { method: "DELETE", token: admin });
    expect(noBody.status).toBe(415);
    expect(calls).toEqual([]);

    expect(await status({ "sec-fetch-site": "same-origin" })).toBe(200);
  });

  it("requires the account ID as confirmation", async () => {
    const refused = async (body: unknown) => {
      const response = await remove(ACCOUNT, { body });
      return [response.status, ((await response.json()) as { error: string }).error];
    };
    expect(await refused({})).toEqual([400, "confirmation_required"]);
    expect(await refused({ confirm: UNKNOWN_ACCOUNT })).toEqual([400, "confirmation_required"]);
    expect(await refused({ confirm: ACCOUNT.toUpperCase() })).toEqual([
      400,
      "confirmation_required",
    ]);
    expect(await refused([ACCOUNT])).toEqual([400, "confirmation_required"]);
    expect(await refused(ACCOUNT)).toEqual([400, "confirmation_required"]);
    expect(await refused({ confirm: ACCOUNT, pad: "x".repeat(20_000) })).toEqual([
      413,
      "body_too_large",
    ]);
    expect(calls).toEqual([]);
  });

  it("does not remove the account when the broker fails", async () => {
    const logs = captureLogs();
    const response = await remove(TOKEN_REMOVAL_FAILS);
    logs.restore();
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({
      error: "token_not_removed",
      token: null,
      account: null,
    });
    expect(calls.map((c) => c.method)).toEqual(["remove"]);
    expect(logs.text()).not.toContain("vault unavailable");
  });

  it("reports the token result when core fails to remove the account", async () => {
    const logs = captureLogs();
    const response = await remove(ACCOUNT_REMOVAL_FAILS);
    logs.restore();
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({
      error: "account_not_removed",
      token: { removed: true },
      account: null,
    });
    expect(calls.map((c) => c.method)).toEqual(["remove", "removeAccount"]);
    expect(logs.text()).not.toContain("index unavailable");
  });

  it("answers 404 and 405 for other paths and methods", async () => {
    expect((await remove("not-an-account")).status).toBe(404);
    const findings = await call(`/api/accounts/${ACCOUNT}/findings`, {
      method: "DELETE",
      token: admin,
      body: { confirm: ACCOUNT },
    });
    expect(findings.status).toBe(405);
    const put = await call(`/api/accounts/${ACCOUNT}`, { method: "PUT", token: admin, body: {} });
    expect(put.status).toBe(405);
    expect(put.headers.get("allow")).toBe("GET, DELETE");
    const all = await call("/api/accounts", { method: "DELETE", token: admin, body: {} });
    expect(all.status).toBe(405);
    expect(calls).toEqual([]);
  });
});
