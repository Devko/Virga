import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ADMIN, ORIGIN, VIEWER } from "./config.ts";
import {
  ACCOUNT,
  accounts,
  detail,
  MARKUP,
  neighborhood,
  REMOVING_ACCOUNT,
  removingSummary,
  summary,
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

const get = (path: string, token = viewer) => call(path, { token });

describe("read API", () => {
  it("lists accounts and returns hostile names as plain JSON strings", async () => {
    const response = await get("/api/accounts");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    const body = (await response.json()) as typeof accounts;
    expect(body).toEqual(accounts);
    expect(body[0]?.name).toContain(MARKUP);
  });

  it("returns the scan summary, and 404 for an account not in the index", async () => {
    expect(await (await get(`/api/accounts/${ACCOUNT}`)).json()).toEqual(summary);
    const unknown = await get(`/api/accounts/${UNKNOWN_ACCOUNT}`);
    expect(unknown.status).toBe(404);
    expect(await unknown.json()).toEqual({ error: "not_found" });
    expect((await get("/api/accounts/not-an-account-id")).status).toBe(404);
    expect(calls.map((c) => c.method)).toEqual(["getScanSummary", "getScanSummary"]);
  });

  it("passes the status `removing` through in the list and the summary (R5-08)", async () => {
    const list = (await (await get("/api/accounts")).json()) as typeof accounts;
    expect(list.find((a) => a.id === REMOVING_ACCOUNT)?.status).toBe("removing");
    const response = await get(`/api/accounts/${REMOVING_ACCOUNT}`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(removingSummary);
  });

  it("passes finding filters and the cursor through, and validates them", async () => {
    const page = await get(
      `/api/accounts/${ACCOUNT}/findings?status=open&status=suppressed&severity=critical&limit=1&cursor=1%3Aabc`,
    );
    expect(page.status).toBe(200);
    expect(await page.json()).toMatchObject({ cursor: "1:next", findings: [{ ruleId: "CF-001" }] });
    expect(calls.at(-1)).toEqual({
      method: "listFindings",
      args: [
        ACCOUNT,
        { status: ["open", "suppressed"], severity: ["critical"], limit: 1, cursor: "1:abc" },
      ],
    });
    const bad = async (query: string) => {
      const response = await get(`/api/accounts/${ACCOUNT}/findings?${query}`);
      return [response.status, ((await response.json()) as { error: string }).error];
    };
    expect(await bad("status=gone")).toEqual([400, "invalid_status"]);
    expect(await bad("severity=urgent")).toEqual([400, "invalid_severity"]);
    expect(await bad("limit=0")).toEqual([400, "invalid_limit"]);
    expect(await bad("limit=201")).toEqual([400, "invalid_limit"]);
    expect(await bad("limit=1.5")).toEqual([400, "invalid_limit"]);
    expect(await bad(`cursor=${"x".repeat(3000)}`)).toEqual([400, "invalid_cursor"]);
  });

  it("returns a finding by fingerprint", async () => {
    const fp = encodeURIComponent(detail.fingerprint);
    expect(await (await get(`/api/accounts/${ACCOUNT}/finding?fingerprint=${fp}`)).json()).toEqual(
      detail,
    );
    expect((await get(`/api/accounts/${ACCOUNT}/finding?fingerprint=CF-999%3Ax`)).status).toBe(404);
    expect((await get(`/api/accounts/${ACCOUNT}/finding`)).status).toBe(400);
  });

  it("returns a node's neighborhood with depth and limit", async () => {
    const node = encodeURIComponent("worker_script:api");
    const response = await get(
      `/api/accounts/${ACCOUNT}/neighborhood?node=${node}&depth=2&limit=10`,
    );
    expect(await response.json()).toEqual(neighborhood);
    expect(calls.at(-1)?.args).toEqual([ACCOUNT, "worker_script:api", { depth: 2, limit: 10 }]);
    await get(`/api/accounts/${ACCOUNT}/neighborhood?node=${node}`);
    expect(calls.at(-1)?.args).toEqual([ACCOUNT, "worker_script:api", { depth: 1, limit: 100 }]);
    expect((await get(`/api/accounts/${ACCOUNT}/neighborhood?node=${node}&depth=3`)).status).toBe(
      400,
    );
  });

  it("answers 502 without detail when core fails", async () => {
    const logs = captureLogs();
    const response = await get(`/api/accounts/${ACCOUNT}/neighborhood?node=boom`);
    logs.restore();
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({ error: "upstream_error" });
    expect(logs.text()).not.toContain("graph failure");
  });

  it("answers 404 and 405 for unknown routes and methods", async () => {
    expect((await get("/api/nothing")).status).toBe(404);
    expect((await get(`/api/accounts/${ACCOUNT}/secrets`)).status).toBe(404);
    expect((await get(`/api/accounts/${ACCOUNT}/findings/extra`)).status).toBe(404);
    const put = await call("/api/accounts", { method: "PUT", token: admin });
    expect(put.status).toBe(405);
    expect(put.headers.get("allow")).toBe("GET, POST");
    expect((await call(`/api/accounts/${ACCOUNT}/scan`, { token: admin })).status).toBe(405);
  });
});

describe("admin API", () => {
  const scan = (token: string, headers: Record<string, string> = {}) =>
    call(`/api/accounts/${ACCOUNT}/scan`, { token, body: {}, headers });

  it("starts a scan for an admin", async () => {
    const response = await scan(admin);
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      started: true,
      id: `scan-${ACCOUNT}-202610290715-manual`,
    });
    const unknown = await call(`/api/accounts/${UNKNOWN_ACCOUNT}/scan`, { token: admin, body: {} });
    expect(unknown.status).toBe(404);
  });

  it("answers 409 with reason `removing` for an account being removed (R5-08)", async () => {
    const response = await call(`/api/accounts/${REMOVING_ACCOUNT}/scan`, {
      token: admin,
      body: {},
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ started: false, reason: "removing", id: null });
    expect(calls).toEqual([{ method: "triggerScan", args: [REMOVING_ACCOUNT] }]);
  });

  it("refuses a non-admin", async () => {
    const response = await scan(viewer);
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "admin_required" });
    const onboarding = await call("/api/accounts", {
      token: viewer,
      body: { accountId: ACCOUNT, token: "x".repeat(40), profile: "inventory" },
    });
    expect(onboarding.status).toBe(403);
    expect(calls).toEqual([]);
  });

  it("requires a JSON body from the same origin (CSRF)", async () => {
    const status = async (headers: Record<string, string>) => (await scan(admin, headers)).status;
    expect(await status({ "content-type": "text/plain" })).toBe(415);
    expect(await status({ "content-type": "application/x-www-form-urlencoded" })).toBe(415);
    expect(await status({ "content-type": "multipart/form-data; boundary=x" })).toBe(415);
    expect(await status({ origin: "https://evil.example.com" })).toBe(403);
    expect(await status({ origin: "null" })).toBe(403);
    expect(await status({ origin: ORIGIN.replace("https:", "http:") })).toBe(403);
    expect(await status({ "sec-fetch-site": "cross-site" })).toBe(403);
    expect(await status({ "sec-fetch-site": "same-site" })).toBe(403);
    expect(await status({ "content-type": "application/json; charset=utf-8" })).toBe(202);
    expect(await status({ "sec-fetch-site": "same-origin" })).toBe(202);

    const noOrigin = new Headers({ "content-type": "application/json" });
    const request = await call(`/api/accounts/${ACCOUNT}/scan`, {
      method: "POST",
      token: admin,
      headers: Object.fromEntries(noOrigin),
    });
    expect(request.status).toBe(403);
    expect(calls.filter((c) => c.method === "triggerScan")).toHaveLength(2);
  });
});
