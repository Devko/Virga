import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiAction } from "../src/audit.ts";
import type { ToolCall } from "../src/rpc.ts";
import { ADMIN, ORIGIN, VIEWER } from "./config.ts";
import { ACCOUNT, auditPage, MARKUP, UNKNOWN_ACCOUNT } from "./fixtures.ts";
import { call, captureLogs, claims, serveCerts, sign, signer, tokenFor } from "./helpers.ts";
import { audit, calls } from "./worker.ts";

let viewer: string;
let admin: string;

beforeEach(async () => {
  serveCerts(await signer());
  viewer = await tokenFor(VIEWER);
  admin = await tokenFor(ADMIN);
  calls.length = 0;
  audit.entries.length = 0;
  audit.fail = false;
});
afterEach(() => {
  vi.restoreAllMocks();
  audit.fail = false;
});

const SERVICE_TOKEN = "e367826f93b8d71185e03fe518aff3b4.access";

// The shapes core's tool_audit accepts (apps/core/src/audit.ts).
const ACTION = /^[A-Za-z0-9_ /{}.-]{1,100}$/;
const OUTCOME = /^[a-z0-9_]{1,32}$/;

function expectStorable(entry: ToolCall) {
  expect(entry.identity.length).toBeGreaterThan(0);
  expect(entry.identity.length).toBeLessThanOrEqual(320);
  expect(["email", "service_token"]).toContain(entry.identityType);
  expect(["ui", "api", "mcp"]).toContain(entry.channel);
  expect(entry.action).toMatch(ACTION);
  expect(entry.outcome).toMatch(OUTCOME);
  if (entry.accountId !== null) expect(entry.accountId).toMatch(/^[0-9a-f]{32}$/);
}

const viewerEntry = (action: string, accountId: string | null, outcome: string) => ({
  identity: VIEWER,
  identityType: "email",
  channel: "api",
  action,
  accountId,
  outcome,
});

describe("tool audit trail: API", () => {
  it("records one entry per API request, by route template and status", async () => {
    await call("/api/me", { token: viewer });
    await call("/api/accounts", { token: viewer });
    await call(`/api/accounts/${ACCOUNT}`, { token: viewer });
    await call(`/api/accounts/${ACCOUNT}/findings?status=open&cursor=4%3Asecret`, {
      token: viewer,
    });
    await call(`/api/accounts/${ACCOUNT}/finding?fingerprint=${encodeURIComponent(MARKUP)}`, {
      token: viewer,
    });
    await call(`/api/accounts/${ACCOUNT}/neighborhood?node=worker_script%3Aapi`, {
      token: viewer,
    });
    await call(`/api/accounts/${ACCOUNT}/findings/export?format=ndjson`, { token: viewer });
    await call(`/api/accounts/${UNKNOWN_ACCOUNT}`, { token: viewer });
    await call(`/api/accounts/${ACCOUNT}/secrets?x=1`, { token: viewer });
    expect(audit.entries).toEqual([
      viewerEntry("GET /api/me", null, "200"),
      viewerEntry("GET /api/accounts", null, "200"),
      viewerEntry("GET /api/accounts/{id}", ACCOUNT, "200"),
      viewerEntry("GET /api/accounts/{id}/findings", ACCOUNT, "200"),
      viewerEntry("GET /api/accounts/{id}/finding", ACCOUNT, "404"),
      viewerEntry("GET /api/accounts/{id}/neighborhood", ACCOUNT, "200"),
      viewerEntry("GET /api/accounts/{id}/findings/export", ACCOUNT, "200"),
      viewerEntry("GET /api/accounts/{id}", UNKNOWN_ACCOUNT, "404"),
      viewerEntry("GET unmatched", ACCOUNT, "404"),
    ]);
    // Never the query or anything from the account.
    const text = JSON.stringify(audit.entries);
    expect(text).not.toMatch(/secret|status=|fingerprint|onerror|\?/);
  });

  it("records admin actions and refusals, never the body or the token", async () => {
    const token = "cfat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90";
    await call(`/api/accounts/${ACCOUNT}/scan`, { token: admin, body: {} });
    await call(`/api/accounts/${ACCOUNT}/scan`, { token: viewer, body: {} });
    await call(`/api/accounts/${ACCOUNT}/scan`, {
      token: admin,
      body: {},
      headers: { origin: "https://evil.example.com" },
    });
    await call("/api/accounts", {
      token: admin,
      body: { accountId: ACCOUNT, token, profile: "inventory", name: MARKUP },
    });
    await call(`/api/accounts/${ACCOUNT}`, {
      token: admin,
      method: "DELETE",
      body: { confirm: ACCOUNT },
    });
    expect(audit.entries.map((e) => [e.identity, e.action, e.accountId, e.outcome])).toEqual([
      [ADMIN, "POST /api/accounts/{id}/scan", ACCOUNT, "202"],
      [VIEWER, "POST /api/accounts/{id}/scan", ACCOUNT, "403"],
      [ADMIN, "POST /api/accounts/{id}/scan", ACCOUNT, "403"],
      [ADMIN, "POST /api/accounts", null, "201"],
      [ADMIN, "DELETE /api/accounts/{id}", ACCOUNT, "200"],
    ]);
    const text = JSON.stringify(audit.entries);
    expect(text).not.toContain(token);
    expect(text).not.toContain("cfat_");
    expect(text).not.toContain("onerror");
  });

  it("tells the SPA from other clients, and service tokens from users", async () => {
    await call("/api/accounts", { token: viewer, headers: { "sec-fetch-site": "same-origin" } });
    await call("/api/accounts", { token: viewer, headers: { "sec-fetch-site": "none" } });
    const service = await sign(await signer(), claims(null, { common_name: SERVICE_TOKEN }));
    await call("/api/accounts", { token: service });
    expect(audit.entries.map((e) => [e.identity, e.identityType, e.channel])).toEqual([
      [VIEWER, "email", "ui"],
      [VIEWER, "email", "api"],
      [SERVICE_TOKEN, "service_token", "api"],
    ]);
  });

  it("records nothing for a request Access refused, or for the SPA's files", async () => {
    await call("/api/accounts");
    await call("/api/accounts", { token: "not.a.token" });
    await call("/api/accounts", { token: await tokenFor(VIEWER, { exp: 1 }) });
    await call("/mcp", {
      body: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_accounts" } },
      noOrigin: true,
    });
    await call("/", { token: viewer });
    expect(audit.entries).toEqual([]);
  });

  it("answers the request when the audit write fails, and logs no detail", async () => {
    audit.fail = true;
    const logs = captureLogs();
    const response = await call("/api/accounts", { token: viewer });
    logs.restore();
    expect(response.status).toBe(200);
    expect(audit.entries).toEqual([]);
    expect(logs.text()).toContain("audit: record failed Error");
    expect(logs.text()).not.toContain(VIEWER);
  });

  it("keeps every field within the table's bounds", async () => {
    await call(`/api/accounts/${ACCOUNT}/neighborhood?node=${"x".repeat(2000)}`, {
      token: viewer,
    });
    await call(`/api/${"a/".repeat(3000)}`, { token: viewer });
    await call("/api/accounts", { token: viewer, method: "PROPFIND" });
    await call(`/api/accounts/${ACCOUNT.toUpperCase()}`, { token: viewer });
    const longest = `${"a".repeat(308)}@example.com`;
    await call("/api/me", { token: await tokenFor(longest) });
    expect(audit.entries.map((e) => e.action)).toEqual([
      "GET /api/accounts/{id}/neighborhood",
      "GET unmatched",
      "OTHER /api/accounts",
      "GET unmatched",
      "GET /api/me",
    ]);
    expect(audit.entries[3]?.accountId).toBeNull();
    expect(audit.entries[4]?.identity).toBe(longest);
    for (const entry of audit.entries) expectStorable(entry);

    expect(apiAction("GET", ["accounts", ACCOUNT, "findings", "export"])).toEqual({
      action: "GET /api/accounts/{id}/findings/export",
      accountId: ACCOUNT,
    });
    expect(apiAction("GET", ["accounts", ACCOUNT, "finding", "export"]).action).toBe(
      "GET unmatched",
    );
    expect(apiAction("GET", []).action).toBe("GET unmatched");
    expect(apiAction("GET", [""]).action).toBe("GET unmatched");
  });
});

describe("tool audit trail: read", () => {
  it("lets admins read it, newest first and paged", async () => {
    const response = await call("/api/audit", { token: admin });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual(auditPage);
    await call("/api/audit?limit=20&cursor=2", { token: admin });
    expect(calls).toEqual([
      { method: "listToolCalls", args: [{}] },
      { method: "listToolCalls", args: [{ limit: 20, cursor: "2" }] },
    ]);
    // The read is an API request like any other.
    expect(audit.entries.map((e) => [e.action, e.outcome])).toEqual([
      ["GET /api/audit", "200"],
      ["GET /api/audit", "200"],
    ]);
  });

  it("refuses viewers and service tokens with 403", async () => {
    const response = await call("/api/audit", { token: viewer });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "admin_required" });
    const service = await sign(await signer(), claims(null, { common_name: SERVICE_TOKEN }));
    expect((await call("/api/audit", { token: service })).status).toBe(403);
    expect(calls).toEqual([]);
    expect(audit.entries.map((e) => [e.identity, e.action, e.outcome])).toEqual([
      [VIEWER, "GET /api/audit", "403"],
      [SERVICE_TOKEN, "GET /api/audit", "403"],
    ]);
  });

  it("validates the query and the method", async () => {
    const status = async (query: string) =>
      (await call(`/api/audit${query}`, { token: admin })).status;
    expect(await status("?limit=0")).toBe(400);
    expect(await status("?limit=201")).toBe(400);
    expect(await status("?cursor=abc")).toBe(400);
    expect(await status("?cursor=0")).toBe(400);
    expect(await status(`?cursor=${"9".repeat(17)}`)).toBe(400);
    expect((await call("/api/audit/x", { token: admin })).status).toBe(404);
    const post = await call("/api/audit", { token: admin, body: {} });
    expect(post.status).toBe(405);
    expect(calls).toEqual([]);
  });
});

let nextId = 1;

/** One MCP JSON-RPC request, as a non-browser client sends it. */
async function mcp(
  method: string,
  params: object,
  headers: Record<string, string> = {},
  token = viewer,
) {
  const response = await call("/mcp", {
    token,
    body: { jsonrpc: "2.0", id: nextId++, method, params },
    headers: { accept: "application/json, text/event-stream", ...headers },
    noOrigin: !("origin" in headers),
  });
  await response.arrayBuffer();
  return response;
}

const tool = (name: string, args: object, headers: Record<string, string> = {}) =>
  mcp("tools/call", { name, arguments: args }, headers);

describe("tool audit trail: MCP", () => {
  it("records one entry per tool call with its outcome", async () => {
    await mcp("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "test", version: "1.0.0" },
    });
    await mcp("tools/list", {});
    expect(audit.entries).toEqual([]);

    await tool("list_accounts", {});
    await tool("list_findings", { account_id: ACCOUNT, status: ["open"] });
    await tool("get_finding", { account_id: UNKNOWN_ACCOUNT, fingerprint: MARKUP });
    await tool("get_neighborhood", { account_id: ACCOUNT, node_id: "boom" });
    expect(audit.entries).toEqual([
      {
        identity: VIEWER,
        identityType: "email",
        channel: "mcp",
        action: "list_accounts",
        accountId: null,
        outcome: "ok",
      },
      {
        identity: VIEWER,
        identityType: "email",
        channel: "mcp",
        action: "list_findings",
        accountId: ACCOUNT,
        outcome: "ok",
      },
      {
        identity: VIEWER,
        identityType: "email",
        channel: "mcp",
        action: "get_finding",
        accountId: UNKNOWN_ACCOUNT,
        outcome: "not_found",
      },
      {
        identity: VIEWER,
        identityType: "email",
        channel: "mcp",
        action: "get_neighborhood",
        accountId: ACCOUNT,
        outcome: "error",
      },
    ]);
    expect(JSON.stringify(audit.entries)).not.toContain("onerror");
  });

  it("records a tool call that runs no tool as refused", async () => {
    await tool("list_findings", { account_id: "../../etc" });
    await tool("list_findings", { account_id: ACCOUNT, limit: 51 });
    await tool("trigger_scan", { account_id: ACCOUNT });
    await tool(MARKUP, {});
    await tool("list_accounts", {}, { origin: "https://evil.example.com" });
    expect(audit.entries.map((e) => [e.action, e.accountId, e.outcome])).toEqual([
      ["list_findings", null, "refused"],
      ["list_findings", ACCOUNT, "refused"],
      ["unknown_tool", ACCOUNT, "refused"],
      ["unknown_tool", null, "refused"],
      ["list_accounts", null, "refused"],
    ]);
    expect(calls).toEqual([]);
    for (const entry of audit.entries) expectStorable(entry);
  });

  it("records the service token of an MCP client", async () => {
    const service = await sign(await signer(), claims(null, { common_name: SERVICE_TOKEN }));
    await mcp(
      "tools/call",
      { name: "get_scan_summary", arguments: { account_id: ACCOUNT } },
      {},
      service,
    );
    await tool("list_accounts", {}, { origin: ORIGIN });
    expect(audit.entries.map((e) => [e.identity, e.identityType, e.channel, e.outcome])).toEqual([
      [SERVICE_TOKEN, "service_token", "mcp", "ok"],
      [VIEWER, "email", "mcp", "ok"],
    ]);
  });
});
