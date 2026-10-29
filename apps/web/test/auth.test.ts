import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type AccessEnv, accessConfig, authenticate } from "../src/auth.ts";
import { ADMIN, TEST_ACCESS, VIEWER } from "./config.ts";
import {
  CERTS_URL,
  call,
  captureLogs,
  claims,
  newSigner,
  nowS,
  serveCerts,
  sign,
  signer,
  tokenFor,
} from "./helpers.ts";

const reason = async (request: Request, overrides: Partial<AccessEnv> = {}, ctx = {}) => {
  const result = await authenticate(request, { ...TEST_ACCESS, ...overrides }, ctx);
  return result.ok ? "ok" : result.reason;
};

const withToken = (token: string) =>
  new Request("https://virga.example.com/", { headers: { "Cf-Access-Jwt-Assertion": token } });

beforeEach(async () => {
  serveCerts(await signer());
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("Access check", () => {
  it("refuses every path without a token, assets and MCP included", async () => {
    for (const path of [
      "/",
      "/index.html",
      "/accounts",
      "/assets/app.js",
      "/api/accounts",
      "/mcp",
    ]) {
      const response = await call(path);
      expect(response.status, path).toBe(403);
      expect(await response.json()).toEqual({ error: "forbidden" });
      expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    }
    const post = await call("/mcp", { body: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(post.status).toBe(403);
  });

  it("accepts a valid token and reads the identity from it", async () => {
    const response = await call("/api/me", { token: await tokenFor(VIEWER) });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ email: VIEWER, serviceToken: null, admin: false });

    const admin = await call("/api/me", { token: await tokenFor("ADMIN@example.com") });
    expect(await admin.json()).toMatchObject({ email: ADMIN, admin: true });
  });

  it("accepts a service token login without an email, never as admin", async () => {
    const token = await sign(
      await signer(),
      claims(null, { common_name: "e367826f93b8d71185e03fe518aff3b4.access" }),
    );
    const response = await call("/api/me", { token });
    expect(await response.json()).toEqual({
      email: null,
      serviceToken: "e367826f93b8d71185e03fe518aff3b4.access",
      admin: false,
    });
  });

  it("refuses malformed and tampered tokens", async () => {
    const good = await tokenFor(VIEWER);
    const [head, body, signature] = good.split(".") as [string, string, string];
    const forged = btoa(JSON.stringify(claims(ADMIN)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await reason(withToken("not-a-jwt"))).toBe("malformed");
    expect(await reason(withToken(`${head}.${body}`))).toBe("malformed");
    expect(await reason(withToken(`${head}.${body}.${signature}.x`))).toBe("malformed");
    expect(await reason(withToken(`${head}.e30.${signature}`))).toBe("bad_signature");
    expect(await reason(withToken(`${head}.${forged}.${signature}`))).toBe("bad_signature");
    expect(await reason(withToken(`${head}.${body}.${signature.slice(0, -4)}AAAA`))).toBe(
      "bad_signature",
    );
    expect(await reason(withToken("x".repeat(20_000)))).toBe("malformed");
    expect(await reason(new Request("https://virga.example.com/"))).toBe("missing_token");
  });

  it("refuses a token signed by another key", async () => {
    const stranger = await newSigner("test-key-1");
    expect(await reason(withToken(await sign(stranger, claims(VIEWER))))).toBe("bad_signature");
    const unknownKid = await newSigner("other-kid");
    expect(await reason(withToken(await sign(unknownKid, claims(VIEWER))))).toBe("unknown_key");
  });

  it("refuses alg none and HS256", async () => {
    const s = await signer();
    expect(await reason(withToken(await sign(s, claims(VIEWER), { alg: "none" })))).toBe(
      "unsupported_algorithm",
    );
    expect(await reason(withToken(await sign(s, claims(VIEWER), { alg: "HS256" })))).toBe(
      "unsupported_algorithm",
    );
  });

  it("checks aud, iss, exp, nbf and type", async () => {
    const s = await signer();
    const check = async (extra: object) => reason(withToken(await sign(s, claims(VIEWER, extra))));
    expect(await check({})).toBe("ok");
    expect(await check({ aud: TEST_ACCESS.ACCESS_AUD })).toBe("ok");
    expect(await check({ aud: ["another-application-aud"] })).toBe("wrong_audience");
    expect(await check({ aud: undefined })).toBe("wrong_audience");
    expect(await check({ iss: "https://other-team.cloudflareaccess.com" })).toBe("wrong_issuer");
    expect(await check({ exp: nowS() - 120 })).toBe("expired");
    expect(await check({ exp: undefined })).toBe("expired");
    expect(await check({ exp: String(nowS() + 300) })).toBe("expired");
    expect(await check({ nbf: nowS() + 600 })).toBe("not_yet_valid");
    expect(await check({ type: "org" })).toBe("wrong_type");
    expect(await check({ email: undefined, sub: "" })).toBe("no_identity");
  });

  it("answers 403 for an expired token and a wrong audience through the Worker", async () => {
    const s = await signer();
    const expired = await sign(s, claims(ADMIN, { exp: nowS() - 3600 }));
    expect((await call("/api/accounts", { token: expired })).status).toBe(403);
    const wrongAud = await sign(s, claims(ADMIN, { aud: ["0".repeat(64)] }));
    expect((await call("/api/accounts", { token: wrongAud })).status).toBe(403);
  });

  it("refuses everything while the configuration is a placeholder", async () => {
    const request = withToken(await tokenFor(VIEWER));
    expect(await reason(request, { ACCESS_AUD: "<ACCESS_AUD>" })).toBe("config");
    expect(
      await reason(request, { ACCESS_TEAM_DOMAIN: "https://<team-name>.cloudflareaccess.com" }),
    ).toBe("config");
    expect(
      await reason(request, { ACCESS_TEAM_DOMAIN: "http://virga-test.cloudflareaccess.com" }),
    ).toBe("config");
    expect(await reason(request, { ACCESS_TEAM_DOMAIN: "https://evil.example.com" })).toBe(
      "config",
    );
    expect(
      accessConfig({ ...TEST_ACCESS, ACCESS_TEAM_DOMAIN: `${TEST_ACCESS.ACCESS_TEAM_DOMAIN}/` }),
    ).toMatchObject({ teamDomain: TEST_ACCESS.ACCESS_TEAM_DOMAIN });
  });

  it("compares ctx.access with the configured audience, and can require it", async () => {
    const token = await tokenFor(VIEWER);
    const aud = TEST_ACCESS.ACCESS_AUD;
    expect(await reason(withToken(token), {}, { access: { aud } })).toBe("ok");
    expect(await reason(withToken(token), {}, { access: { aud: "other" } })).toBe(
      "access_context_mismatch",
    );
    const strict = { REQUIRE_ACCESS_CONTEXT: "true" };
    expect(await reason(withToken(token), strict, {})).toBe("no_access_context");
    expect(await reason(withToken(token), strict, { access: { aud } })).toBe("ok");
    // ctx.access alone is not enough: the token is always verified.
    expect(
      await reason(new Request("https://virga.example.com/"), strict, { access: { aud } }),
    ).toBe("missing_token");
    expect((await call("/api/me", { token, access: { aud: "other" } })).status).toBe(403);
    expect((await call("/api/me", { token, access: { aud } })).status).toBe(200);
  });

  it("caches the signing keys and refetches them for a new kid", async () => {
    const first = await signer();
    const rotated = await newSigner("test-key-2");
    const fetches = serveCerts(first, rotated);
    for (let i = 0; i < 3; i++) {
      expect(await reason(withToken(await sign(first, claims(VIEWER))))).toBe("ok");
    }
    expect(fetches).toHaveBeenCalledTimes(1);
    expect(fetches.mock.calls[0]?.[0]).toBe(CERTS_URL);
    expect(await reason(withToken(await sign(rotated, claims(VIEWER))))).toBe("ok");
    expect(fetches).toHaveBeenCalledTimes(1);

    // An unknown kid refetches the keys, at most once per 30 seconds.
    const unknown = withToken(await sign(await newSigner("test-key-3"), claims(VIEWER)));
    const at = (seconds: number) =>
      authenticate(unknown, TEST_ACCESS, {}, Date.now() + seconds * 1000);
    expect(await at(0)).toEqual({ ok: false, reason: "unknown_key" });
    expect(fetches).toHaveBeenCalledTimes(1);
    expect(await at(31)).toEqual({ ok: false, reason: "unknown_key" });
    expect(await at(32)).toEqual({ ok: false, reason: "unknown_key" });
    expect(fetches).toHaveBeenCalledTimes(2);

    // After an hour the keys are fetched again; a failed fetch keeps the old ones.
    fetches.mockResolvedValue(new Response("down", { status: 503 }));
    const known = withToken(await sign(first, claims(VIEWER, { exp: nowS() + 7200 })));
    expect(await authenticate(known, TEST_ACCESS, {}, Date.now() + 3700_000)).toEqual({
      ok: true,
      identity: { email: VIEWER, serviceToken: null, admin: false },
    });
    expect(fetches).toHaveBeenCalledTimes(3);
  });

  it("refuses when the certs endpoint fails, and never logs the token", async () => {
    vi.restoreAllMocks();
    serveCerts();
    vi.mocked(globalThis.fetch).mockResolvedValue(new Response("down", { status: 503 }));
    const logs = captureLogs();
    const token = await tokenFor(ADMIN);
    const response = await call("/api/accounts", { token });
    logs.restore();
    expect(response.status).toBe(403);
    expect(logs.text()).toContain("keys_unavailable");
    expect(logs.text()).not.toContain(token);
    expect(logs.text()).not.toContain(token.split(".")[2]);
  });

  it("uses the Worker's configured vars", () => {
    expect(env.ACCESS_AUD).toBe(TEST_ACCESS.ACCESS_AUD);
  });
});
