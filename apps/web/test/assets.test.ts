import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CSP } from "../src/http.ts";
import { VIEWER } from "./config.ts";
import { ACCOUNT } from "./fixtures.ts";
import { call, serveCerts, signer, tokenFor } from "./helpers.ts";

// The SPA build (`vite build`, run before the tests) served through the
// Worker: only after the Access check, with the security headers.

let token: string;

beforeEach(async () => {
  serveCerts(await signer());
  token = await tokenFor(VIEWER);
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("SPA assets", () => {
  it("serves the built index with external scripts only and a strict CSP", async () => {
    const response = await call("/", { token });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/^text\/html/);
    expect(response.headers.get("content-security-policy")).toBe(CSP);
    expect(CSP).toContain("script-src 'self'");
    expect(CSP).not.toMatch(/unsafe-inline|unsafe-eval/);
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    const html = await response.text();
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
    expect(scripts.length).toBeGreaterThan(0);
    for (const [, attributes = "", body = ""] of scripts) {
      expect(attributes).toMatch(/src="\/assets\/[\w.-]+\.js"/);
      expect(body.trim()).toBe("");
    }
    expect(html).not.toMatch(/<style|\sstyle=|\son\w+=/i);

    const src = /src="(\/assets\/[\w.-]+\.js)"/.exec(html)?.[1] as string;
    const script = await call(src, { token });
    expect(script.status).toBe(200);
    expect(script.headers.get("content-type")).toMatch(/javascript/);
    expect(script.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("answers app paths with the SPA, and refuses assets without a token", async () => {
    const page = await call(`/accounts/${ACCOUNT}`, { token });
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('<div id="root">');
    expect((await call(`/accounts/${ACCOUNT}`)).status).toBe(403);
    expect((await call("/favicon.svg")).status).toBe(403);
    expect((await call("/favicon.svg", { token })).status).toBe(200);
  });

  it("does not serve assets for writes", async () => {
    expect((await call("/", { token, method: "POST" })).status).toBe(405);
    const api = await call("/api/unknown", { token });
    expect(api.status).toBe(404);
    expect(api.headers.get("content-type")).toMatch(/^application\/json/);
  });
});
