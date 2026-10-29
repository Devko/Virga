import { describe, expect, it } from "vitest";
import {
  ALLOWED_READS,
  createReader,
  isAllowedRead,
  isPlainPath,
  NoPermissionError,
  NotAllowedError,
  NotFoundError,
  RateLimitedError,
} from "../src/index.ts";
import { envelope, failure, fixtureTransport } from "../src/testing.ts";

const rules = [{ method: "GET" as const, pattern: "/accounts/:account_id/things", usedBy: "test" }];

describe("allowlist", () => {
  it("matches patterns segment by segment", () => {
    expect(isAllowedRead("GET", "/accounts/abc/things", rules)).toBe(true);
    expect(isAllowedRead("GET", "/accounts/abc/things/1", rules)).toBe(false);
    expect(isAllowedRead("POST", "/accounts/abc/things", rules)).toBe(false);
  });

  it("rejects paths that are not plain", () => {
    for (const path of ["accounts/a", "/accounts/../x", "/a//b", "/a?b=1", "/a/%2F", "/a/b#c"]) {
      expect(isPlainPath(path), path).toBe(false);
    }
  });

  it("contains only reads", () => {
    for (const rule of ALLOWED_READS) {
      expect(rule.method === "GET" || rule.pattern === "/graphql", rule.pattern).toBe(true);
    }
  });
});

describe("createReader", () => {
  it("follows page-based pagination", async () => {
    const transport = fixtureTransport(
      {
        "/accounts/a/tokens/verify": (q) =>
          envelope([Number(q.page)], { page: Number(q.page), total_pages: 3 }),
      },
      { enforceAllowlist: true },
    );
    const reader = createReader(transport);
    expect(await reader.all("/accounts/a/tokens/verify")).toEqual([1, 2, 3]);
    expect(transport.calls).toHaveLength(3);
  });

  it("follows cursor-based pagination", async () => {
    const pages: Record<string, unknown> = { start: ["a"], c1: ["b"], c2: [] };
    const transport = fixtureTransport({
      "/accounts/a/tokens/verify": (q) => {
        const key = String(q.cursor ?? "start");
        const next = key === "start" ? "c1" : key === "c1" ? "c2" : undefined;
        return envelope(pages[key], next ? { cursor: next } : {});
      },
    });
    expect(await createReader(transport).all("/accounts/a/tokens/verify")).toEqual(["a", "b"]);
  });

  it("maps statuses to typed errors", async () => {
    const reader = createReader(
      fixtureTransport({
        "/accounts/a/tokens/verify": failure(403, 10000, "Authentication error"),
        "/accounts/a/tokens/t1": { ...failure(429, 971, "rate limited"), retryAfter: 120 },
      }),
    );
    await expect(reader.get("/accounts/a/tokens/verify")).rejects.toBeInstanceOf(NoPermissionError);
    await expect(reader.get("/accounts/a/tokens/t1")).rejects.toBeInstanceOf(RateLimitedError);
    await expect(reader.get("/accounts/a/tokens/t2")).rejects.toBeInstanceOf(NotFoundError);
    await expect(reader.get("/accounts/a/workers/scripts")).rejects.toBeInstanceOf(NotAllowedError);
  });
});
