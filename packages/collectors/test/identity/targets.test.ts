import { describe, expect, it } from "vitest";
import { appTargets, hostTarget, needsWorkerScripts } from "../../src/identity/targets.ts";

// Wildcard and path semantics:
// https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/
// Destination types and overrides:
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/

const hostname = (host: string, path = "", overrides: object[] = []) => ({
  kind: "hostname",
  host,
  path,
  overrides,
});

describe("hostTarget", () => {
  const cases: [string, ReturnType<typeof hostname>][] = [
    ["example.com", hostname("example.com")],
    ["Test.Example.COM/admin", hostname("test.example.com", "/admin")],
    // Paths stay as configured; the evaluator applies Access path semantics.
    ["test.example.com/admin/", hostname("test.example.com", "/admin/")],
    // Paths keep their case: they are matched case-sensitively.
    ["example.com/Admin/Users", hostname("example.com", "/Admin/Users")],
    ["*.example.com", hostname("*.example.com")],
    ["*.test.example.com/api", hostname("*.test.example.com", "/api")],
    ["example.com/*", hostname("example.com", "/*")],
    // `/alpha/*` does not cover `/alpha`, so the wildcard is kept.
    ["example.com/alpha/*", hostname("example.com", "/alpha/*")],
    ["example.com/alpha*", hostname("example.com", "/alpha*")],
    ["example.com/foo*/bar", hostname("example.com", "/foo*/bar")],
    ["https://example.com/login", hostname("example.com", "/login")],
    ["my-worker.my-sub.workers.dev", hostname("my-worker.my-sub.workers.dev")],
  ];
  it.each(cases)("normalizes %s", (input, expected) => {
    expect(hostTarget(input)).toEqual(expected);
  });

  const unplaceable = [
    "*test.example.com",
    "foo*.example.com",
    "*.*.example.com",
    "test.*.example.com",
    "*",
    "example.com:8443/admin",
    "example.com/search?q=1",
    "example.com/#settings",
    "/admin",
    "",
  ];
  it.each(unplaceable)("maps %j to other", (input) => {
    expect(hostTarget(input)).toEqual({ kind: "other", raw: input });
  });

  it("maps an overlong host or path to other", () => {
    expect(hostTarget(`${"a".repeat(64)}.example.com`).kind).toBe("other");
    expect(hostTarget(`example.com/${"p".repeat(2000)}`).kind).toBe("other");
  });
});

describe("appTargets", () => {
  const scripts = new Map([["w1", "my-worker"]]);

  it("prefers destinations over self_hosted_domains over domain", () => {
    const app = {
      type: "self_hosted",
      domain: "c.example.com",
      self_hosted_domains: ["b.example.com"],
      destinations: [{ type: "public", uri: "a.example.com" }],
    };
    expect(appTargets(app, null)).toEqual([hostname("a.example.com")]);
    expect(appTargets({ ...app, destinations: [] }, null)).toEqual([hostname("b.example.com")]);
    expect(appTargets({ ...app, destinations: [], self_hosted_domains: [] }, null)).toEqual([
      hostname("c.example.com"),
    ]);
  });

  it("maps a public destination without a type by its uri", () => {
    expect(appTargets({ destinations: [{ uri: "a.example.com/x" }] }, null)).toEqual([
      hostname("a.example.com", "/x"),
    ]);
  });

  it("keeps destination overrides on hostname, Worker and all-Workers targets, sorted", () => {
    const health = { behavior: "public", path_pattern: "/health" };
    const hooks = { behavior: "public", path_pattern: "/webhooks/*" };
    const destinations = [
      { type: "public", uri: "a.example.com", overrides: [health, hooks, health] },
      { type: "worker", worker_id: "w1", overrides: [hooks] },
      { type: "all_preview_workers", overrides: [health] },
      // A behavior added later is kept, so the evaluator can return unknown for it.
      {
        type: "public",
        uri: "b.example.com/app",
        overrides: [{ behavior: "isolate", path_pattern: "/x" }],
      },
    ];
    expect(appTargets({ destinations }, scripts)).toEqual([
      hostname("a.example.com", "", [health, hooks]),
      hostname("b.example.com", "/app", [{ behavior: "isolate", path_pattern: "/x" }]),
      { kind: "all_workers", scope: "previews", overrides: [health] },
      { kind: "worker", script: "my-worker", scope: "all", overrides: [hooks] },
    ]);
  });

  it("maps a destination whose overrides cannot be read to other, so no public path is lost", () => {
    for (const overrides of [
      "/health",
      [{ path_pattern: "/health" }],
      [{ behavior: "public" }],
      [{ behavior: "public", path_pattern: "" }],
      [{ behavior: "public", path_pattern: `/${"p".repeat(600)}` }],
      ["/health"],
      Array.from({ length: 101 }, (_, i) => ({ behavior: "public", path_pattern: `/p${i}` })),
    ]) {
      const [target] = appTargets(
        { destinations: [{ type: "public", uri: "a.example.com", overrides }] },
        null,
      );
      expect(target?.kind, JSON.stringify(overrides).slice(0, 80)).toBe("other");
    }
  });

  const publicPaths = (count: number) =>
    Array.from({ length: count }, (_, i) => ({
      behavior: "public",
      path_pattern: `/p${String(i).padStart(3, "0")}`,
    }));

  it("R2-06: keeps every override of a Worker or all-Workers target, verbatim", () => {
    const overrides = publicPaths(21);
    const long = { behavior: "public", path_pattern: `/${"q".repeat(511)}` };
    const destinations = [
      { type: "all_workers", overrides },
      { type: "worker", worker_id: "w1", overrides: [...overrides, long] },
    ];
    expect(appTargets({ destinations }, scripts)).toEqual([
      { kind: "all_workers", scope: "all", overrides },
      { kind: "worker", script: "my-worker", scope: "all", overrides: [...overrides, long] },
    ]);
    const hundred = publicPaths(100);
    expect(
      appTargets({ destinations: [{ type: "all_workers", overrides: hundred }] }, null),
    ).toEqual([{ kind: "all_workers", scope: "all", overrides: hundred }]);
  });

  it("R2-06: maps more overrides than the limit to other, keeping what scopes it", () => {
    const overrides = publicPaths(101);
    const destinations = [
      { type: "all_workers", overrides },
      { type: "all_preview_workers", overrides },
      { type: "worker", worker_id: "w1", overrides },
      { type: "public", uri: "a.example.com/app", overrides },
    ];
    const targets = appTargets({ destinations }, scripts);
    expect(targets.map((t) => t.kind)).toEqual(["other", "other", "other", "other"]);
    // The evaluator limits an `other` target by its API type, Worker ID or host.
    expect(targets.map((t) => (t.kind === "other" ? t.raw : null))).toEqual([
      expect.objectContaining({ type: "all_preview_workers" }),
      expect.objectContaining({ type: "all_workers" }),
      expect.objectContaining({ type: "public", uri: "a.example.com/app" }),
      expect.objectContaining({ type: "worker", worker_id: "w1" }),
    ]);
  });

  it("maps Worker destinations to the script, or to other when it cannot be resolved", () => {
    const destinations = [
      { type: "worker", worker_id: "w1" },
      { type: "preview_worker", worker_id: "w1" },
      { type: "worker", worker_id: "w2" },
      { type: "worker" },
    ];
    expect(appTargets({ destinations }, scripts)).toEqual([
      { kind: "other", raw: { type: "worker", worker_id: "w2" } },
      { kind: "other", raw: { type: "worker" } },
      { kind: "worker", script: "my-worker", scope: "all", overrides: [] },
      { kind: "worker", script: "my-worker", scope: "previews", overrides: [] },
    ]);
    // Without the Worker list nothing can be resolved.
    expect(appTargets({ destinations: destinations.slice(0, 1) }, null)).toEqual([
      { kind: "other", raw: { type: "worker", worker_id: "w1" } },
    ]);
  });

  it("maps account-level Worker Access to all_workers", () => {
    expect(appTargets({ destinations: [{ type: "all_workers" }] }, null)).toEqual([
      { kind: "all_workers", scope: "all", overrides: [] },
    ]);
    expect(appTargets({ destinations: [{ type: "all_preview_workers" }] }, null)).toEqual([
      { kind: "all_workers", scope: "previews", overrides: [] },
    ]);
  });

  it("maps MCP portal and unknown destination types to other", () => {
    for (const dest of [
      { type: "via_mcp_server_portal", mcp_server_id: "m" },
      { type: "carrier_pigeon" },
      { type: "constructor" },
      { type: "public" },
      "a.example.com",
    ]) {
      expect(appTargets({ destinations: [dest] }, scripts), JSON.stringify(dest)).toEqual([
        { kind: "other", raw: dest },
      ]);
    }
  });

  it("maps a private destination with nulls for missing parts", () => {
    expect(
      appTargets({ destinations: [{ type: "private", cidr: "10.0.0.0/8", vnet_id: "v" }] }, null),
    ).toEqual([{ kind: "private", cidr: "10.0.0.0/8", hostname: null, port_range: null }]);
    expect(
      appTargets({ destinations: [{ hostname: "DB.internal", port_range: "5432" }] }, null),
    ).toEqual([{ kind: "private", cidr: null, hostname: "db.internal", port_range: "5432" }]);
  });

  it("gives a bookmark and an app without destinations no targets", () => {
    expect(appTargets({ type: "bookmark", domain: "https://wiki.example.com" }, null)).toEqual([]);
    expect(appTargets({ type: "saas", saas_app: {} }, null)).toEqual([]);
  });

  it("bounds the raw value of other targets", () => {
    const [target] = appTargets({ destinations: [{ type: "x", note: "n".repeat(1000) }] }, null);
    expect(target?.kind).toBe("other");
    expect(JSON.stringify(target).length).toBeLessThan(400);
  });

  it("sorts and deduplicates targets", () => {
    const app = { self_hosted_domains: ["b.example.com", "a.example.com", "B.example.com"] };
    expect(appTargets(app, null)).toEqual([hostname("a.example.com"), hostname("b.example.com")]);
  });

  it("asks for the Worker list only for single-Worker destinations", () => {
    expect(needsWorkerScripts({ destinations: [{ type: "worker", worker_id: "w1" }] })).toBe(true);
    expect(needsWorkerScripts({ destinations: [{ type: "preview_worker", worker_id: "w" }] })).toBe(
      true,
    );
    expect(needsWorkerScripts({ destinations: [{ type: "all_workers" }] })).toBe(false);
    expect(needsWorkerScripts({ domain: "a.example.com" })).toBe(false);
  });
});
