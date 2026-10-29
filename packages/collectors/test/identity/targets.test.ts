import { describe, expect, it } from "vitest";
import { appTargets, hostTarget, needsWorkerScripts } from "../../src/identity/targets.ts";

// Wildcard and path semantics:
// https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/

describe("hostTarget", () => {
  const cases: [string, ReturnType<typeof hostTarget>][] = [
    ["example.com", { kind: "hostname", host: "example.com", path: "" }],
    ["Test.Example.COM/admin", { kind: "hostname", host: "test.example.com", path: "/admin" }],
    ["test.example.com/admin/", { kind: "hostname", host: "test.example.com", path: "/admin" }],
    // Paths keep their case: they are matched case-sensitively.
    ["example.com/Admin/Users", { kind: "hostname", host: "example.com", path: "/Admin/Users" }],
    ["*.example.com", { kind: "hostname", host: "*.example.com", path: "" }],
    ["*.test.example.com/api", { kind: "hostname", host: "*.test.example.com", path: "/api" }],
    // `example.com/*` covers the apex and every path, like `example.com`.
    ["example.com/*", { kind: "hostname", host: "example.com", path: "" }],
    ["example.com/alpha/*", { kind: "hostname", host: "example.com", path: "/alpha" }],
    ["https://example.com/login", { kind: "hostname", host: "example.com", path: "/login" }],
    [
      "my-worker.my-sub.workers.dev",
      { kind: "hostname", host: "my-worker.my-sub.workers.dev", path: "" },
    ],
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
    "example.com/foo*/bar",
    "example.com/alpha*",
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
    expect(appTargets(app, null)).toEqual([{ kind: "hostname", host: "a.example.com", path: "" }]);
    expect(appTargets({ ...app, destinations: [] }, null)).toEqual([
      { kind: "hostname", host: "b.example.com", path: "" },
    ]);
    expect(appTargets({ ...app, destinations: [], self_hosted_domains: [] }, null)).toEqual([
      { kind: "hostname", host: "c.example.com", path: "" },
    ]);
  });

  it("maps a public destination without a type by its uri", () => {
    expect(appTargets({ destinations: [{ uri: "a.example.com/x" }] }, null)).toEqual([
      { kind: "hostname", host: "a.example.com", path: "/x" },
    ]);
  });

  it("adds an other target for destination overrides, which make paths public", () => {
    const dest = {
      type: "public",
      uri: "a.example.com",
      overrides: [{ behavior: "public", path_pattern: "/health/*" }],
    };
    expect(appTargets({ destinations: [dest] }, null)).toEqual([
      { kind: "hostname", host: "a.example.com", path: "" },
      { kind: "other", raw: dest },
    ]);
  });

  it("maps Worker destinations to the script, or to other when it cannot be resolved", () => {
    const destinations = [
      { type: "worker", worker_id: "w1" },
      { type: "preview_worker", worker_id: "w1" },
      { type: "worker", worker_id: "w2" },
    ];
    expect(appTargets({ destinations }, scripts)).toEqual([
      { kind: "other", raw: { type: "worker", worker_id: "w2" } },
      { kind: "worker", script: "my-worker", scope: "all" },
      { kind: "worker", script: "my-worker", scope: "previews" },
    ]);
    // Without the Worker list nothing can be resolved.
    expect(appTargets({ destinations: destinations.slice(0, 1) }, null)).toEqual([
      { kind: "other", raw: { type: "worker", worker_id: "w1" } },
    ]);
  });

  it("maps account-level Worker Access and unknown destination types to other", () => {
    for (const dest of [
      { type: "all_workers" },
      { type: "all_preview_workers" },
      { type: "via_mcp_server_portal", mcp_server_id: "m" },
      { type: "carrier_pigeon" },
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
    expect(appTargets(app, null)).toEqual([
      { kind: "hostname", host: "a.example.com", path: "" },
      { kind: "hostname", host: "b.example.com", path: "" },
    ]);
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
