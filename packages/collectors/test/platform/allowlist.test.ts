import { ALLOWED_READS, isAllowedRead, matchesRule } from "@virga/cf-api";
import { describe, expect, it } from "vitest";
import { PLATFORM_COLLECTORS } from "../../src/platform/index.ts";
import type { Collector } from "../../src/types.ts";
import {
  ACCOUNT,
  dnsRoutes,
  pagesRoutes,
  type Routes,
  storageRoutes,
  workersRoutes,
  zonesRoutes,
} from "./fixtures/routes.ts";
import { run } from "./helpers.ts";

const CLASSES = ["zones", "dns", "workers", "pages", "storage"];
const PLATFORM_READS = ALLOWED_READS.filter((r) => CLASSES.includes(r.usedBy));
const ROUTES: Record<string, Routes> = {
  zones: zonesRoutes,
  dns: dnsRoutes,
  workers: workersRoutes,
  pages: pagesRoutes,
  storage: storageRoutes,
};

describe("platform collectors", () => {
  it("cover each platform class once, with permission hints", () => {
    expect(PLATFORM_COLLECTORS.map((c) => c.resourceClass)).toEqual(CLASSES);
    for (const c of PLATFORM_COLLECTORS)
      expect(c.permissions.length, c.resourceClass).toBeGreaterThan(0);
  });
});

describe("platform read allowlist", () => {
  it("has only GET rules", () => {
    expect(PLATFORM_READS.length).toBeGreaterThan(0);
    for (const rule of PLATFORM_READS) expect(rule.method, rule.pattern).toBe("GET");
  });

  it("is exactly what each collector calls", async () => {
    for (const collector of PLATFORM_COLLECTORS as Collector<unknown>[]) {
      const cls = collector.resourceClass;
      const { calls } = await run(collector, ROUTES[cls] ?? {});
      const paths = calls.map((c) => c.replace(/^GET /, "").split("?")[0] ?? "");
      const rules = PLATFORM_READS.filter((r) => r.usedBy === cls);
      for (const path of paths) {
        expect(
          rules.some((r) => matchesRule(r, "GET", path)),
          `${cls} calls ${path}`,
        ).toBe(true);
      }
      for (const rule of rules) {
        expect(
          paths.some((p) => matchesRule(rule, "GET", p)),
          `${cls} never uses ${rule.pattern}`,
        ).toBe(true);
      }
    }
  });

  it("reaches no code, values, object contents or secrets", () => {
    const a = `/accounts/${ACCOUNT}`;
    const forbidden = [
      `${a}/workers/scripts/my-worker`,
      `${a}/workers/scripts/my-worker/content`,
      `${a}/workers/scripts/my-worker/content/v2`,
      `${a}/workers/scripts/my-worker/secrets`,
      `${a}/workers/scripts/my-worker/secrets/KEY`,
      `${a}/workers/scripts/my-worker/settings`,
      `${a}/workers/workers/my-worker/versions/18f97339-c287-4872-9bdd-e2135c07ec12`,
      `${a}/storage/kv/namespaces/0f2ac74b498b48028cb68387c421e279/keys`,
      `${a}/storage/kv/namespaces/0f2ac74b498b48028cb68387c421e279/values/key`,
      `${a}/storage/kv/namespaces/0f2ac74b498b48028cb68387c421e279/metadata/key`,
      `${a}/r2/buckets/example-bucket/objects`,
      `${a}/r2/buckets/example-bucket/objects/file.txt`,
      `${a}/d1/database/445e2955-951a-43f8-a35b-a4d0c8138f63/export`,
      `${a}/secrets_store/stores/023e105f4ecef8ad9ca31a8372d0c353/secrets/MY_API_KEY`,
      `${a}/pages/projects/docs/deployments`,
    ];
    for (const path of forbidden) {
      expect(isAllowedRead("GET", path, PLATFORM_READS), path).toBe(false);
      expect(isAllowedRead("POST", path, PLATFORM_READS), path).toBe(false);
    }
  });
});
