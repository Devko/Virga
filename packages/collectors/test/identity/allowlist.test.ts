import { ALLOWED_READS, isAllowedRead, matchesRule } from "@virga/cf-api";
import { describe, expect, it } from "vitest";
import { IDENTITY_COLLECTORS } from "../../src/identity/index.ts";
import type { Collector } from "../../src/types.ts";
import {
  accessRoutes,
  insightsRoutes,
  membersRoutes,
  tokensRoutes,
  trafficRoutes,
  tunnelsRoutes,
} from "./fixtures/routes.ts";
import { trafficGraphql } from "./fixtures/traffic.ts";
import { ACCOUNT, callPaths, type Routes, run } from "./helpers.ts";

const CLASSES = ["access", "tunnels", "tokens", "members", "insights", "traffic"];
const IDENTITY_READS = ALLOWED_READS.filter((r) => CLASSES.includes(r.usedBy));
const ROUTES: Record<string, Routes> = {
  access: accessRoutes,
  tunnels: tunnelsRoutes,
  tokens: tokensRoutes,
  members: membersRoutes,
  insights: insightsRoutes,
  traffic: trafficRoutes,
};

describe("identity collectors", () => {
  it("cover each identity class once, with permission hints", () => {
    expect(IDENTITY_COLLECTORS.map((c) => c.resourceClass)).toEqual(CLASSES);
    for (const c of IDENTITY_COLLECTORS) {
      expect(c.permissions.length, c.resourceClass).toBeGreaterThan(0);
    }
  });
});

describe("identity read allowlist", () => {
  it("has only GET rules; GraphQL is in the core allowlist", () => {
    expect(IDENTITY_READS.length).toBeGreaterThan(0);
    for (const rule of IDENTITY_READS) {
      if (rule.pattern === "/graphql") continue;
      expect(rule.method, rule.pattern).toBe("GET");
    }
    expect(isAllowedRead("POST", "/graphql")).toBe(true);
  });

  it("is exactly what each collector calls", async () => {
    for (const collector of IDENTITY_COLLECTORS as Collector<unknown>[]) {
      const cls = collector.resourceClass;
      const graphql = cls === "traffic" ? trafficGraphql().handler : undefined;
      const { calls } = await run(collector, ROUTES[cls] ?? {}, graphql);
      const rest = calls.filter((c) => c.startsWith("GET "));
      const paths = callPaths(rest);
      const rules = IDENTITY_READS.filter((r) => r.usedBy === cls && r.method === "GET");
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

  it("reaches no tunnel tokens, single credentials or management endpoints", () => {
    const a = `/accounts/${ACCOUNT}`;
    const tunnel = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415";
    const forbidden = [
      `${a}/cfd_tunnel/${tunnel}/token`,
      `${a}/warp_connector/${tunnel}/token`,
      `${a}/cfd_tunnel/${tunnel}/connections`,
      `${a}/cfd_tunnel/${tunnel}/management`,
      `${a}/cfd_tunnel/${tunnel}`,
      `${a}/cfd_tunnel`,
      `${a}/warp_connector`,
      `${a}/access/service_tokens/3537a672-e4d8-4d89-aab9-26cb622918a1`,
      `${a}/access/service_tokens/3537a672-e4d8-4d89-aab9-26cb622918a1/rotate`,
      `${a}/access/service_tokens/3537a672-e4d8-4d89-aab9-26cb622918a1/refresh`,
      `${a}/access/identity_providers/f174e90a-fafe-4643-bbbc-4a0ed4fc8415`,
      `${a}/access/identity_providers/f174e90a-fafe-4643-bbbc-4a0ed4fc8415/refresh_scim_secret`,
      `${a}/access/apps/f174e90a-fafe-4643-bbbc-4a0ed4fc8415`,
      `${a}/access/apps/f174e90a-fafe-4643-bbbc-4a0ed4fc8415/revoke_tokens`,
      `${a}/access/apps/f174e90a-fafe-4643-bbbc-4a0ed4fc8415/user_policy_checks`,
      `${a}/access/certificates`,
      `${a}/access/keys`,
      `${a}/access/users`,
      `${a}/tokens/ed17574386854bf78a67040be0a770b0/value`,
      `${a}/members/4536bcfad5faccb111b47003c79917fa`,
      `${a}/security-center/insights/id/context`,
    ];
    for (const path of forbidden) {
      expect(isAllowedRead("GET", path, IDENTITY_READS), path).toBe(false);
      expect(isAllowedRead("POST", path, IDENTITY_READS), path).toBe(false);
    }
  });
});
