import { envelope } from "@virga/cf-api/testing";
import { describe, expect, it } from "vitest";
import { accessCollector } from "../../src/identity/access.ts";
import {
  APP_ADMIN,
  APP_ALL_PREVIEWS,
  APP_BOOKMARK,
  APP_PRIVATE,
  APP_SAAS,
  APP_SSH,
  APP_VNC,
  APP_WORKER,
  APPS,
  appsRoute,
  FAKE_CLIENT_ID,
  FAKE_SCIM_PASSWORD,
  FAKE_SECRET,
  GROUP_CONTRACTORS,
  GROUP_ENG,
  IDP_OKTA,
  IDP_OTP,
  POLICY_CI,
  POLICY_DEVS,
  POLICY_HEALTH,
  POLICY_MIXED,
  POLICY_UNUSED,
  TOKEN_CI,
  TOKEN_IDLE,
  TOKEN_LEAKED,
  WORKER_UNKNOWN,
} from "./fixtures/access.ts";
import { accessRoutes } from "./fixtures/routes.ts";
import {
  BASE,
  callPaths,
  context,
  denied,
  edge,
  edgeIds,
  expectDeterministic,
  expectNoPermission,
  expectProps,
  node,
  nodeIds,
  run,
} from "./helpers.ts";

const routes = accessRoutes;
const app = (id: string) => `access_app:${id}`;
const policy = (id: string) => `access_policy:${id}`;

describe("access collector", () => {
  it("plans the directory chunk and app chunks of 25", async () => {
    const { chunks, calls } = await run(accessCollector, routes);
    expect(chunks).toEqual([
      [{ kind: "directory" }],
      [
        APP_ADMIN,
        APP_WORKER,
        APP_ALL_PREVIEWS,
        APP_PRIVATE,
        APP_SSH,
        APP_VNC,
        APP_BOOKMARK,
        APP_SAAS,
      ]
        .sort()
        .map((id) => ({ kind: "app", id })),
    ]);
    // The app list comes in two pages, as total_pages says.
    expect(calls.slice(0, 2)).toEqual([
      `GET ${BASE}/access/apps?page=1&per_page=1000`,
      `GET ${BASE}/access/apps?page=2&per_page=1000`,
    ]);
    const many = Array.from({ length: 60 }, (_, i) => ({ ...APPS[0], id: `app-${i}` }));
    const plan = await accessCollector.plan(
      context({ ...routes, [`${BASE}/access/apps`]: appsRoute(many) }).ctx,
    );
    expect(plan.map((c) => c.length)).toEqual([1, 25, 25, 10]);
    const empty = await accessCollector.plan(
      context({ ...routes, [`${BASE}/access/apps`]: envelope([]) }).ctx,
    );
    expect(empty).toEqual([[{ kind: "directory" }]]);
  });

  it("emits access_app nodes with the contract props", async () => {
    const { output } = await run(accessCollector, routes);
    expectProps(output, "access_app", ["app_type", "targets", "session_duration", "allowed_idps"]);
    expect(node(output, app(APP_ADMIN))).toEqual({
      type: "access_app",
      nativeId: APP_ADMIN,
      name: "Admin Site",
      props: {
        app_type: "self_hosted",
        // Paths as configured, wildcards and the trailing slash included.
        targets: [
          { kind: "hostname", host: "*.example.com", path: "", overrides: [] },
          { kind: "hostname", host: "example.com", path: "/foo*/bar", overrides: [] },
          {
            kind: "hostname",
            host: "example.com",
            path: "/api/*",
            overrides: [{ behavior: "public", path_pattern: "/api/health" }],
          },
          { kind: "hostname", host: "test.example.com", path: "/admin/", overrides: [] },
          // A partial label wildcard has no place in the contract.
          { kind: "other", raw: { type: "public", uri: "shop*.example.com" } },
        ],
        session_duration: "24h",
        allowed_idps: [IDP_OKTA],
      },
    });
    expect(node(output, app(APP_SAAS)).props).toEqual({
      app_type: "saas",
      targets: [],
      session_duration: null,
      allowed_idps: [],
    });
  });

  it("maps Worker-level Access to the script, through the Worker list", async () => {
    const { output, calls } = await run(accessCollector, routes);
    expect(node(output, app(APP_WORKER)).props?.targets).toEqual([
      { kind: "other", raw: { type: "worker", worker_id: WORKER_UNKNOWN } },
      { kind: "worker", script: "api-worker", scope: "previews", overrides: [] },
      {
        kind: "worker",
        script: "my-worker",
        scope: "all",
        overrides: [{ behavior: "public", path_pattern: "/webhooks/*" }],
      },
    ]);
    // Account-level Worker Access has no single script.
    expect(node(output, app(APP_ALL_PREVIEWS)).props?.targets).toEqual([
      { kind: "all_workers", scope: "previews", overrides: [] },
    ]);
    // Read once, and only because of the Worker destinations.
    expect(callPaths(calls).filter((p) => p.endsWith("/workers/workers"))).toHaveLength(1);
  });

  it("leaves Worker destinations unresolved without permission to list Workers", async () => {
    const { output } = await run(accessCollector, {
      ...routes,
      [`${BASE}/workers/workers`]: denied(),
    });
    // The raw destination keeps the override, so its public path is not lost.
    expect(node(output, app(APP_WORKER)).props?.targets).toEqual([
      {
        kind: "other",
        raw: {
          overrides: [{ behavior: "public", path_pattern: "/webhooks/*" }],
          type: "worker",
          worker_id: "e8f70fdbc8b1fb0b8ddb1af166186758",
        },
      },
      {
        kind: "other",
        raw: { type: "preview_worker", worker_id: "c81a2d22c29840ed9d61681a3270dbff" },
      },
      { kind: "other", raw: { type: "worker", worker_id: WORKER_UNKNOWN } },
    ]);
    expect(node(output, app(APP_ADMIN)).props?.targets).toHaveLength(5);
  });

  it("does not list Workers when no app has a Worker destination", async () => {
    const { calls } = await run(accessCollector, {
      ...routes,
      [`${BASE}/access/apps`]: appsRoute(APPS.filter((a) => a.id !== APP_WORKER)),
    });
    expect(callPaths(calls)).not.toContain(`${BASE}/workers/workers`);
  });

  it("normalizes private, MCP portal, unknown, legacy and domain-only destinations", async () => {
    const { output } = await run(accessCollector, routes);
    expect(node(output, app(APP_PRIVATE)).props?.targets).toEqual([
      {
        kind: "private",
        cidr: "10.0.0.0/8",
        hostname: "intranet.example.internal",
        port_range: "443",
      },
      { kind: "other", raw: { coop: "north", type: "carrier_pigeon" } },
      { kind: "other", raw: { mcp_server_id: "mcp-1", type: "via_mcp_server_portal" } },
    ]);
    expect(node(output, app(APP_SSH)).props?.targets).toEqual([
      { kind: "hostname", host: "ssh.example.com", path: "", overrides: [] },
      { kind: "hostname", host: "test.anotherexample.com", path: "/staff", overrides: [] },
    ]);
    expect(node(output, app(APP_VNC)).props).toMatchObject({
      app_type: "vnc",
      targets: [{ kind: "hostname", host: "vnc.example.com", path: "", overrides: [] }],
      session_duration: "1h",
    });
    // A bookmark links, it does not protect.
    expect(node(output, app(APP_BOOKMARK)).props?.targets).toEqual([]);
  });

  it("emits policies with normalized selectors", async () => {
    const { output } = await run(accessCollector, routes);
    expectProps(output, "access_policy", [
      "decision",
      "include",
      "require",
      "exclude",
      "session_duration",
    ]);
    expect(nodeIds(output, "access_policy")).toEqual(
      [POLICY_DEVS, POLICY_HEALTH, POLICY_CI, POLICY_MIXED, POLICY_UNUSED].map(policy).sort(),
    );
    expect(node(output, policy(POLICY_DEVS))).toEqual({
      type: "access_policy",
      nativeId: POLICY_DEVS,
      name: "Allow devs",
      props: {
        decision: "allow",
        include: [
          { kind: "email_domain", value: "example.com" },
          { kind: "group", value: GROUP_ENG },
        ],
        require: [{ kind: "login_method", value: IDP_OKTA }],
        exclude: [{ kind: "email", value: "intern@example.com" }],
        session_duration: "24h",
      },
    });
    expect(node(output, policy(POLICY_HEALTH)).props).toEqual({
      decision: "bypass",
      include: [{ kind: "everyone", value: null }],
      require: [],
      exclude: [],
      session_duration: null,
    });
    expect(node(output, policy(POLICY_CI)).props).toMatchObject({
      decision: "non_identity",
      include: [
        { kind: "any_valid_service_token", value: null },
        { kind: "service_token", value: TOKEN_CI },
      ],
    });
    const mixed = node(output, policy(POLICY_MIXED)).props ?? {};
    expect((mixed.include as { kind: string }[]).map((s) => s.kind)).toEqual([
      "certificate",
      "common_name",
      "device_posture",
      "email_list",
      "geo",
      "idp_group",
      "idp_group",
      "idp_group",
      "idp_group",
      "idp_group",
      "idp_group",
      "ip",
    ]);
    expect(mixed.require).toEqual([
      { kind: "other", value: { auth_method: { auth_method: "mfa" } } },
      { kind: "other", value: { ip_list: { id: "a05b3c4d-2e6f-4a7b-8c9d-e0f1a2b3c4d5" } } },
    ]);
    expect(mixed.exclude).toEqual([
      { kind: "other", value: { email: {} } },
      {
        kind: "other",
        value: {
          external_evaluation: {
            evaluate_url: "https://eval.example.com",
            keys_url: "https://eval.example.com/keys",
          },
        },
      },
    ]);
  });

  it("emits ALLOWS with the precedence of the policy in each app", async () => {
    const { output } = await run(accessCollector, routes);
    expect(edgeIds(output, "ALLOWS")).toEqual(
      [
        `ALLOWS:${policy(POLICY_CI)}->${app(APP_WORKER)}`,
        `ALLOWS:${policy(POLICY_DEVS)}->${app(APP_ADMIN)}`,
        `ALLOWS:${policy(POLICY_DEVS)}->${app(APP_ALL_PREVIEWS)}`,
        `ALLOWS:${policy(POLICY_DEVS)}->${app(APP_SAAS)}`,
        `ALLOWS:${policy(POLICY_DEVS)}->${app(APP_SSH)}`,
        `ALLOWS:${policy(POLICY_DEVS)}->${app(APP_WORKER)}`,
        `ALLOWS:${policy(POLICY_HEALTH)}->${app(APP_ADMIN)}`,
        `ALLOWS:${policy(POLICY_MIXED)}->${app(APP_PRIVATE)}`,
      ].sort(),
    );
    expect(edge(output, `ALLOWS:${policy(POLICY_DEVS)}->${app(APP_ADMIN)}`)).toEqual({
      type: "ALLOWS",
      src: policy(POLICY_DEVS),
      dst: app(APP_ADMIN),
      props: { precedence: 1 },
    });
    expect(edge(output, `ALLOWS:${policy(POLICY_DEVS)}->${app(APP_WORKER)}`).props).toEqual({
      precedence: 2,
    });
    // The unused reusable policy allows nothing.
    expect(edgeIds(output, "ALLOWS").some((id) => id.includes(POLICY_UNUSED))).toBe(false);
  });

  it("emits SELECTS edges keyed by list, and the everyone node once", async () => {
    const { output } = await run(accessCollector, routes);
    expect(edgeIds(output, "SELECTS")).toEqual(
      [
        `SELECTS:access_group:${GROUP_ENG}->access_group:${GROUP_CONTRACTORS}#exclude`,
        `SELECTS:access_group:${GROUP_ENG}->identity_provider:${IDP_OKTA}#include`,
        `SELECTS:${policy(POLICY_CI)}->service_token:${TOKEN_CI}#include`,
        `SELECTS:${policy(POLICY_DEVS)}->access_group:${GROUP_ENG}#include`,
        `SELECTS:${policy(POLICY_DEVS)}->identity_provider:${IDP_OKTA}#require`,
        `SELECTS:${policy(POLICY_HEALTH)}->everyone:everyone#include`,
        `SELECTS:${policy(POLICY_MIXED)}->identity_provider:${IDP_OKTA}#include`,
        `SELECTS:${policy(POLICY_UNUSED)}->everyone:everyone#include`,
      ].sort(),
    );
    expect(edge(output, `SELECTS:${policy(POLICY_HEALTH)}->everyone:everyone#include`)).toEqual({
      type: "SELECTS",
      src: policy(POLICY_HEALTH),
      dst: "everyone:everyone",
      key: "include",
      props: {},
    });
    expect(nodeIds(output, "everyone")).toEqual(["everyone:everyone"]);
    expect(node(output, "everyone:everyone")).toEqual({
      type: "everyone",
      nativeId: "everyone",
      name: "Everyone",
      props: {},
    });
  });

  it("emits groups, service tokens with last_seen_at, and identity providers", async () => {
    const { output } = await run(accessCollector, routes);
    expectProps(output, "access_group", ["include", "require", "exclude"]);
    expect(node(output, `access_group:${GROUP_ENG}`)).toEqual({
      type: "access_group",
      nativeId: GROUP_ENG,
      name: "Engineering",
      props: {
        include: [{ kind: "idp_group", value: { idp: IDP_OKTA, name: "engineering" } }],
        require: [],
        exclude: [{ kind: "group", value: GROUP_CONTRACTORS }],
      },
    });

    expectProps(output, "service_token", ["expires_at", "duration", "enabled"]);
    expect(node(output, `service_token:${TOKEN_CI}`)).toEqual({
      type: "service_token",
      nativeId: TOKEN_CI,
      name: "CI/CD token",
      props: { expires_at: "2014-01-01T05:20:00.12345Z", duration: "60m", enabled: true },
    });
    // The field is optional: null, not a guess, when the API omits it.
    expect(node(output, `service_token:${TOKEN_IDLE}`).props).toEqual({
      expires_at: null,
      duration: "forever",
      enabled: null,
    });
    expect(node(output, `service_token:${TOKEN_LEAKED}`).props).toEqual({
      expires_at: "2026-02-01T00:00:00Z",
      duration: "8760h",
      enabled: false,
    });
    expect(output.signals).toEqual([
      {
        nodeId: `service_token:${TOKEN_CI}`,
        name: "last_seen_at",
        value: Date.parse("2014-01-01T05:20:00.12345Z"),
      },
      // Never seen: null, not missing, so rules can tell it from no data.
      { nodeId: `service_token:${TOKEN_IDLE}`, name: "last_seen_at", value: null },
      {
        nodeId: `service_token:${TOKEN_LEAKED}`,
        name: "last_seen_at",
        value: Date.parse("2025-06-01T08:00:00Z"),
      },
    ]);

    expectProps(output, "identity_provider", ["idp_type"]);
    expect(node(output, `identity_provider:${IDP_OTP}`)).toEqual({
      type: "identity_provider",
      nativeId: IDP_OTP,
      name: "Widget Corps IDP",
      props: { idp_type: "onetimepin" },
    });
    expect(node(output, `identity_provider:${IDP_OKTA}`).props).toEqual({ idp_type: "okta" });
  });

  it("keeps credentials from the listings out of the output", async () => {
    const { output } = await run(accessCollector, routes);
    const json = JSON.stringify(output);
    for (const secret of [FAKE_SECRET, FAKE_SCIM_PASSWORD, FAKE_CLIENT_ID]) {
      expect(json).not.toContain(secret);
    }
  });

  it("reads a missing policies route as no policies", async () => {
    const { output, calls } = await run(accessCollector, routes);
    expect(calls).toContain(
      `GET ${BASE}/access/apps/${APP_BOOKMARK}/policies?page=1&per_page=1000`,
    );
    expect(nodeIds(output, "access_app")).toContain(app(APP_BOOKMARK));
  });

  it("is deterministic", async () => {
    await expectDeterministic(accessCollector, routes);
  });

  it("surfaces 403 as NoPermissionError", async () => {
    await expectNoPermission(accessCollector, { ...routes, [`${BASE}/access/apps`]: denied() });
    await expectNoPermission(accessCollector, {
      ...routes,
      [`${BASE}/access/apps/${APP_ADMIN}/policies`]: denied(),
    });
    for (const resource of ["policies", "groups", "service_tokens", "identity_providers"]) {
      await expectNoPermission(accessCollector, {
        ...routes,
        [`${BASE}/access/${resource}`]: denied(),
      });
    }
  });
});
