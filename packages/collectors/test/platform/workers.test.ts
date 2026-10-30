import { envelope } from "@virga/cf-api/testing";
import { describe, expect, it } from "vitest";
import { PREVIEW_WINDOW, workersCollector } from "../../src/platform/workers.ts";
import { workersRoutes } from "./fixtures/routes.ts";
import { doNamespaceLegacy, queueExample } from "./fixtures/storage.ts";
import {
  apiWorker,
  FAKE_TOKEN,
  PLAIN_URL,
  routeWithoutScript,
  routeWithScript,
  V_API_1,
  V_MY_0,
  V_MY_1,
  V_MY_2,
  V_MY_3,
  versionMy2,
} from "./fixtures/workers.ts";
import { ZONE_A, ZONE_B } from "./fixtures/zones.ts";
import {
  ACCOUNT,
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
  without,
} from "./helpers.ts";

const base = `/accounts/${ACCOUNT}/workers`;
const scripts = `${base}/scripts`;

const routes = workersRoutes;

const SCRIPT = "worker_script:my-worker";

describe("workers collector", () => {
  it("plans script chunks of 20 and zone chunks of 25", async () => {
    const { chunks } = await run(workersCollector, routes);
    expect(chunks).toEqual([
      [
        { kind: "script", name: "api-worker" },
        { kind: "script", name: "legacy-worker" },
        { kind: "script", name: "my-worker" },
      ],
      [
        { kind: "zone", id: ZONE_A },
        { kind: "zone", id: ZONE_B },
      ],
    ]);
    const many = Array.from({ length: 45 }, (_, i) => ({ ...apiWorker, name: `w-${i}` }));
    const plan = await workersCollector.plan(
      context({ ...routes, [`${base}/workers`]: envelope(many) }).ctx,
    );
    expect(plan.map((c) => c.length)).toEqual([20, 20, 5, 2]);
  });

  it("emits worker_script nodes with the contract props", async () => {
    const { output } = await run(workersCollector, routes);
    expectProps(output, "worker_script", [
      "worker_id",
      "workers_dev",
      "preview_urls",
      "has_assets",
      "compatibility_date",
      "created_on",
      "modified_on",
    ]);
    expect(node(output, SCRIPT)).toEqual({
      type: "worker_script",
      nativeId: "my-worker",
      name: "my-worker",
      props: {
        worker_id: "e8f70fdbc8b1fb0b8ddb1af166186758",
        workers_dev: true,
        preview_urls: true,
        has_assets: null,
        // From the version with 90 % of traffic.
        compatibility_date: "2024-09-23",
        created_on: "2019-12-27T18:11:19.117Z",
        modified_on: "2024-10-02T08:00:00.000Z",
      },
    });
    expect(node(output, "worker_script:api-worker").props).toMatchObject({
      workers_dev: false,
      preview_urls: false,
      compatibility_date: "2023-05-18",
    });
    // Flags from the script's subdomain endpoint; never deployed.
    expect(node(output, "worker_script:legacy-worker").props).toMatchObject({
      worker_id: "6c2d7e1f3a4b5c8d9e0f1a2b3c4d5e6f",
      workers_dev: true,
      preview_urls: false,
      compatibility_date: null,
    });
  });

  it("emits deployed versions with DEPLOYS percentages and without values", async () => {
    const { output } = await run(workersCollector, routes);
    expect(edgeIds(output, "DEPLOYS")).toEqual([
      `DEPLOYS:worker_script:api-worker->worker_version:${V_API_1}`,
      `DEPLOYS:${SCRIPT}->worker_version:${V_MY_2}`,
      `DEPLOYS:${SCRIPT}->worker_version:${V_MY_1}`,
    ]);
    expect(edge(output, `DEPLOYS:${SCRIPT}->worker_version:${V_MY_1}`).props).toEqual({
      percentage: 90,
    });
    expect(edge(output, `DEPLOYS:${SCRIPT}->worker_version:${V_MY_2}`).props).toEqual({
      percentage: 10,
    });
    // The older deployment's version is neither deployed nor in the preview window.
    expect(nodeIds(output, "worker_version")).not.toContain(`worker_version:${V_MY_0}`);

    expectProps(output, "worker_version", [
      "script_node_id",
      "number",
      "created_on",
      "source",
      "plain_text_vars",
      "secret_names",
    ]);
    expect(node(output, `worker_version:${V_MY_1}`)).toEqual({
      type: "worker_version",
      nativeId: V_MY_1,
      name: "12",
      props: {
        script_node_id: SCRIPT,
        number: 12,
        created_on: "2024-09-23T09:00:00.000Z",
        source: "wrangler",
        plain_text_vars: [
          { name: "API_BASE", kind: "plain_text", looks_secret: false, secret_pattern: null },
          { name: "CF_TOKEN", kind: "plain_text", looks_secret: true, secret_pattern: "cfat_" },
        ],
        secret_names: ["STRIPE_KEY"],
      },
    });
    expect(node(output, `worker_version:${V_API_1}`).props).toMatchObject({
      script_node_id: "worker_script:api-worker",
      source: "dash",
      plain_text_vars: [],
      secret_names: [],
    });
    const json = JSON.stringify(output);
    expect(json).not.toContain(FAKE_TOKEN);
    expect(json).not.toContain(PLAIN_URL);
  });

  it("R2-09: inspects every string of a json binding and keeps only the verdict", async () => {
    const awsKey = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
    const bindings = [
      // wrangler uploads a [vars] entry with an object value as a json binding.
      { name: "CONFIG", type: "json", json: { api_key: FAKE_TOKEN } },
      { name: "NESTED", type: "json", json: { a: [1, true, null, { b: ["x", awsKey] }] } },
      { name: "SETTINGS", type: "json", json: { region: "eu", retries: 3, debug: false } },
      { name: "KEYED", type: "json", json: { [FAKE_TOKEN]: true } },
      { name: "BARE", type: "json", json: FAKE_TOKEN },
      { name: "NULL", type: "json", json: null },
      // Without a value nothing was inspected: unknown, not clean.
      { name: "EMPTY", type: "json" },
      { name: "UNSET", type: "plain_text" },
      { name: "API_BASE", type: "plain_text", text: PLAIN_URL },
    ];
    const version = { ...versionMy2, resources: { ...versionMy2.resources, bindings } };
    const { output } = await run(workersCollector, {
      ...routes,
      [`${scripts}/my-worker/versions/${V_MY_2}`]: envelope(version),
    });
    const verdict = (kind: string, looks: boolean | null, pattern: string | null = null) => ({
      kind,
      looks_secret: looks,
      secret_pattern: pattern,
    });
    expect(node(output, `worker_version:${V_MY_2}`).props?.plain_text_vars).toEqual([
      { name: "API_BASE", ...verdict("plain_text", false) },
      { name: "BARE", ...verdict("json", true, "cfat_") },
      { name: "CONFIG", ...verdict("json", true, "cfat_") },
      { name: "EMPTY", ...verdict("json", null) },
      { name: "KEYED", ...verdict("json", true, "cfat_") },
      { name: "NESTED", ...verdict("json", true, "aws_access_key") },
      { name: "NULL", ...verdict("json", false) },
      { name: "SETTINGS", ...verdict("json", false) },
      { name: "UNSET", ...verdict("plain_text", null) },
    ]);
    const json = JSON.stringify(output);
    for (const value of [FAKE_TOKEN, awsKey, PLAIN_URL, "region"]) {
      expect(json).not.toContain(value);
    }
  });

  it("emits BINDS edges for every binding with a node, keyed by binding name", async () => {
    const { output } = await run(workersCollector, routes);
    const v1 = `worker_version:${V_MY_1}`;
    expect(edgeIds(output, "BINDS")).toEqual([
      `BINDS:worker_version:${V_MY_2}->kv_namespace:0f2ac74b498b48028cb68387c421e279#CACHE`,
      `BINDS:${v1}->d1_database:445e2955-951a-43f8-a35b-a4d0c8138f63#DB`,
      `BINDS:${v1}->do_namespace:5eb63bbbe01eeed093cb22bb8f5acdc3#COUNTER`,
      // Resolved from script and class through the namespace list.
      `BINDS:${v1}->do_namespace:${doNamespaceLegacy.id}#ROOM`,
      `BINDS:${v1}->hyperdrive_config:a76a99bc342644deb02c38d66082262a#PG`,
      `BINDS:${v1}->kv_namespace:0f2ac74b498b48028cb68387c421e279#CACHE`,
      // Resolved from the queue name through the queue list.
      `BINDS:${v1}->queue:${queueExample.queue_id}#JOBS`,
      `BINDS:${v1}->r2_bucket:example-bucket#FILES`,
      `BINDS:${v1}->secrets_store_secret:023e105f4ecef8ad9ca31a8372d0c353/MY_API_KEY#STRIPE`,
      `BINDS:${v1}->vectorize_index:my_index#INDEX`,
      `BINDS:${v1}->worker_script:api-worker#AUTH`,
      `BINDS:worker_version:${V_MY_3}->r2_bucket:logs#FILES`,
    ]);
    expect(edge(output, `BINDS:${v1}->queue:${queueExample.queue_id}#JOBS`)).toEqual({
      type: "BINDS",
      src: v1,
      dst: `queue:${queueExample.queue_id}`,
      key: "JOBS",
      props: { binding_type: "queue" },
    });
    expect(edge(output, `BINDS:${v1}->worker_script:api-worker#AUTH`).props).toEqual({
      binding_type: "service",
    });
  });

  it("emits entry points with ROUTES_TO", async () => {
    const { output } = await run(workersCollector, routes);
    const preview = (id: string) => `${id.slice(0, 8)}-my-worker.my-subdomain.workers.dev`;
    expect(edgeIds(output, "ROUTES_TO")).toEqual([
      `ROUTES_TO:worker_custom_domain:my-worker.example.com->${SCRIPT}`,
      `ROUTES_TO:worker_preview_url:${preview(V_MY_2)}->worker_version:${V_MY_2}`,
      `ROUTES_TO:worker_preview_url:${preview(V_MY_1)}->worker_version:${V_MY_1}`,
      `ROUTES_TO:worker_preview_url:${preview(V_MY_3)}->worker_version:${V_MY_3}`,
      `ROUTES_TO:worker_route:${routeWithScript.id}->${SCRIPT}`,
      `ROUTES_TO:workers_dev:my-worker.my-subdomain.workers.dev->${SCRIPT}`,
    ]);
    expect(node(output, "workers_dev:my-worker.my-subdomain.workers.dev").props).toEqual({
      script: "my-worker",
    });
    // Disabled for api-worker; legacy-worker has no known hostname.
    expect(nodeIds(output, "workers_dev")).toHaveLength(1);

    expect(node(output, "worker_custom_domain:my-worker.example.com")).toEqual({
      type: "worker_custom_domain",
      nativeId: "my-worker.example.com",
      name: "my-worker.example.com",
      props: {
        zone_id: ZONE_A,
        hostname: "my-worker.example.com",
        service: "my-worker",
        environment: null,
      },
    });

    expectProps(output, "worker_preview_url", ["script", "kind", "version_id", "alias"]);
    expect(node(output, `worker_preview_url:${preview(V_MY_3)}`).props).toEqual({
      script: "my-worker",
      kind: "version",
      version_id: V_MY_3,
      alias: null,
    });
    // The undeployed version behind the preview URL is a node with its script set.
    expect(node(output, `worker_version:${V_MY_3}`).props).toMatchObject({
      script_node_id: SCRIPT,
      number: 14,
    });

    expect(node(output, `worker_route:${routeWithScript.id}`)).toEqual({
      type: "worker_route",
      nativeId: routeWithScript.id,
      name: "example.com/*",
      props: { zone_id: ZONE_A, pattern: "example.com/*", script: "my-worker" },
    });
    // A route without a script is a node but routes nowhere.
    expect(node(output, `worker_route:${routeWithoutScript.id}`).props).toEqual({
      zone_id: ZONE_A,
      pattern: "example.com/static/*",
      script: null,
    });
  });

  it("asks only for the preview window and the versions it needs", async () => {
    const { calls } = await run(workersCollector, routes);
    expect(calls).toContain(`GET ${scripts}/my-worker/versions?page=1&per_page=${PREVIEW_WINDOW}`);
    // Previews are off for api-worker and legacy-worker.
    expect(calls.filter((c) => c.endsWith("/versions?page=1&per_page=5"))).toHaveLength(1);
    expect(calls.filter((c) => c.includes("/subdomain"))).toEqual([
      `GET ${scripts}/legacy-worker/subdomain`,
    ]);
    expect(calls.some((c) => c.includes(V_MY_0))).toBe(false);
    // Each lookup list is read once per chunk.
    expect(calls.filter((c) => c.startsWith(`GET /accounts/${ACCOUNT}/queues`))).toHaveLength(1);
    expect(calls.filter((c) => c.includes("durable_objects"))).toHaveLength(1);
  });

  it("skips scripts and versions deleted between listing and reading", async () => {
    const gone = without(
      routes,
      `${scripts}/my-worker/versions/${V_MY_3}`,
      `${scripts}/api-worker/deployments`,
    );
    const { output } = await run(workersCollector, gone);
    expect(nodeIds(output, "worker_version")).toEqual([
      `worker_version:${V_MY_2}`,
      `worker_version:${V_MY_1}`,
    ]);
    expect(edgeIds(output, "DEPLOYS")).toHaveLength(2);
    expect(node(output, "worker_script:api-worker").props).toMatchObject({
      compatibility_date: null,
    });
  });

  it("is deterministic", async () => {
    await expectDeterministic(workersCollector, routes);
  });

  it("surfaces 403 as NoPermissionError", async () => {
    for (const path of [
      `${base}/workers`,
      `${scripts}/my-worker/deployments`,
      `${scripts}/my-worker/versions`,
      `${scripts}/my-worker/versions/${V_MY_1}`,
      `${scripts}/legacy-worker/subdomain`,
      `/accounts/${ACCOUNT}/queues`,
      `/zones/${ZONE_A}/workers/routes`,
      "/zones",
    ]) {
      await expectNoPermission(workersCollector, { ...routes, [path]: denied() });
    }
  });
});
