import { type CfQuery, NoPermissionError } from "@virga/cf-api";
import { envelope } from "@virga/cf-api/testing";
import { describe, expect, it } from "vitest";
import { storageCollector } from "../../src/platform/storage.ts";
import { storageRoutes } from "./fixtures/routes.ts";
import {
  d1Example,
  hyperdriveExample,
  kvExample,
  managedDisabled,
  storeExample,
} from "./fixtures/storage.ts";
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

const base = `/accounts/${ACCOUNT}`;
const routes = storageRoutes;

/** A page-based route that serves `items` in pages of `perPage`, without total_pages. */
const paged = (items: object[]) => (q: CfQuery) => {
  const page = Number(q.page);
  const perPage = Number(q.per_page);
  return envelope(items.slice((page - 1) * perPage, page * perPage), {
    page,
    per_page: perPage,
    total_count: items.length,
  });
};

describe("storage collector", () => {
  it("plans one chunk per product and R2 buckets in chunks of 25", async () => {
    const { chunks } = await run(storageCollector, routes);
    expect(chunks).toEqual([
      [{ kind: "d1" }],
      [{ kind: "do_namespaces" }],
      [{ kind: "hyperdrive" }],
      [{ kind: "kv" }],
      [{ kind: "queues" }],
      [{ kind: "r2_buckets" }],
      [{ kind: "secrets" }],
      [
        { kind: "r2_domains", bucket: "example-bucket" },
        { kind: "r2_domains", bucket: "logs" },
      ],
    ]);
    const many = Array.from({ length: 60 }, (_, i) => ({ name: `bucket-${i}` }));
    const plan = await storageCollector.plan(
      context({ [`${base}/r2/buckets`]: envelope({ buckets: many }) }).ctx,
    );
    expect(plan.slice(7).map((c) => c.length)).toEqual([25, 25, 10]);
  });

  it("emits store nodes with the contract props", async () => {
    const { output } = await run(storageCollector, routes);
    expect(nodeIds(output)).toEqual([
      "d1_database:445e2955-951a-43f8-a35b-a4d0c8138f63",
      "do_namespace:5eb63bbbe01eeed093cb22bb8f5acdc3",
      "do_namespace:7a1f0d2e9c3b4a5d8e6f7a8b9c0d1e2f",
      "hyperdrive_config:a76a99bc342644deb02c38d66082262a",
      "hyperdrive_config:c1d2e3f4a5b647c8d9e0f1a2b3c4d5e6",
      "kv_namespace:0f2ac74b498b48028cb68387c421e279",
      "queue:b7e0a1c4d2f34e5a9c8b7a6d5e4f3a21",
      "r2_bucket:example-bucket",
      "r2_bucket:logs",
      "r2_public_domain:prefix.example-domain.one.com",
      "r2_public_domain:prefix.example-domain.two.com",
      "r2_public_domain:pub-0113a9e4549cf9b1ff1bf56e04da0cef.r2.dev",
      "secrets_store_secret:023e105f4ecef8ad9ca31a8372d0c353/MY_API_KEY",
    ]);
    expectProps(output, "r2_bucket", [
      "location",
      "jurisdiction",
      "storage_class",
      "creation_date",
    ]);
    expect(node(output, "r2_bucket:example-bucket")).toEqual({
      type: "r2_bucket",
      nativeId: "example-bucket",
      name: "example-bucket",
      props: {
        location: "apac",
        jurisdiction: "default",
        storage_class: "Standard",
        creation_date: "2024-05-01T12:00:00.000Z",
      },
    });
    expect(node(output, "r2_bucket:logs").props).toEqual({
      location: null,
      jurisdiction: null,
      storage_class: null,
      creation_date: null,
    });
    expect(node(output, "d1_database:445e2955-951a-43f8-a35b-a4d0c8138f63")).toMatchObject({
      name: "my-database",
      props: { created_at: "2022-11-15T18:25:44.442097Z" },
    });
    expect(node(output, "kv_namespace:0f2ac74b498b48028cb68387c421e279")).toMatchObject({
      name: "My Own Namespace",
      props: {},
    });
    expect(node(output, "queue:b7e0a1c4d2f34e5a9c8b7a6d5e4f3a21").name).toBe("example-queue");
    expect(node(output, "hyperdrive_config:a76a99bc342644deb02c38d66082262a")).toMatchObject({
      name: "example-hyperdrive",
      props: { origin_host: "database.example.com", origin_scheme: "postgres" },
    });
    expect(node(output, "hyperdrive_config:c1d2e3f4a5b647c8d9e0f1a2b3c4d5e6").props).toEqual({
      origin_host: null,
      origin_scheme: "mysql",
    });
    expect(node(output, "do_namespace:5eb63bbbe01eeed093cb22bb8f5acdc3")).toEqual({
      type: "do_namespace",
      nativeId: "5eb63bbbe01eeed093cb22bb8f5acdc3",
      name: "my-worker:Counter",
      props: { script: "my-worker", class: "Counter", use_sqlite: true },
    });
    expect(node(output, "do_namespace:7a1f0d2e9c3b4a5d8e6f7a8b9c0d1e2f").props).toMatchObject({
      use_sqlite: false,
    });
    expect(
      node(output, "secrets_store_secret:023e105f4ecef8ad9ca31a8372d0c353/MY_API_KEY"),
    ).toEqual({
      type: "secrets_store_secret",
      nativeId: "023e105f4ecef8ad9ca31a8372d0c353/MY_API_KEY",
      name: "MY_API_KEY",
      props: { store_id: "023e105f4ecef8ad9ca31a8372d0c353" },
    });
  });

  it("emits public R2 domains with ROUTES_TO, the r2.dev domain only when enabled", async () => {
    const { output } = await run(storageCollector, routes);
    expectProps(output, "r2_public_domain", ["bucket", "kind", "enabled", "zone_id"]);
    expect(
      node(output, "r2_public_domain:pub-0113a9e4549cf9b1ff1bf56e04da0cef.r2.dev").props,
    ).toEqual({ bucket: "example-bucket", kind: "r2_dev", enabled: true, zone_id: null });
    expect(node(output, "r2_public_domain:prefix.example-domain.one.com").props).toEqual({
      bucket: "example-bucket",
      kind: "custom",
      enabled: false,
      zone_id: "36ca64a6d92827b8a6b90be344bb1bfd",
    });
    expect(nodeIds(output, "r2_public_domain")).not.toContain(
      `r2_public_domain:${managedDisabled.domain}`,
    );
    expect(edgeIds(output)).toEqual([
      "ROUTES_TO:r2_public_domain:prefix.example-domain.one.com->r2_bucket:example-bucket",
      "ROUTES_TO:r2_public_domain:prefix.example-domain.two.com->r2_bucket:example-bucket",
      "ROUTES_TO:r2_public_domain:pub-0113a9e4549cf9b1ff1bf56e04da0cef.r2.dev->r2_bucket:example-bucket",
    ]);
    expect(
      edge(
        output,
        "ROUTES_TO:r2_public_domain:prefix.example-domain.two.com->r2_bucket:example-bucket",
      ).props,
    ).toEqual({});
  });

  it("R4-02: emits the r2.dev domain with enabled null when its flag cannot be read", async () => {
    // The flag was dropped with the entry point, so CF-021 resolved a public
    // bucket's finding instead of leaving it undecided.
    const host = managedDisabled.domain;
    const managed = `${base}/r2/buckets/logs/domains/managed`;
    for (const enabled of [undefined, null, "true", 1, {}]) {
      const { output } = await run(storageCollector, {
        ...routes,
        [managed]: envelope({ ...managedDisabled, enabled }),
      });
      expect(node(output, `r2_public_domain:${host}`).props, String(enabled)).toEqual({
        bucket: "logs",
        kind: "r2_dev",
        enabled: null,
        zone_id: null,
      });
      expect(edgeIds(output)).toContain(`ROUTES_TO:r2_public_domain:${host}->r2_bucket:logs`);
    }
    // Disabled stays out, and a response without a domain names no entry point.
    for (const result of [managedDisabled, { enabled: true }, null]) {
      const { output } = await run(storageCollector, { ...routes, [managed]: envelope(result) });
      expect(nodeIds(output, "r2_public_domain")).not.toContain(`r2_public_domain:${host}`);
      expect(edgeIds(output).filter((e) => e.endsWith("->r2_bucket:logs"))).toEqual([]);
    }
  });

  it("follows pagination of every listing", async () => {
    const buckets = Array.from({ length: 1001 }, (_, i) => ({
      name: `b-${String(i).padStart(4, "0")}`,
    }));
    const d1 = Array.from({ length: 1001 }, (_, i) => ({ ...d1Example, uuid: `d1-${i}` }));
    const kv = Array.from({ length: 1000 }, (_, i) => ({ ...kvExample, id: `kv-${i}` }));
    const hyperdrive = Array.from({ length: 101 }, (_, i) => ({
      ...hyperdriveExample,
      id: `h-${i}`,
    }));
    const { ctx, transport } = context({
      [`${base}/r2/buckets`]: (q: CfQuery) => {
        const start = q.start_after ? buckets.findIndex((b) => b.name === q.start_after) + 1 : 0;
        return envelope({ buckets: buckets.slice(start, start + Number(q.per_page)) });
      },
      [`${base}/d1/database`]: paged(d1),
      [`${base}/storage/kv/namespaces`]: paged(kv),
      [`${base}/hyperdrive/configs`]: paged(hyperdrive),
    });
    const out = await storageCollector.collect(ctx, [
      { kind: "r2_buckets" },
      { kind: "d1" },
      { kind: "kv" },
      { kind: "hyperdrive" },
    ]);
    expect(nodeIds(out, "r2_bucket")).toHaveLength(1001);
    expect(nodeIds(out, "d1_database")).toHaveLength(1001);
    expect(nodeIds(out, "kv_namespace")).toHaveLength(1000);
    expect(nodeIds(out, "hyperdrive_config")).toHaveLength(101);
    expect(transport.calls).toEqual([
      `GET ${base}/r2/buckets?per_page=1000`,
      `GET ${base}/r2/buckets?per_page=1000&start_after=b-0999`,
      `GET ${base}/d1/database?page=1&per_page=1000`,
      `GET ${base}/d1/database?page=2&per_page=1000`,
      `GET ${base}/storage/kv/namespaces?page=1&per_page=1000`,
      `GET ${base}/storage/kv/namespaces?page=2&per_page=1000`,
      `GET ${base}/hyperdrive/configs?page=1&per_page=100`,
      `GET ${base}/hyperdrive/configs?page=2&per_page=100`,
    ]);
  });

  it("skips buckets and stores deleted between listing and reading", async () => {
    const gone = without(
      routes,
      `${base}/r2/buckets/example-bucket/domains/managed`,
      `${base}/r2/buckets/example-bucket/domains/custom`,
      `${base}/secrets_store/stores/${storeExample.id}/secrets`,
    );
    const { output } = await run(storageCollector, gone);
    expect(nodeIds(output, "r2_public_domain")).toEqual([]);
    expect(nodeIds(output, "secrets_store_secret")).toEqual([]);
    expect(nodeIds(output, "r2_bucket")).toHaveLength(2);
  });

  it("is deterministic", async () => {
    await expectDeterministic(storageCollector, routes);
  });

  it("surfaces 403 as NoPermissionError in the product's own chunk", async () => {
    for (const path of [
      "/d1/database",
      "/storage/kv/namespaces",
      "/queues",
      "/hyperdrive/configs",
      "/workers/durable_objects/namespaces",
      "/secrets_store/stores",
      "/r2/buckets/example-bucket/domains/managed",
    ]) {
      await expectNoPermission(storageCollector, { ...routes, [`${base}${path}`]: denied() });
    }
  });

  it("still plans the other products when R2 is denied", async () => {
    const noR2 = { ...routes, [`${base}/r2/buckets`]: denied() };
    const { ctx } = context(noR2);
    const plan = await storageCollector.plan(ctx);
    expect(plan).toHaveLength(7);
    await expect(storageCollector.collect(ctx, [{ kind: "r2_buckets" }])).rejects.toBeInstanceOf(
      NoPermissionError,
    );
    const d1 = await storageCollector.collect(ctx, [{ kind: "d1" }]);
    expect(nodeIds(d1)).toEqual(["d1_database:445e2955-951a-43f8-a35b-a4d0c8138f63"]);
  });
});
