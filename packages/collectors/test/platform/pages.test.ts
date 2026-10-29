import { envelope } from "@virga/cf-api/testing";
import { describe, expect, it } from "vitest";
import { pagesCollector } from "../../src/platform/pages.ts";
import { directUploadProject, SECRET_VALUE } from "./fixtures/pages.ts";
import { pagesRoutes } from "./fixtures/routes.ts";
import { queueExample } from "./fixtures/storage.ts";
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

const projects = `/accounts/${ACCOUNT}/pages/projects`;
const GIT = "pages_project:this-is-my-project-01";
const routes = pagesRoutes;

describe("pages collector", () => {
  it("plans project chunks of 20 across pages of the project list", async () => {
    const { chunks } = await run(pagesCollector, routes);
    expect(chunks).toEqual([["docs", "landing", "this-is-my-project-01"]]);
    const many = Array.from({ length: 21 }, (_, i) => ({ ...directUploadProject, name: `p-${i}` }));
    const plan = await pagesCollector.plan(context({ [projects]: envelope(many) }).ctx);
    expect(plan.map((c) => c.length)).toEqual([20, 1]);
  });

  it("emits pages_project nodes with the contract props", async () => {
    const { output } = await run(pagesCollector, routes);
    expectProps(output, "pages_project", ["production_branch", "subdomain", "preview_deployments"]);
    expect(node(output, GIT)).toEqual({
      type: "pages_project",
      nativeId: "this-is-my-project-01",
      name: "this-is-my-project-01",
      props: {
        production_branch: "main",
        subdomain: "this-is-my-project-01.pages.dev",
        preview_deployments: "all",
      },
    });
    expect(node(output, "pages_project:docs").props).toEqual({
      production_branch: "main",
      subdomain: "docs-4xz.pages.dev",
      preview_deployments: "none",
    });
    // Direct Upload: no source settings, previews are on by default.
    expect(node(output, "pages_project:landing").props).toEqual({
      production_branch: "main",
      subdomain: "landing.pages.dev",
      preview_deployments: "all",
    });
  });

  it("emits domains and previews with ROUTES_TO and the environment", async () => {
    const { output } = await run(pagesCollector, routes);
    expect(nodeIds(output, "pages_domain")).toEqual([
      "pages_domain:customdomain.com",
      "pages_domain:customdomain.org",
      "pages_domain:docs-4xz.pages.dev",
      "pages_domain:landing.pages.dev",
      "pages_domain:this-is-my-project-01.pages.dev",
    ]);
    expectProps(output, "pages_domain", ["project", "status"]);
    expect(node(output, "pages_domain:customdomain.org").props).toEqual({
      project: "this-is-my-project-01",
      status: "pending",
    });
    expect(node(output, "pages_domain:this-is-my-project-01.pages.dev").props).toEqual({
      project: "this-is-my-project-01",
      status: null,
    });
    // None for docs, whose previews are off.
    expect(nodeIds(output, "pages_preview")).toEqual([
      "pages_preview:*.landing.pages.dev",
      "pages_preview:*.this-is-my-project-01.pages.dev",
    ]);
    expectProps(output, "pages_preview", ["project"]);
    expect(
      edge(output, `ROUTES_TO:pages_preview:*.this-is-my-project-01.pages.dev->${GIT}`).props,
    ).toEqual({ environment: "preview" });
    expect(edge(output, `ROUTES_TO:pages_domain:customdomain.com->${GIT}`).props).toEqual({
      environment: "production",
    });
    expect(edgeIds(output, "ROUTES_TO")).toHaveLength(7);
  });

  it("emits BINDS per environment, keyed by environment and binding name", async () => {
    const { output } = await run(pagesCollector, routes);
    const binds = (env: string) => [
      `BINDS:${GIT}->d1_database:445e2955-951a-43f8-a35b-a4d0c8138f63#${env}:D1_BINDING`,
      `BINDS:${GIT}->do_namespace:5eb63bbbe01eeed093cb22bb8f5acdc3#${env}:DO_BINDING`,
      `BINDS:${GIT}->hyperdrive_config:a76a99bc342644deb02c38d66082262a#${env}:HYPERDRIVE`,
      `BINDS:${GIT}->kv_namespace:0f2ac74b498b48028cb68387c421e279#${env}:KV_BINDING`,
      `BINDS:${GIT}->queue:${queueExample.queue_id}#${env}:QUEUE_PRODUCER_BINDING`,
      `BINDS:${GIT}->r2_bucket:${env === "production" ? "example-bucket" : "logs"}#${env}:R2_BINDING`,
      `BINDS:${GIT}->vectorize_index:my_index#${env}:VECTORIZE`,
      `BINDS:${GIT}->worker_script:example-worker#${env}:SERVICE_BINDING`,
    ];
    expect(edgeIds(output, "BINDS").sort()).toEqual(
      [...binds("preview"), ...binds("production")].sort(),
    );
    expect(
      edge(output, `BINDS:${GIT}->worker_script:example-worker#production:SERVICE_BINDING`).props,
    ).toEqual({ binding_type: "service", environment: "production" });
    expect(edge(output, `BINDS:${GIT}->r2_bucket:logs#preview:R2_BINDING`).props).toEqual({
      binding_type: "r2_bucket",
      environment: "preview",
    });
    const json = JSON.stringify(output);
    expect(json).not.toContain(SECRET_VALUE);
    expect(json).not.toContain("hello world");
  });

  it("skips projects deleted between listing and reading", async () => {
    const gone = without(routes, `${projects}/docs`, `${projects}/landing/domains`);
    const { output } = await run(pagesCollector, gone);
    expect(nodeIds(output, "pages_project")).toEqual([
      "pages_project:landing",
      "pages_project:this-is-my-project-01",
    ]);
    expect(nodeIds(output, "pages_domain")).toContain("pages_domain:landing.pages.dev");
  });

  it("is deterministic", async () => {
    await expectDeterministic(pagesCollector, routes);
  });

  it("surfaces 403 as NoPermissionError", async () => {
    for (const path of [
      projects,
      `${projects}/docs`,
      `${projects}/this-is-my-project-01/domains`,
      `/accounts/${ACCOUNT}/queues`,
    ]) {
      await expectNoPermission(pagesCollector, { ...routes, [path]: denied() });
    }
  });
});
