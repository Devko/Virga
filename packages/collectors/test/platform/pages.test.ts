import { envelope } from "@virga/cf-api/testing";
import { describe, expect, it } from "vitest";
import { pagesCollector } from "../../src/platform/pages.ts";
import { directUploadProject, gitProject, SECRET_VALUE } from "./fixtures/pages.ts";
import { pagesRoutes } from "./fixtures/routes.ts";
import { queueExample } from "./fixtures/storage.ts";
import { FAKE_TOKEN } from "./fixtures/workers.ts";
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

/** The entry for an environment whose env vars the API did not return. */
const unread = (environment: string) => ({
  name: null,
  environment,
  kind: "unread",
  looks_secret: null,
  secret_pattern: null,
});

/** The entry for a variable that is neither plain text nor secret text. */
const unknownVar = (environment: string, name: string) => ({
  name,
  environment,
  kind: "unknown",
  looks_secret: null,
  secret_pattern: null,
});

/** plain_text_vars of the Git project when the API returns it like this. */
async function varsOf(project: object) {
  const { output } = await run(pagesCollector, {
    ...routes,
    [`${projects}/this-is-my-project-01`]: envelope({ ...gitProject, ...project }),
  });
  expect(JSON.stringify(output)).not.toContain(FAKE_TOKEN);
  return node(output, GIT).props?.plain_text_vars;
}

describe("pages collector", () => {
  it("asks for Pages Metadata Read, not Pages Read, which also reads content", () => {
    expect(pagesCollector.permissions).toEqual(["Pages Metadata Read", "Queues Read"]);
  });

  it("plans project chunks of 20 across pages of the project list", async () => {
    const { chunks } = await run(pagesCollector, routes);
    expect(chunks).toEqual([["docs", "landing", "this-is-my-project-01"]]);
    const many = Array.from({ length: 21 }, (_, i) => ({ ...directUploadProject, name: `p-${i}` }));
    const plan = await pagesCollector.plan(context({ [projects]: envelope(many) }).ctx);
    expect(plan.map((c) => c.length)).toEqual([20, 1]);
  });

  it("emits pages_project nodes with the contract props", async () => {
    const { output } = await run(pagesCollector, routes);
    expectProps(output, "pages_project", [
      "production_branch",
      "subdomain",
      "preview_deployments",
      "plain_text_vars",
    ]);
    const foo = (environment: string) => ({
      name: "foo",
      environment,
      kind: "plain_text",
      looks_secret: false,
      secret_pattern: null,
    });
    expect(node(output, GIT)).toEqual({
      type: "pages_project",
      nativeId: "this-is-my-project-01",
      name: "this-is-my-project-01",
      props: {
        production_branch: "main",
        subdomain: "this-is-my-project-01.pages.dev",
        preview_deployments: "all",
        plain_text_vars: [foo("preview"), foo("production")],
      },
    });
    expect(node(output, "pages_project:docs").props).toEqual({
      production_branch: "main",
      subdomain: "docs-4xz.pages.dev",
      preview_deployments: "none",
      plain_text_vars: [],
    });
    // Direct Upload: no source settings, previews are on by default. Its
    // configs carry no env_vars, so neither environment was inspected.
    expect(node(output, "pages_project:landing").props).toEqual({
      production_branch: "main",
      subdomain: "landing.pages.dev",
      preview_deployments: "all",
      plain_text_vars: [unread("preview"), unread("production")],
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

  it("R2-09: inspects plain-text environment variables and keeps only the verdict", async () => {
    const envVars = {
      API_KEY: { type: "plain_text", value: FAKE_TOKEN },
      foo: { type: "plain_text", value: "hello world" },
      // Without a value nothing was inspected: unknown, not clean.
      EMPTY: { type: "plain_text" },
      TOKEN: { type: "secret_text", value: SECRET_VALUE },
      GONE: null,
    };
    const project = {
      ...gitProject,
      deployment_configs: {
        preview: { env_vars: { foo: envVars.foo } },
        production: { env_vars: envVars },
      },
    };
    const { output } = await run(pagesCollector, {
      ...routes,
      [`${projects}/this-is-my-project-01`]: envelope(project),
    });
    const plain = (environment: string, name: string, looks: boolean | null, pattern = null) => ({
      name,
      environment,
      kind: "plain_text",
      looks_secret: looks,
      secret_pattern: pattern,
    });
    expect(node(output, GIT).props?.plain_text_vars).toEqual([
      plain("preview", "foo", false),
      { ...plain("production", "API_KEY", true), secret_pattern: "cfat_" },
      plain("production", "EMPTY", null),
      plain("production", "foo", false),
    ]);
    const json = JSON.stringify(output);
    for (const value of [FAKE_TOKEN, SECRET_VALUE, "hello world"]) {
      expect(json).not.toContain(value);
    }
  });

  it("R5-07: records an environment whose env vars the API did not return as unread", async () => {
    // The review's scan 2: the project came back without deployment_configs,
    // or with env_vars null, and CF-024 resolved its finding.
    const token = { API_KEY: { type: "plain_text", value: FAKE_TOKEN } };
    const both = [unread("preview"), unread("production")];
    const { deployment_configs: _, ...withoutConfigs } = gitProject;
    const { output } = await run(pagesCollector, {
      ...routes,
      [`${projects}/this-is-my-project-01`]: envelope(withoutConfigs),
    });
    expect(node(output, GIT).props?.plain_text_vars).toEqual(both);
    for (const deployment_configs of [null, "configs", [], {}]) {
      expect(await varsOf({ deployment_configs }), JSON.stringify(deployment_configs)).toEqual(
        both,
      );
    }
    for (const preview of [undefined, null, {}, { env_vars: null }, { env_vars: "x" }]) {
      const vars = await varsOf({
        deployment_configs: { preview, production: { env_vars: token } },
      });
      expect(vars, JSON.stringify(preview)).toEqual([
        unread("preview"),
        {
          name: "API_KEY",
          environment: "production",
          kind: "plain_text",
          looks_secret: true,
          secret_pattern: "cfat_",
        },
      ]);
    }
    // Present and empty is inspected: no variables.
    const empty = { preview: { env_vars: {} }, production: { env_vars: {} } };
    expect(await varsOf({ deployment_configs: empty })).toEqual([]);
  });

  it("R5-07: records a variable of another or no type as uninspected, without its value", async () => {
    // The review's third variant: the variable came back without `type`.
    const env_vars = {
      API_KEY: { value: FAKE_TOKEN },
      OTHER: { type: "json", value: FAKE_TOKEN },
      BARE: FAKE_TOKEN,
      TOKEN: { type: "secret_text", value: FAKE_TOKEN },
      GONE: null,
    };
    const vars = await varsOf({
      deployment_configs: { preview: { env_vars: {} }, production: { env_vars } },
    });
    expect(vars).toEqual([
      unknownVar("production", "API_KEY"),
      unknownVar("production", "BARE"),
      unknownVar("production", "OTHER"),
    ]);
  });

  it("R6-05: records a plain-text variable whose value is not a string as uninspected", async () => {
    // The review's scan 2: API_KEY came back with value null or an object,
    // read as clean, and CF-024 resolved its finding.
    const vars = async (value: unknown) =>
      varsOf({
        deployment_configs: {
          preview: { env_vars: {} },
          production: { env_vars: { API_KEY: { type: "plain_text", value }, GONE: null } },
        },
      });
    const apiKey = (looks: boolean | null, pattern: string | null = null) => [
      {
        name: "API_KEY",
        environment: "production",
        kind: "plain_text",
        looks_secret: looks,
        secret_pattern: pattern,
      },
    ];
    for (const value of [null, { redacted: true }, {}, [], 42, true]) {
      expect(await vars(value), JSON.stringify(value)).toEqual(apiKey(null));
    }
    // An object holding the token is not walked either: it is no plain-text value.
    expect(await vars({ value: FAKE_TOKEN })).toEqual(apiKey(null));
    // A string is inspected, an empty one too; a variable that is itself null
    // (GONE, the delete marker) still yields nothing.
    expect(await vars(FAKE_TOKEN)).toEqual(apiKey(true, "cfat_"));
    expect(await vars("hello world")).toEqual(apiKey(false));
    expect(await vars("")).toEqual(apiKey(false));
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
