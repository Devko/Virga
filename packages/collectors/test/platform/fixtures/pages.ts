// Sources, each built from the documented 200 example:
// https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/list/
// https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/get/
// https://developers.cloudflare.com/api/resources/pages/subresources/projects/subresources/domains/methods/list/
// canonical_deployment and latest_deployment are left out of the projects: the
// collector reads only the project's own fields.

export const SECRET_VALUE = "hunter2-should-never-appear";

const envConfig = (environment: "preview" | "production") => ({
  always_use_latest_compatibility_date: false,
  build_image_major_version: 3,
  compatibility_date: "2025-01-01T00:00:00Z",
  compatibility_flags: ["url_standard"],
  env_vars: {
    foo: { type: "plain_text", value: "hello world" },
    TOKEN: { type: "secret_text", value: SECRET_VALUE },
  },
  fail_open: true,
  usage_model: "standard",
  ai_bindings: { AI_BINDING: { project_id: "some-project-id" } },
  analytics_engine_datasets: { ANALYTICS_ENGINE_BINDING: { dataset: "api_analytics" } },
  browsers: { BROWSER: {} },
  d1_databases: { D1_BINDING: { id: "445e2955-951a-43f8-a35b-a4d0c8138f63" } },
  durable_object_namespaces: { DO_BINDING: { namespace_id: "5eb63bbbe01eeed093cb22bb8f5acdc3" } },
  hyperdrive_bindings: { HYPERDRIVE: { id: "a76a99bc342644deb02c38d66082262a" } },
  kv_namespaces: { KV_BINDING: { namespace_id: "0f2ac74b498b48028cb68387c421e279" } },
  limits: { cpu_ms: 100 },
  mtls_certificates: { MTLS: { certificate_id: "d7cdd17c-916f-4cb7-aabe-585eb382ec4e" } },
  placement: { mode: "smart" },
  queue_producers: { QUEUE_PRODUCER_BINDING: { name: "example-queue" } },
  r2_buckets: {
    R2_BINDING: {
      name: environment === "production" ? "example-bucket" : "logs",
      jurisdiction: "eu",
    },
  },
  services: {
    SERVICE_BINDING: {
      environment: "production",
      service: "example-worker",
      entrypoint: "MyHandler",
    },
  },
  vectorize_bindings: { VECTORIZE: { index_name: "my_index" } },
  wrangler_config_hash: "abc123def456",
});

const source = (setting: string) => ({
  config: {
    deployments_enabled: true,
    owner: "my-org",
    owner_id: "12345678",
    path_excludes: ["string"],
    path_includes: ["string"],
    pr_comments_enabled: true,
    preview_branch_excludes: ["string"],
    preview_branch_includes: ["string"],
    preview_deployment_setting: setting,
    production_branch: "main",
    production_deployments_enabled: true,
    repo_id: "12345678",
    repo_name: "my-repo",
  },
  type: "github",
});

/** Git-connected project, previews for all branches. */
export const gitProject = {
  id: "7b162ea7-7367-4d67-bcde-1160995d5",
  created_on: "2017-01-01T00:00:00Z",
  deployment_configs: { preview: envConfig("preview"), production: envConfig("production") },
  framework: "react",
  framework_version: "18.2.0",
  name: "this-is-my-project-01",
  preview_script_name: "pages-worker--1234567-preview",
  production_branch: "main",
  production_script_name: "pages-worker--1234567-production",
  uses_functions: true,
  build_config: {
    web_analytics_tag: "cee1c73f6e4743d0b5e6bb1a0bcaabcc",
    web_analytics_token: "021e1057c18547eca7b79f2516f06o7x",
    build_caching: true,
    build_command: "npm run build",
    destination_dir: "build",
    root_dir: "/",
  },
  domains: ["customdomain.com", "customdomain.org"],
  source: source("all"),
  subdomain: "this-is-my-project-01.pages.dev",
};

/** Git-connected project with preview deployments switched off. */
export const noPreviewProject = {
  ...gitProject,
  id: "9c3f1e2d-4b5a-4c6d-8e7f-0a1b2c3d4e5f",
  deployment_configs: { preview: {}, production: {} },
  name: "docs",
  domains: [],
  source: source("none"),
  subdomain: "docs-4xz.pages.dev",
};

/** Direct Upload project: no source, no subdomain field. */
export const directUploadProject = {
  id: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
  created_on: "2020-01-01T00:00:00Z",
  deployment_configs: { preview: {}, production: {} },
  name: "landing",
  production_branch: "main",
  uses_functions: false,
};

const domain = (name: string, status: string) => ({
  id: "id",
  certificate_authority: "lets_encrypt",
  created_on: "created_on",
  domain_id: "domain_id",
  name,
  status,
  validation_data: { method: "http", status: "active" },
  verification_data: { status: "active" },
  zone_tag: "zone_tag",
});

export const gitProjectDomains = [
  domain("customdomain.com", "active"),
  domain("CustomDomain.org", "pending"),
];
