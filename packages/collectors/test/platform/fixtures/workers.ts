// Sources, each built from the documented 200 example and its schema:
// https://developers.cloudflare.com/api/resources/workers/subresources/beta/subresources/workers/methods/list/
// https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/subdomain/methods/get/
// https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/list/
// https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/list/
// https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/get/
// https://developers.cloudflare.com/api/resources/workers/subresources/routes/methods/list/
// Binding shapes: the bindings union on
// https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/script_and_version_settings/methods/get/
// (the version get page links to https://developers.cloudflare.com/workers/configuration/multipart-upload-metadata/#bindings).

import { ZONE_A } from "./zones.ts";

export const V_MY_0 = "0e3a6f52-6b1d-4c8e-9f2a-1b2c3d4e5f60";
export const V_MY_1 = "18f97339-c287-4872-9bdd-e2135c07ec12";
export const V_MY_2 = "023e105f-2a42-4f8b-a1c1-73f6a2a30c0f";
export const V_MY_3 = "9387e76d-6e1a-4fe4-a799-aa6d9a6ab26e";
export const V_API_1 = "182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e";

/** Assembled at runtime so secret scanners do not flag the fixture. */
export const FAKE_TOKEN = `${"cfat"}_${"Q7v2Lm9XkT4pR8sWc1Ny6Hb3Jd5Fg0Za2Ue7Io4P"}a1B2c`;
export const PLAIN_URL = "https://api.example.com/v1";

const observability = {
  enabled: true,
  head_sampling_rate: 1,
  issues: { enabled: true },
  logs: {
    destinations: ["string"],
    enabled: true,
    head_sampling_rate: 1,
    invocation_logs: true,
    persist: true,
  },
};

const references = {
  dispatch_namespace_outbounds: [],
  domains: [],
  durable_objects: [],
  queues: [],
  workers: [],
};

/** Workers API (beta) list entries. */
export const myWorker = {
  id: "e8f70fdbc8b1fb0b8ddb1af166186758",
  created_on: "2019-12-27T18:11:19.117Z",
  logpush: true,
  name: "my-worker",
  observability,
  references: {
    ...references,
    domains: [
      {
        id: "e8f70fdbc8b1fb0b8ddb1af166186758",
        certificate_id: "certificate_id",
        hostname: "My-Worker.example.com",
        zone_id: ZONE_A,
        zone_name: "example.com",
      },
    ],
    queues: [
      {
        queue_consumer_id: "e8f70fdbc8b1fb0b8ddb1af166186758",
        queue_id: "b7e0a1c4d2f34e5a9c8b7a6d5e4f3a21",
        queue_name: "example-queue",
      },
    ],
  },
  subdomain: {
    enabled: true,
    preview_url_suffix: "-my-worker.my-subdomain.workers.dev",
    previews_enabled: true,
    url: "https://my-worker.my-subdomain.workers.dev",
  },
  tags: ["my-team", "my-public-api"],
  tail_consumers: [{ name: "my-tail-consumer" }],
  updated_on: "2024-10-02T08:00:00.000Z",
  deployed_on: "2024-10-02T08:00:00.000Z",
  previews_base_config: { env: { MY_ENV_VAR: { type: "plain_text" } } },
};

export const apiWorker = {
  id: "5b1c6f0e2d3a4b7c8d9e0f1a2b3c4d5e",
  created_on: "2023-05-18T10:00:00.000Z",
  logpush: false,
  name: "api-worker",
  observability,
  references,
  subdomain: {
    enabled: false,
    preview_url_suffix: "-api-worker.my-subdomain.workers.dev",
    previews_enabled: false,
    url: "https://api-worker.my-subdomain.workers.dev",
  },
  tags: [],
  tail_consumers: [],
  updated_on: "2023-05-18T10:00:00.000Z",
  deployed_on: "2023-05-18T10:00:00.000Z",
};

/** An entry without the subdomain object: the collector falls back to the script's subdomain. */
export const legacyWorker = {
  id: "6c2d7e1f3a4b5c8d9e0f1a2b3c4d5e6f",
  created_on: "2018-01-01T00:00:00.000Z",
  logpush: false,
  name: "legacy-worker",
  observability,
  references,
  tags: [],
  tail_consumers: [],
  updated_on: "2018-01-01T00:00:00.000Z",
};

/** `result` of GET .../scripts/legacy-worker/subdomain. */
export const legacySubdomain = { enabled: true, previews_enabled: false };

const deployment = (versions: { percentage: number; version_id: string }[], created: string) => ({
  id: "182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e",
  created_on: created,
  source: "api",
  strategy: "percentage",
  versions,
  annotations: { "workers/message": "Deploy bug fix.", "workers/triggered_by": "deployment" },
  author_email: "dev@example.com",
});

/** The first deployment serves traffic: a 90/10 gradual deployment. The second is history. */
export const myDeployments = {
  deployments: [
    deployment(
      [
        { percentage: 90, version_id: V_MY_1 },
        { percentage: 10, version_id: V_MY_2 },
      ],
      "2024-10-02T08:00:00.000Z",
    ),
    deployment([{ percentage: 100, version_id: V_MY_0 }], "2024-09-01T08:00:00.000Z"),
  ],
};

export const apiDeployments = {
  deployments: [deployment([{ percentage: 100, version_id: V_API_1 }], "2023-05-18T10:00:00Z")],
};

const metadata = (created: string, source: string, hasPreview: boolean) => ({
  author_email: "user@example.com",
  author_id: "408cbcdfd4dda4617efef40b04d168a1",
  created_on: created,
  hasPreview,
  modified_on: created,
  source,
});

/** `result` of GET .../scripts/my-worker/versions; the first item is the latest. */
export const myVersionList = {
  items: [
    { id: V_MY_3, metadata: metadata("2024-10-03T09:00:00.000Z", "wrangler", true), number: 14 },
    { id: V_MY_2, metadata: metadata("2024-10-01T09:00:00.000Z", "wrangler", true), number: 13 },
    { id: V_MY_1, metadata: metadata("2024-09-23T09:00:00.000Z", "wrangler", true), number: 12 },
    { id: V_MY_0, metadata: metadata("2024-09-01T09:00:00.000Z", "api", false), number: 11 },
  ],
};

const script = {
  etag: "13a3240e8fb414561b0366813b0b8f42b3e6cfa0d9e70e99835dae83d0d8a794",
  handlers: ["fetch"],
  last_deployed_from: "wrangler",
  named_handlers: [{ handlers: ["fetch"], name: "MyClass" }],
};

const version = (
  id: string,
  number: number,
  meta: ReturnType<typeof metadata>,
  compatibilityDate: string,
  bindings: object[],
) => ({
  resources: {
    bindings,
    script,
    script_runtime: {
      compatibility_date: compatibilityDate,
      compatibility_flags: ["nodejs_compat"],
      limits: { cpu_ms: 50 },
      migration_tag: "v1",
      usage_model: "standard",
    },
  },
  id,
  metadata: meta,
  number,
});

/** 90 % of traffic. Every kind of binding the target table knows, plus some without a node. */
export const versionMy1 = version(
  V_MY_1,
  12,
  metadata("2024-09-23T09:00:00.000Z", "wrangler", true),
  "2024-09-23",
  [
    { name: "API_BASE", type: "plain_text", text: PLAIN_URL },
    { name: "CF_TOKEN", type: "plain_text", text: FAKE_TOKEN },
    { name: "STRIPE_KEY", type: "secret_text" },
    { name: "CACHE", type: "kv_namespace", namespace_id: "0f2ac74b498b48028cb68387c421e279" },
    { name: "DB", type: "d1", database_id: "445e2955-951a-43f8-a35b-a4d0c8138f63" },
    { name: "FILES", type: "r2_bucket", bucket_name: "example-bucket" },
    {
      name: "COUNTER",
      type: "durable_object_namespace",
      class_name: "Counter",
      namespace_id: "5eb63bbbe01eeed093cb22bb8f5acdc3",
    },
    { name: "ROOM", type: "durable_object_namespace", class_name: "Room", script_name: "chat" },
    { name: "AUTH", type: "service", service: "api-worker", environment: "production" },
    { name: "JOBS", type: "queue", queue_name: "example-queue" },
    { name: "GONE", type: "queue", queue_name: "deleted-queue" },
    { name: "PG", type: "hyperdrive", id: "a76a99bc342644deb02c38d66082262a" },
    {
      name: "STRIPE",
      type: "secrets_store_secret",
      store_id: "023e105f4ecef8ad9ca31a8372d0c353",
      secret_name: "MY_API_KEY",
    },
    { name: "INDEX", type: "vectorize", index_name: "my_index" },
    { name: "AI", type: "ai" },
    { name: "ANALYTICS", type: "analytics_engine", dataset: "api_analytics" },
  ],
);

/** 10 % of traffic. */
export const versionMy2 = version(
  V_MY_2,
  13,
  metadata("2024-10-01T09:00:00.000Z", "wrangler", true),
  "2024-10-01",
  [{ name: "CACHE", type: "kv_namespace", namespace_id: "0f2ac74b498b48028cb68387c421e279" }],
);

/** Uploaded but not deployed: reachable only through its version URL. */
export const versionMy3 = version(
  V_MY_3,
  14,
  metadata("2024-10-03T09:00:00.000Z", "wrangler", true),
  "2024-10-03",
  [{ name: "FILES", type: "r2_bucket", bucket_name: "logs" }],
);

export const versionApi1 = version(
  V_API_1,
  3,
  metadata("2023-05-18T10:00:00.000Z", "dash", false),
  "2023-05-18",
  [],
);

export const routeWithScript = {
  id: "023e105f4ecef8ad9ca31a8372d0c353",
  pattern: "example.com/*",
  script: "my-worker",
};

export const routeWithoutScript = {
  id: "8f5e3c1a2b4d4e6f8a0b1c2d3e4f5a6b",
  pattern: "example.com/static/*",
};
