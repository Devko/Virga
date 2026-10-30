// A fake Cloudflare account for the end-to-end scan test: one seeded
// misconfiguration per phase 1 rule, each with a clean counterpart, served
// as API responses in the shapes the collectors parse. The expected coverage,
// exposure and findings sit next to the cases they belong to.
//
// Response shapes follow the documented 200 examples, mostly by spreading the
// collectors' fixtures (packages/collectors/test/*/fixtures, which cite their
// pages). Shapes written here follow these pages:
// - Worker versions, deployments and binding objects (D1 `database_id`, KV
//   `namespace_id`, plain_text `text`):
//   https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/get/
//   https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/list/
//   https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/script_and_version_settings/methods/get/
// - Access destinations (`public` with `uri`, `worker` with `worker_id`) and
//   app policies with `precedence`:
//   https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/
//   https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/methods/list/
// - Tunnel ingress:
//   https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/subresources/configurations/methods/get/
// - Pages env vars (`deployment_configs.<env>.env_vars`, `{ type, value }`):
//   https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/get/

import type { CfQuery } from "@virga/cf-api";
import { envelope, type FixtureRoute, type FixtureTransportOptions } from "@virga/cf-api/testing";
import type { RuleSeverity } from "@virga/rules";
import {
  appsRoute,
  FAKE_CLIENT_ID,
  FAKE_SCIM_PASSWORD,
  FAKE_SECRET,
  idpOkta,
  idpOtp,
  listInfo,
  tokenCi as serviceTokenExample,
} from "../../../../packages/collectors/test/identity/fixtures/access.ts";
import {
  exampleIssue,
  insightsRoute,
} from "../../../../packages/collectors/test/identity/fixtures/insights.ts";
import {
  memberExample,
  membersRoute,
} from "../../../../packages/collectors/test/identity/fixtures/members.ts";
import { tokensRoute } from "../../../../packages/collectors/test/identity/fixtures/tokens.ts";
import { trafficGraphql } from "../../../../packages/collectors/test/identity/fixtures/traffic.ts";
import {
  blog as tunnelExample,
  tunnelsRoute,
} from "../../../../packages/collectors/test/identity/fixtures/tunnels.ts";
import { recordA, recordTxt } from "../../../../packages/collectors/test/platform/fixtures/dns.ts";
import { gitProject } from "../../../../packages/collectors/test/platform/fixtures/pages.ts";
import {
  bucketExample,
  d1Example,
  kvExample,
} from "../../../../packages/collectors/test/platform/fixtures/storage.ts";
import {
  FAKE_TOKEN,
  myWorker,
  PLAIN_URL,
} from "../../../../packages/collectors/test/platform/fixtures/workers.ts";
import { zoneA, zonesRoute } from "../../../../packages/collectors/test/platform/fixtures/zones.ts";

export type Routes = Record<string, FixtureRoute>;
type GraphqlHandler = NonNullable<FixtureTransportOptions["graphql"]>;

/** Scan start of the first scan, 2026-10-29T06:17:00Z. */
export const NOW = Date.UTC(2026, 9, 29, 6, 17);

const ZONE_COM = "3782469a55594b87c47f3192bc11ec4f";
const ZONE_ORG = "6fddf0c2469238e11e6f76eb720fed56";
/** The account's workers.dev subdomain. */
const SUBDOMAIN = "acme";

// D1 databases and KV namespaces.
const D1_ORDERS = "f92a9afe-a664-43b0-bb0f-5662e7879077";
const D1_STAFF = "32db1aa4-1bb2-4edc-b853-7331a260ccba";
const D1_BILLING = "74cfbd6b-87a0-405c-a6be-21d3358b6dd6";
const D1_BLOG = "4612baad-4508-459f-bdbb-4825a5aaa73a";
const D1_BLOG_PREVIEW = "1283ab41-edab-4118-9690-52fb37447fca";
const KV_REPORTS = "e8e7f7f382220450be2107966c646409";
const KV_STATUS = "2e2b1065142186964e025aca4dd01f6e";
const KV_API = "aa996534dea021b1578c5533d660fd21";
const KV_REPORTER = "d66ceb900b848e56c71c0783d78c41ef";

// R2 buckets; the managed domain is pub-<bucket ID>.r2.dev.
const R2_PUBLIC_ID = "7f683811a36009d8c5d33e06c36beb28";
const R2_PRIVATE_ID = "396611bbeb265893b78dc2c361e936d4";
export const R2_DEV_HOST = `pub-${R2_PUBLIC_ID}.r2.dev`;

// DNS records in example.com.
const REC_APEX = "83152896406f9fa548b6ca644f8196d0";
const REC_WWW = "25894e4131c2f1b34caf0dab9551e776";
const REC_ORIGIN = "83ad0ee7c31586d2f7aad002f819577f";
const REC_MAIL = "b871d8b90fbc99c1f8c2cf953dfa7768";
const REC_TXT = "1ea0cc9d710d8747a9595618aec6635f";

const ROUTE_SHOP = "8b520eacd9f321f3fb44d189be271187";

const TOKEN_DEPLOY = "dfb6780d5fa6fc15baf48f3412b8ee17";
const TOKEN_CI = "4993d5cf2e097945ece62ecddf6f291f";
const TOKEN_READ = "daa53e942980a368d855dabb8867bd65";

const APP_PORTAL = "90b8f6fc-cde8-4349-a983-ef10524d24dd";
const APP_INTRANET = "69d475df-e0bd-4322-a457-e858b9728e6b";
const APP_TUNNEL = "b77acb2b-ec8b-477f-8149-c63c43f78d1b";
const APP_REPORTS = "1fb1dc21-4e36-4496-89fb-f49aefca2725";
const APP_BILLING = "c4e8c2f5-30af-4391-a3e6-fe7ce5482ae7";
const APP_STATUS = "94ccd251-b1f4-4bdd-8071-6cb2f16c95f5";
const APP_API = "ee819a64-4567-4250-a6fe-2d35d4ffe1ce";
const APP_API_HEALTH = "c09732be-87aa-4ea0-bbde-21e117e5cd87";
const APP_KB = "5d3b8e1f-6c2a-4f9d-8b7e-0a4c2e6f8d1b";

const POLICY_STAFF = "5233833d-2d68-4b2c-8981-f1ee893bd074";
const POLICY_EMPLOYEES = "23995aac-33ab-4c01-a865-8830dd8c3407";
const POLICY_EVERYONE = "adf4e4c5-be7f-4519-be32-ec89f2f71041";
const POLICY_BYPASS = "56119f96-992c-402c-950b-8a6c76d6d9cf";
const POLICY_HEALTH = "faa1737b-b574-4278-9075-43af1fa13beb";
const GROUP_STAFF = "a30a625c-bfd9-453e-aed1-f299024f1314";

const TUNNEL_EDGE = "958098ee-467d-4161-a056-47df6b3dd0d6";
const TUNNEL_TEAM = "4c7d2b1e-8a3f-4e6d-9b5c-2f1a0e9d8c7b";
const TUNNEL_DEBUG = "a1e5c9d3-7b2f-4a8e-b6d0-3c9f1e7a5b2d";
const TUNNEL_OPS = "e8b2f6a4-1d9c-4e3b-a7f5-9d2c6b0e4a1f";

/** What tests may change between scans. */
export interface AccountState {
  /** CF-021: the managed r2.dev domain of `public-assets` is enabled. */
  publicAssetsR2Dev: boolean;
}

export const initialState = (): AccountState => ({ publicAssetsR2Dev: true });

// Workers ---------------------------------------------------------------------

interface WorkerSpec {
  name: string;
  /** Worker ID in the Workers API (beta). */
  id: string;
  versionId: string;
  createdOn: string;
  workersDev: boolean;
  customDomains: string[];
  bindings: object[];
  /** Requests in the 30-day traffic window; 0 means no GraphQL row. */
  requests: number;
}

const d1 = (name: string, id: string) => ({ name, type: "d1", database_id: id });
const kv = (name: string, id: string) => ({ name, type: "kv_namespace", namespace_id: id });
const plainText = (name: string, text: string) => ({ name, type: "plain_text", text });

const WORKERS: WorkerSpec[] = [
  // CF-002 seeded: Access in front of the Custom Domain, workers.dev left on.
  {
    name: "portal",
    id: "c4b4f55754d8877a63f243f4bc6f02a1",
    versionId: "46e68d08-20da-4216-9547-dbb327fa72d6",
    createdOn: "2025-06-01T10:00:00.000Z",
    workersDev: true,
    customDomains: ["portal.example.com"],
    bindings: [plainText("GREETING", "hello")],
    requests: 300,
  },
  // CF-002 clean: Worker-level Access covers the Custom Domain and workers.dev alike.
  {
    name: "intranet",
    id: "b8d968c4f655a7d099f400c4cfb067f4",
    versionId: "0249d6c8-84be-4cd0-ad0b-2d65d0758e70",
    createdOn: "2025-06-01T10:00:00.000Z",
    workersDev: true,
    customDomains: ["intranet.example.com"],
    bindings: [d1("DB", D1_STAFF)],
    requests: 120,
  },
  // The live workload that puts orders-db in production use (CF-009), and
  // CF-024 clean: a URL as plain text and the key as a secret binding.
  {
    name: "shop",
    id: "037802f00de5d66a756899f1098e231c",
    versionId: "8101deb9-e55b-400b-a9b7-0464efe76875",
    createdOn: "2024-03-01T10:00:00.000Z",
    workersDev: false,
    customDomains: [],
    bindings: [
      plainText("API_BASE", PLAIN_URL),
      { name: "STRIPE_KEY", type: "secret_text" },
      d1("DB", D1_ORDERS),
    ],
    requests: 1200,
  },
  // CF-009 seeded: no traffic for 30 days, created long before, bound to orders-db.
  {
    name: "archiver",
    id: "beed0436b08c90e6cead28106989b287",
    versionId: "847ea618-5c4f-4c1b-ab05-e7198535b0c8",
    createdOn: "2025-01-15T00:00:00.000Z",
    workersDev: false,
    customDomains: [],
    bindings: [d1("ORDERS", D1_ORDERS)],
    requests: 0,
  },
  // CF-009 clean: just as idle, but its namespace serves no other workload.
  {
    name: "reporter",
    id: "0bf3dec2e73a1c942bf95bb7de95507a",
    versionId: "d450a2ff-c796-430b-b4c4-8427430ffc51",
    createdOn: "2025-01-15T00:00:00.000Z",
    workersDev: false,
    customDomains: [],
    bindings: [kv("CACHE", KV_REPORTER)],
    requests: 0,
  },
  // CF-010 seeded: behind an app whose Allow policy includes Everyone.
  {
    name: "reports",
    id: "09379f22cbcb20bb4e555e0be87c5e56",
    versionId: "3a31a9d2-4f02-48c5-96ea-3852f964b033",
    createdOn: "2025-06-01T10:00:00.000Z",
    workersDev: false,
    customDomains: ["reports.example.com"],
    bindings: [kv("REPORTS", KV_REPORTS)],
    requests: 40,
  },
  // CF-010 clean: the app's Allow policy is limited to one email domain.
  {
    name: "billing",
    id: "704afceadbc7b69c60d9bc0927ff75b0",
    versionId: "32940e32-9b63-4698-9f41-6a7834a8e1a5",
    createdOn: "2025-06-01T10:00:00.000Z",
    workersDev: false,
    customDomains: ["billing.example.com"],
    bindings: [d1("DB", D1_BILLING)],
    requests: 25,
  },
  // CF-011 seeded: behind an app with a Bypass policy for the whole host.
  {
    name: "status",
    id: "6f25d6bfc7576f8f18381316a64b84c2",
    versionId: "40d7a624-de79-4a7c-8377-6ae9de4ef18d",
    createdOn: "2025-06-01T10:00:00.000Z",
    workersDev: false,
    customDomains: ["status.example.com"],
    bindings: [kv("STATE", KV_STATUS)],
    requests: 900,
  },
  // CF-011 clean: the Bypass policy sits on a path app (/health); the host needs identity.
  {
    name: "api",
    id: "47695a58c897dae2b14d0551dad652ba",
    versionId: "94dd6a64-5ef0-4664-b622-aec7f4355bb4",
    createdOn: "2025-06-01T10:00:00.000Z",
    workersDev: false,
    customDomains: ["api.example.com"],
    bindings: [kv("SESSIONS", KV_API)],
    requests: 500,
  },
  // CF-024 seeded: an API token in a plain-text variable.
  {
    name: "mailer",
    id: "b185d0276be3ce5e3e83673aba80ac6c",
    versionId: "947a829a-3dce-494d-ae7e-9e66115c1838",
    createdOn: "2025-06-01T10:00:00.000Z",
    workersDev: false,
    customDomains: [],
    bindings: [plainText("MAIL_FROM", "noreply@example.com"), plainText("CF_TOKEN", FAKE_TOKEN)],
    requests: 60,
  },
];

const workerByName = (name: string): WorkerSpec => {
  const worker = WORKERS.find((w) => w.name === name);
  if (!worker) throw new Error(`no worker ${name}`);
  return worker;
};

/** A Workers API (beta) list entry. */
const workerEntry = (w: WorkerSpec) => ({
  ...myWorker,
  id: w.id,
  name: w.name,
  created_on: w.createdOn,
  updated_on: "2026-10-01T09:00:00.000Z",
  deployed_on: "2026-10-01T09:00:00.000Z",
  tags: [],
  references: {
    dispatch_namespace_outbounds: [],
    domains: w.customDomains.map((hostname) => ({
      id: w.id,
      certificate_id: "certificate_id",
      hostname,
      zone_id: ZONE_COM,
      zone_name: "example.com",
    })),
    durable_objects: [],
    queues: [],
    workers: [],
  },
  subdomain: {
    enabled: w.workersDev,
    preview_url_suffix: `-${w.name}.${SUBDOMAIN}.workers.dev`,
    previews_enabled: false,
    url: `https://${w.name}.${SUBDOMAIN}.workers.dev`,
  },
});

const versionMetadata = {
  author_email: "dev@example.com",
  author_id: "408cbcdfd4dda4617efef40b04d168a1",
  created_on: "2026-10-01T09:00:00.000Z",
  hasPreview: false,
  modified_on: "2026-10-01T09:00:00.000Z",
  source: "wrangler",
};

const version = (w: WorkerSpec) => ({
  id: w.versionId,
  metadata: versionMetadata,
  number: 7,
  resources: {
    bindings: w.bindings,
    script: {
      etag: "13a3240e8fb414561b0366813b0b8f42b3e6cfa0d9e70e99835dae83d0d8a794",
      handlers: ["fetch"],
      last_deployed_from: "wrangler",
    },
    script_runtime: {
      compatibility_date: "2026-10-01",
      compatibility_flags: ["nodejs_compat"],
      limits: { cpu_ms: 50 },
      usage_model: "standard",
    },
  },
});

/** One deployment that sends all traffic to the Worker's version. */
const deployments = (w: WorkerSpec) => ({
  deployments: [
    {
      id: "14a49583-5abf-478a-8c14-fb6356edff69",
      created_on: "2026-10-01T09:00:00.000Z",
      source: "wrangler",
      strategy: "percentage",
      versions: [{ percentage: 100, version_id: w.versionId }],
      annotations: { "workers/triggered_by": "deployment" },
      author_email: "dev@example.com",
    },
  ],
});

// GraphQL Analytics rows, as the traffic fixtures shape them.
const trafficRows = WORKERS.filter((w) => w.requests > 0).map((w) => ({
  dimensions: { scriptName: w.name },
  sum: { errors: 0, requests: w.requests },
}));

// Storage ---------------------------------------------------------------------

const BUCKETS = [
  { ...bucketExample, name: "public-assets", creation_date: "2025-02-01T12:00:00.000Z" },
  { ...bucketExample, name: "private-data", creation_date: "2025-02-01T12:00:00.000Z" },
];

const D1_DATABASES: [string, string][] = [
  [D1_ORDERS, "orders-db"],
  [D1_STAFF, "staff-db"],
  [D1_BILLING, "billing-db"],
  [D1_BLOG, "blog-db"],
  [D1_BLOG_PREVIEW, "blog-preview-db"],
];

const KV_NAMESPACES: [string, string][] = [
  [KV_REPORTS, "reports"],
  [KV_STATUS, "status"],
  [KV_API, "api-sessions"],
  [KV_REPORTER, "reporter-cache"],
];

// Pages -----------------------------------------------------------------------

/** Test values for Pages env vars, split like FAKE_TOKEN so secret scanners skip the source. */
const PAGES_TOKEN = `${"cfat"}_${"Hk3Zr8Wq1Lm6Tp9Xc2Vb5Nd7Fs0Gj4Ya8Re1Ui6O"}x9Y8z`;
const PAGES_KEY = `${"cfk"}_${"Wd4Rt7Yp2Ks9Lx3Mv6Bn1Qc8Fh5Gz0Ja7Ue2Io4E"}m3N6b`;

const plainVar = (value: string) => ({ type: "plain_text", value });
const secretVar = (value: string) => ({ type: "secret_text", value });

const pagesEnv = (
  d1Databases: Record<string, { id: string }>,
  envVars: Record<string, { type: string; value: string }> = {},
) => ({
  always_use_latest_compatibility_date: false,
  build_image_major_version: 3,
  compatibility_date: "2026-10-01",
  compatibility_flags: [],
  env_vars: envVars,
  fail_open: true,
  usage_model: "standard",
  d1_databases: d1Databases,
});

type PagesEnv = ReturnType<typeof pagesEnv>;

const pagesProject = (name: string, id: string, preview: PagesEnv, production: PagesEnv) => ({
  ...gitProject,
  id,
  name,
  domains: [],
  subdomain: `${name}.pages.dev`,
  deployment_configs: { preview, production },
});

const withDb = (id: string) => pagesEnv({ DB: { id } });

// The key as a secret env var. It carries a value here, which the collector
// never reads, so the value must not show up anywhere (SECRET_VALUES).
const landingEnv = pagesEnv({}, { API_BASE: plainVar(PLAIN_URL), API_KEY: secretVar(PAGES_KEY) });

const PAGES_PROJECTS = [
  // CF-022 seeded: previews for every branch, and they bind the production database.
  pagesProject(
    "storefront",
    "0c9e5a7b-1d3f-4b6a-8c2e-4f6a8b0c2d4e",
    withDb(D1_ORDERS),
    withDb(D1_ORDERS),
  ),
  // CF-022 clean: previews for every branch, with a database of their own.
  pagesProject(
    "blog",
    "5e7a9c1b-3d5f-4a7b-9c1d-3e5f7a9b1c3d",
    withDb(D1_BLOG_PREVIEW),
    withDb(D1_BLOG),
  ),
  // CF-024 seeded: an API token in a plain-text env var of the production environment.
  pagesProject(
    "handbook",
    "0d83c20a-0b90-4a4e-9c48-f284882c3071",
    pagesEnv({}),
    pagesEnv({}, { API_BASE: plainVar(PLAIN_URL), CF_API_TOKEN: plainVar(PAGES_TOKEN) }),
  ),
  // CF-024 clean: a URL as plain text and the key as a secret env var, in both environments.
  pagesProject("landing", "25507196-ff59-435e-9f6e-87d5ed25721a", landingEnv, landingEnv),
];

// Access ----------------------------------------------------------------------

const timestamps = { created_at: "2025-06-01T10:00:00Z", updated_at: "2025-06-01T10:00:00Z" };

const policy = (
  id: string,
  name: string,
  decision: string,
  include: object[],
  reusable: boolean,
) => ({
  ...timestamps,
  id,
  name,
  decision,
  include,
  require: [],
  exclude: [],
  approval_groups: [],
  approval_required: false,
  isolation_required: false,
  purpose_justification_required: false,
  reusable,
  session_duration: "24h",
});

const staff = policy(POLICY_STAFF, "Staff", "allow", [{ group: { id: GROUP_STAFF } }], true);
const employees = policy(
  POLICY_EMPLOYEES,
  "Employees",
  "allow",
  [{ email_domain: { domain: "example.com" } }],
  true,
);
// CF-010 seeded.
const everyone = policy(POLICY_EVERYONE, "Anyone", "allow", [{ everyone: {} }], false);
// CF-011 seeded.
const bypass = policy(POLICY_BYPASS, "Public status page", "bypass", [{ everyone: {} }], false);
// CF-011 clean: a Bypass policy, but only on the /health path app.
const health = policy(POLICY_HEALTH, "Health checks", "bypass", [{ everyone: {} }], false);

type Destination = { type: "public"; uri: string } | { type: "worker"; worker_id: string };

const app = (id: string, name: string, destinations: Destination[]) => {
  const uri = destinations.flatMap((d) => (d.type === "public" ? [d.uri] : []))[0];
  return {
    ...timestamps,
    aud: "737646a56ab1df6ec9bddc7e5ca84eaf3b0768850f3ffb5d74f1534911fe3893",
    id,
    name,
    type: "self_hosted",
    ...(uri ? { domain: uri, self_hosted_domains: [uri] } : {}),
    destinations,
    allowed_idps: [],
    app_launcher_visible: true,
    session_duration: "24h",
  };
};

const publicUri = (uri: string): Destination => ({ type: "public", uri });

const APPS: { app: ReturnType<typeof app>; policies: ReturnType<typeof policy>[] }[] = [
  { app: app(APP_PORTAL, "Portal", [publicUri("portal.example.com")]), policies: [staff] },
  {
    app: app(APP_INTRANET, "Intranet Worker", [
      { type: "worker", worker_id: workerByName("intranet").id },
    ]),
    policies: [staff],
  },
  { app: app(APP_TUNNEL, "Internal app", [publicUri("app.example.com")]), policies: [employees] },
  { app: app(APP_KB, "Knowledge base", [publicUri("kb.example.com")]), policies: [employees] },
  { app: app(APP_REPORTS, "Reports", [publicUri("reports.example.com")]), policies: [everyone] },
  { app: app(APP_BILLING, "Billing", [publicUri("billing.example.com")]), policies: [employees] },
  { app: app(APP_STATUS, "Status page", [publicUri("status.example.com")]), policies: [bypass] },
  { app: app(APP_API, "API", [publicUri("api.example.com")]), policies: [employees] },
  {
    app: app(APP_API_HEALTH, "API health checks", [publicUri("api.example.com/health")]),
    policies: [health],
  },
];

const groupStaff = {
  ...timestamps,
  id: GROUP_STAFF,
  name: "Staff",
  include: [{ email_domain: { domain: "example.com" } }],
  require: [],
  exclude: [],
  is_default: [],
};

// Tunnels ---------------------------------------------------------------------

/** cloudflared checks the Access token of every request this block applies to. */
const originAccess = {
  access: {
    required: true,
    teamName: "acme",
    audTag: ["737646a56ab1df6ec9bddc7e5ca84eaf3b0768850f3ffb5d74f1534911fe3893"],
  },
};

/** Remotely managed configurations by tunnel. */
const TUNNEL_CONFIGS: Record<string, { name: string; config: object }> = {
  [TUNNEL_EDGE]: {
    name: "edge",
    config: {
      ingress: [
        // CF-004 seeded: SSH to the origin, no Access app on the hostname.
        { hostname: "ssh.example.com", service: "ssh://localhost:22" },
        // CF-004 clean: behind the "Internal app" Access app.
        { hostname: "app.example.com", service: "http://localhost:8080" },
        { service: "http_status:404" },
      ],
      "warp-routing": { enabled: false },
    },
  },
  // R3-01: an access block at the top of the configuration. cloudflared
  // builds the token check from a rule's own block only.
  [TUNNEL_TEAM]: {
    name: "team",
    config: {
      originRequest: originAccess,
      ingress: [
        // CF-004 seeded: no Access app, and no check of its own.
        { hostname: "git.example.com", service: "ssh://localhost:2222" },
        // CF-004 clean: the rule's own block requires the token.
        {
          hostname: "wiki.example.com",
          service: "http://localhost:8090",
          originRequest: originAccess,
        },
        { service: "http_status:404" },
      ],
    },
  },
  // R3-02, case A: a rule without a hostname matches every hostname, so
  // /debug of each hostname below reaches localhost:6060.
  [TUNNEL_DEBUG]: {
    name: "debug",
    config: {
      ingress: [
        // CF-004 seeded on dash.example.com; clean on kb.example.com, where an Access app decides.
        { path: "^/debug", service: "http://localhost:6060" },
        // CF-004 clean: the token check covers the rest of the hostname.
        {
          hostname: "dash.example.com",
          service: "http://localhost:3000",
          originRequest: originAccess,
        },
        { hostname: "kb.example.com", service: "http://localhost:4000" },
        { service: "http_status:404" },
      ],
    },
  },
  // R3-02, case B: every path of ops.example.com but /admin falls through
  // to the catch-all origin.
  [TUNNEL_OPS]: {
    name: "ops",
    config: {
      ingress: [
        // CF-004 clean: the token check covers /admin.
        {
          hostname: "ops.example.com",
          path: "^/admin",
          service: "http://localhost:9000",
          originRequest: originAccess,
        },
        // CF-004 clean: takes every path, so the catch-all never applies to it.
        {
          hostname: "vault.example.com",
          service: "http://localhost:8200",
          originRequest: originAccess,
        },
        // CF-004 seeded on ops.example.com.
        { service: "http://localhost:8080" },
      ],
    },
  },
};

const TUNNELS = Object.entries(TUNNEL_CONFIGS).map(([id, { name }]) => ({
  ...tunnelExample,
  id,
  name,
}));

const tunnelConfig = (accountId: string, tunnelId: string, config: object) => ({
  account_id: accountId,
  config,
  created_at: "2025-06-01T10:00:00Z",
  source: "cloudflare",
  tunnel_id: tunnelId,
  version: 4,
});

// Tokens ----------------------------------------------------------------------

const permissionGroup = (id: string, name: string) => ({
  id,
  meta: { label: name, scopes: "com.cloudflare.api.account" },
  name,
});

interface TokenSpec {
  id: string;
  policyId: string;
  name: string;
  group: ReturnType<typeof permissionGroup>;
  expires_on?: string;
  last_used_on?: string;
}

const accountToken = (accountId: string, { id, policyId, name, group, ...dates }: TokenSpec) => ({
  id,
  issued_on: "2026-03-01T00:00:00Z",
  modified_on: "2026-03-01T00:00:00Z",
  ...dates,
  name,
  policies: [
    {
      id: policyId,
      effect: "allow",
      permission_groups: [group],
      resources: { [`com.cloudflare.api.account.${accountId}`]: "*" },
    },
  ],
  status: "active",
});

const scriptsWrite = permissionGroup("e086da7e2179491d91ee5f35b3ca210a", "Workers Scripts Write");
const scriptsRead = permissionGroup("1a71c399035b4950a1bd1466bbe4f420", "Workers Scripts Read");

const TOKENS: TokenSpec[] = [
  // CF-003 seeded: write access, no expiry, no IP condition, used two days ago.
  {
    id: TOKEN_DEPLOY,
    policyId: "3cdd61b0a6c94b4e9d1f2a7e8b5c4d01",
    name: "deploy",
    group: scriptsWrite,
    last_used_on: "2026-10-27T08:00:00Z",
  },
  // CF-003 clean: the same grant, but it expires in 17 days.
  {
    id: TOKEN_CI,
    policyId: "4dee72c1b7da4c5fae2a3b8f9c6d5e12",
    name: "ci",
    group: scriptsWrite,
    expires_on: "2026-11-15T00:00:00Z",
    last_used_on: "2026-10-28T08:00:00Z",
  },
  // CF-003 clean: no expiry, but read-only.
  {
    id: TOKEN_READ,
    policyId: "5eff83d2c8eb4d6abf3b4c9a0d7e6f23",
    name: "read",
    group: scriptsRead,
  },
];

// DNS -------------------------------------------------------------------------

const aRecord = (id: string, name: string, content: string, proxied: boolean) => ({
  ...recordA,
  id,
  name,
  content,
  proxied,
  comment: null,
  tags: [],
  meta: {},
});

const DNS: Record<string, object[]> = {
  [ZONE_COM]: [
    aRecord(REC_APEX, "example.com", "198.51.100.4", true),
    // CF-007 seeded: the proxied www and the unproxied origin share an address.
    aRecord(REC_WWW, "www.example.com", "203.0.113.10", true),
    aRecord(REC_ORIGIN, "origin.example.com", "203.0.113.10", false),
    // CF-007 clean: unproxied, but no proxied record uses its address.
    aRecord(REC_MAIL, "mail.example.com", "198.51.100.25", false),
  ],
  [ZONE_ORG]: [{ ...recordTxt, id: REC_TXT }],
};

// Routes ----------------------------------------------------------------------

const pageInfo = (count: number, perPage: number) => ({
  count,
  page: 1,
  per_page: perPage,
  total_count: count,
  total_pages: 1,
});

const list = <T>(items: T[], perPage = 50) => envelope(items, pageInfo(items.length, perPage));

/** The account's API, as routes for fixtureTransport, plus the GraphQL handler for traffic. */
export function fakeAccount(
  accountId: string,
  state: AccountState,
): { routes: Routes; graphql: GraphqlHandler } {
  const base = `/accounts/${accountId}`;
  const scripts = `${base}/workers/scripts`;
  const zone = (id: string, name: string) => ({
    ...zoneA,
    id,
    name,
    account: { id: accountId, name: "Example Account Name" },
    paused: false,
  });

  const routes: Routes = {
    "/zones": zonesRoute([zone(ZONE_COM, "example.com"), zone(ZONE_ORG, "example.org")]),
    [`/zones/${ZONE_COM}/workers/routes`]: envelope([
      { id: ROUTE_SHOP, pattern: "shop.example.com/*", script: "shop" },
    ]),
    [`/zones/${ZONE_ORG}/workers/routes`]: envelope([]),
    [`${base}/workers/workers`]: (q: CfQuery) =>
      envelope(WORKERS.map(workerEntry), {
        count: WORKERS.length,
        page: Number(q.page ?? 1),
        per_page: Number(q.per_page ?? 100),
        total_pages: 1,
      }),

    [`${base}/r2/buckets`]: envelope({ buckets: BUCKETS }, { per_page: 1000 }),
    [`${base}/r2/buckets/public-assets/domains/managed`]: envelope({
      bucketId: R2_PUBLIC_ID,
      domain: R2_DEV_HOST,
      enabled: state.publicAssetsR2Dev,
    }),
    [`${base}/r2/buckets/public-assets/domains/custom`]: envelope({ domains: [] }),
    [`${base}/r2/buckets/private-data/domains/managed`]: envelope({
      bucketId: R2_PRIVATE_ID,
      domain: `pub-${R2_PRIVATE_ID}.r2.dev`,
      enabled: false,
    }),
    [`${base}/r2/buckets/private-data/domains/custom`]: envelope({ domains: [] }),
    [`${base}/d1/database`]: envelope(
      D1_DATABASES.map(([uuid, name]) => ({ ...d1Example, uuid, name })),
      { count: D1_DATABASES.length, page: 1, per_page: 1000, total_count: D1_DATABASES.length },
    ),
    [`${base}/storage/kv/namespaces`]: envelope(
      KV_NAMESPACES.map(([id, title]) => ({ ...kvExample, id, title })),
      { count: KV_NAMESPACES.length, page: 1, per_page: 1000, total_count: KV_NAMESPACES.length },
    ),
    [`${base}/queues`]: list([]),
    [`${base}/hyperdrive/configs`]: envelope([], {
      count: 0,
      page: 1,
      per_page: 100,
      total_count: 0,
    }),
    [`${base}/workers/durable_objects/namespaces`]: list([], 1000),
    [`${base}/secrets_store/stores`]: list([], 100),

    [`${base}/pages/projects`]: list(PAGES_PROJECTS),

    [`${base}/access/apps`]: appsRoute(APPS.map((a) => a.app)),
    [`${base}/access/policies`]: envelope([staff, employees], listInfo(2)),
    [`${base}/access/groups`]: envelope([groupStaff], listInfo(1)),
    [`${base}/access/service_tokens`]: envelope([serviceTokenExample], listInfo(1)),
    [`${base}/access/identity_providers`]: envelope([idpOtp, idpOkta], listInfo(2)),

    [`${base}/tunnels`]: tunnelsRoute(TUNNELS),
    [`${base}/tokens`]: tokensRoute(TOKENS.map((t) => accountToken(accountId, t))),
    [`${base}/members`]: membersRoute([memberExample]),
    [`${base}/security-center/insights`]: insightsRoute([exampleIssue]),
  };

  for (const [zoneId, records] of Object.entries(DNS)) {
    routes[`/zones/${zoneId}/dns_records`] = list(records, 5000);
  }
  for (const w of WORKERS) {
    routes[`${scripts}/${w.name}/deployments`] = envelope(deployments(w));
    routes[`${scripts}/${w.name}/versions/${w.versionId}`] = envelope(version(w));
  }
  for (const project of PAGES_PROJECTS) {
    routes[`${base}/pages/projects/${project.name}`] = envelope(project);
    routes[`${base}/pages/projects/${project.name}/domains`] = list([]);
  }
  for (const { app, policies } of APPS) {
    const ranked = policies.map((p, i) => ({ ...p, precedence: i + 1 }));
    routes[`${base}/access/apps/${app.id}/policies`] = envelope(ranked, listInfo(ranked.length));
  }
  for (const [id, { config }] of Object.entries(TUNNEL_CONFIGS)) {
    routes[`${base}/cfd_tunnel/${id}/configurations`] = envelope(
      tunnelConfig(accountId, id, config),
    );
  }
  return { routes, graphql: trafficGraphql(trafficRows).handler };
}

// Expectations ----------------------------------------------------------------

/**
 * Credentials in the API responses: the token in mailer's plain-text variable,
 * the token and key in Pages env vars, the IdP client and SCIM secrets, and
 * the service token's client ID. None of them may reach the graph.
 */
export const SECRET_VALUES = [
  FAKE_TOKEN,
  PAGES_TOKEN,
  PAGES_KEY,
  FAKE_SECRET,
  FAKE_SCIM_PASSWORD,
  FAKE_CLIENT_ID,
];

/**
 * A tunnel hostname node ID in the form of the graph contract as of round 1,
 * `<hostname><path>`. The test maps it to the ID the collector emits, so the
 * round 2 form `<tunnel_id>:<hostname><path>` passes too. Each hostname and
 * path appears in one tunnel only, so the mapping is unique.
 */
const tunnelHostname = (hostnameAndPath: string) => `tunnel_hostname:${hostnameAndPath}`;

export interface SeededCase {
  rule: string;
  case: string;
  fingerprint: string;
  severity: RuleSeverity;
  /** A cross-package mismatch that keeps this case from passing; the test is `it.fails`. */
  mismatch?: string;
}

export const SEEDED: SeededCase[] = [
  {
    rule: "CF-002",
    case: "Worker behind Access on its Custom Domain and public on workers.dev",
    fingerprint: "CF-002:worker_script:portal",
    severity: "high",
  },
  {
    rule: "CF-003",
    case: "long-lived account token with Workers Scripts Write",
    fingerprint: `CF-003:account_token:${TOKEN_DEPLOY}`,
    severity: "high",
  },
  {
    rule: "CF-004",
    case: "public tunnel hostname with an SSH origin",
    fingerprint: `CF-004:${tunnelHostname("ssh.example.com")}`,
    severity: "critical",
  },
  {
    rule: "CF-004",
    case: "R3-01: SSH origin under a top-level access block that cloudflared does not enforce",
    fingerprint: `CF-004:${tunnelHostname("git.example.com")}`,
    severity: "critical",
  },
  {
    rule: "CF-004",
    case: "R3-02: path-only rule before a hostname rule that requires an Access token",
    fingerprint: `CF-004:${tunnelHostname("dash.example.com^/debug")}`,
    severity: "high",
  },
  {
    rule: "CF-004",
    case: "R3-02: catch-all origin behind a path-restricted hostname that requires an Access token",
    fingerprint: `CF-004:${tunnelHostname("ops.example.com")}`,
    severity: "high",
  },
  {
    rule: "CF-007",
    case: "unproxied A record to the address of a proxied record",
    fingerprint: `CF-007:dns_record:${REC_ORIGIN}`,
    severity: "medium",
  },
  {
    rule: "CF-009",
    case: "idle Worker bound to the database a live Worker uses",
    fingerprint: "CF-009:worker_script:archiver",
    severity: "low",
  },
  {
    rule: "CF-010",
    case: "Allow policy including Everyone on an app in front of a Worker with data",
    fingerprint: `CF-010:access_policy:${POLICY_EVERYONE}`,
    severity: "critical",
  },
  {
    rule: "CF-011",
    case: "Bypass policy on a whole-host app in front of a Worker with data",
    fingerprint: `CF-011:access_policy:${POLICY_BYPASS}`,
    severity: "high",
  },
  {
    rule: "CF-021",
    case: "bucket public through r2.dev",
    fingerprint: "CF-021:r2_bucket:public-assets",
    severity: "high",
  },
  {
    rule: "CF-022",
    case: "Pages project with public previews bound to the production database",
    fingerprint: "CF-022:pages_project:storefront",
    severity: "medium",
  },
  {
    rule: "CF-024",
    case: "API token in a plain-text variable",
    fingerprint: "CF-024:worker_script:mailer",
    severity: "medium",
  },
  {
    rule: "CF-024",
    case: "API token in a plain-text env var of a Pages project's production environment",
    fingerprint: "CF-024:pages_project:handbook",
    severity: "medium",
  },
];

export interface CleanCase {
  rule: string;
  case: string;
  /** The node a finding of the rule would be about. */
  subject: string;
}

export const CLEAN: CleanCase[] = [
  {
    rule: "CF-002",
    case: "Worker-level Access on every entry point",
    subject: "worker_script:intranet",
  },
  { rule: "CF-003", case: "write token that expires soon", subject: `account_token:${TOKEN_CI}` },
  { rule: "CF-003", case: "long-lived read-only token", subject: `account_token:${TOKEN_READ}` },
  {
    rule: "CF-004",
    case: "tunnel hostname behind Access",
    subject: tunnelHostname("app.example.com"),
  },
  {
    rule: "CF-004",
    case: "R3-01: tunnel hostname whose own rule requires an Access token",
    subject: tunnelHostname("wiki.example.com"),
  },
  {
    rule: "CF-004",
    case: "R3-02: hostname rule that requires an Access token next to a path-only rule",
    subject: tunnelHostname("dash.example.com"),
  },
  {
    rule: "CF-004",
    case: "R3-02: path-only rule on a hostname behind an Access app",
    subject: tunnelHostname("kb.example.com^/debug"),
  },
  {
    rule: "CF-004",
    case: "R3-02: path-restricted hostname rule that requires an Access token",
    subject: tunnelHostname("ops.example.com^/admin"),
  },
  {
    rule: "CF-004",
    case: "R3-02: hostname rule that requires an Access token on every path, before a catch-all origin",
    subject: tunnelHostname("vault.example.com"),
  },
  {
    rule: "CF-007",
    case: "unproxied record with an address of its own",
    subject: `dns_record:${REC_MAIL}`,
  },
  {
    rule: "CF-009",
    case: "idle Worker whose data no other workload uses",
    subject: "worker_script:reporter",
  },
  {
    rule: "CF-010",
    case: "Allow policy for one email domain",
    subject: `access_policy:${POLICY_EMPLOYEES}`,
  },
  {
    rule: "CF-010",
    case: "Allow policy for an Access group",
    subject: `access_policy:${POLICY_STAFF}`,
  },
  {
    rule: "CF-011",
    case: "Bypass policy on a path app",
    subject: `access_policy:${POLICY_HEALTH}`,
  },
  { rule: "CF-021", case: "bucket with r2.dev disabled", subject: "r2_bucket:private-data" },
  {
    rule: "CF-022",
    case: "public previews with their own database",
    subject: "pages_project:blog",
  },
  {
    rule: "CF-024",
    case: "URL as plain text, key as a secret binding",
    subject: "worker_script:shop",
  },
  {
    rule: "CF-024",
    case: "Pages project with a URL as plain text and the key as a secret env var",
    subject: "pages_project:landing",
  },
];

export interface ExposureExpectation {
  case: string;
  entry: string;
  rows: {
    path_prefix: string;
    decision: string;
    confidence: number;
    reason_id: string | null;
  }[];
  mismatch?: string;
}

const row = (
  decision: string,
  reasonId: string | null,
  pathPrefix = "/",
  confidence = 2,
): ExposureExpectation["rows"][number] => ({
  path_prefix: pathPrefix,
  decision,
  confidence,
  reason_id: reasonId,
});

/**
 * cloudflared requires an Access token (`access_required`) and no Access app
 * decides: the tunnel hostname is the reason, with medium confidence.
 */
const originRow = (entry: string, pathPrefix = "/") => row("access", entry, pathPrefix, 1);

/** Exposure of the entry points the seeded and clean cases depend on. */
export const EXPOSURE: ExposureExpectation[] = [
  {
    case: "Custom Domain behind a hostname app",
    entry: "worker_custom_domain:portal.example.com",
    rows: [row("access", `access_app:${APP_PORTAL}`)],
  },
  {
    case: "workers.dev of the same Worker without Access",
    entry: `workers_dev:portal.${SUBDOMAIN}.workers.dev`,
    rows: [row("public", null)],
  },
  {
    case: "Custom Domain behind Worker-level Access",
    entry: "worker_custom_domain:intranet.example.com",
    rows: [row("access", `access_app:${APP_INTRANET}`)],
  },
  {
    case: "workers.dev behind Worker-level Access",
    entry: `workers_dev:intranet.${SUBDOMAIN}.workers.dev`,
    rows: [row("access", `access_app:${APP_INTRANET}`)],
  },
  {
    case: "route without Access",
    entry: `worker_route:${ROUTE_SHOP}`,
    rows: [row("public", null)],
  },
  {
    case: "Allow for Everyone is still an identity decision",
    entry: "worker_custom_domain:reports.example.com",
    rows: [row("access", `access_app:${APP_REPORTS}`)],
  },
  {
    case: "Bypass for everyone on the whole host",
    entry: "worker_custom_domain:status.example.com",
    rows: [row("public", `access_policy:${POLICY_BYPASS}`)],
  },
  {
    case: "host behind identity, /health bypassed by a path app",
    entry: "worker_custom_domain:api.example.com",
    rows: [
      row("access", `access_app:${APP_API}`),
      row("public", `access_policy:${POLICY_HEALTH}`, "/health"),
    ],
  },
  {
    case: "tunnel hostname without Access",
    entry: tunnelHostname("ssh.example.com"),
    rows: [row("public", null)],
  },
  {
    case: "tunnel hostname behind Access",
    entry: tunnelHostname("app.example.com"),
    rows: [row("access", `access_app:${APP_TUNNEL}`)],
  },
  {
    case: "R3-01: a top-level access block leaves the tunnel hostname public",
    entry: tunnelHostname("git.example.com"),
    rows: [row("public", null)],
  },
  {
    case: "R3-01: the rule's own access block requires the token",
    entry: tunnelHostname("wiki.example.com"),
    rows: [originRow(tunnelHostname("wiki.example.com"))],
  },
  {
    case: "R3-02: a path-only rule is public on a hostname without an Access app",
    entry: tunnelHostname("dash.example.com^/debug"),
    rows: [row("public", null, "/debug*")],
  },
  {
    case: "R3-02: the hostname rule's own token check decides the hostname rule only",
    entry: tunnelHostname("dash.example.com"),
    rows: [originRow(tunnelHostname("dash.example.com"))],
  },
  {
    case: "R3-02: an Access app on the hostname covers a path-only rule",
    entry: tunnelHostname("kb.example.com^/debug"),
    rows: [row("access", `access_app:${APP_KB}`, "/debug*")],
  },
  {
    case: "R3-02: a path-restricted hostname rule with its own token check",
    entry: tunnelHostname("ops.example.com^/admin"),
    rows: [originRow(tunnelHostname("ops.example.com^/admin"), "/admin*")],
  },
  {
    case: "R3-02: the catch-all origin is public on the path-restricted hostname",
    entry: tunnelHostname("ops.example.com"),
    rows: [row("public", null)],
  },
  {
    case: "R3-02: a hostname rule for every path keeps the catch-all away",
    entry: tunnelHostname("vault.example.com"),
    rows: [originRow(tunnelHostname("vault.example.com"))],
  },
  {
    case: "enabled r2.dev domain",
    entry: `r2_public_domain:${R2_DEV_HOST}`,
    rows: [row("public", null)],
  },
  {
    case: "Pages preview wildcard without Access",
    entry: "pages_preview:*.storefront.pages.dev",
    rows: [row("public", null)],
  },
];
