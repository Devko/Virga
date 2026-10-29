// Sources, each built from the documented 200 example and its schema:
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/methods/list/
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/policies/methods/list/
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/groups/methods/list/
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/methods/list/
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/methods/list/
// https://developers.cloudflare.com/api/resources/workers/subresources/beta/subresources/workers/methods/list/
// Worker destinations: https://developers.cloudflare.com/workers/configuration/cloudflare-access/
// Paths and wildcards: https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/

import type { CfQuery } from "@virga/cf-api";
import { envelope } from "@virga/cf-api/testing";

/** Assembled at runtime so secret scanners do not flag the fixture. */
export const FAKE_SECRET = `${"idp"}-${"Zt8Qw3Lp6Vn1Rx4Ys7Ub0Mc"}`;
export const FAKE_SCIM_PASSWORD = `${"scim"}-${"Hk2Jf5Gd8Sa1Pl4Oi7Uy0Tr"}`;
export const FAKE_CLIENT_ID = "88bf3b6d86161464f6509f7219099e57.access.example.com";

export const IDP_OTP = "f174e90a-fafe-4643-bbbc-4a0ed4fc8415";
export const IDP_OKTA = "699d98642c564d2e855e9661899b7252";
export const GROUP_ENG = "aa0a4aab-672b-4bdb-bc33-a59f1130a11f";
export const GROUP_CONTRACTORS = "bb1b5bbc-783c-4cec-cd44-b6a02241b22a";
export const TOKEN_CI = "3537a672-e4d8-4d89-aab9-26cb622918a1";
export const TOKEN_IDLE = "4648b783-f5e9-4e9a-bbca-37dc733029b2";

export const WORKER_MY = "e8f70fdbc8b1fb0b8ddb1af166186758";
export const WORKER_API = "c81a2d22c29840ed9d61681a3270dbff";
export const WORKER_UNKNOWN = "0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a";

export const APP_ADMIN = "f174e90a-fafe-4643-bbbc-4a0ed4fc8415";
export const APP_WORKER = "2a7f5c1e-0b6d-4e2f-9a1c-3d4e5f6a7b8c";
export const APP_ALL_PREVIEWS = "3b8a6d2f-1c7e-4f3a-8b2d-4e5f6a7b8c9d";
export const APP_PRIVATE = "4c9b7e3a-2d8f-4a4b-9c3e-5f6a7b8c9d0e";
export const APP_SSH = "5dac8f4b-3e9a-4b5c-8d4f-6a7b8c9d0e1f";
export const APP_VNC = "6ebd9a5c-4fab-4c6d-9e5a-7b8c9d0e1f2a";
export const APP_BOOKMARK = "7fce0b6d-5abc-4d7e-8f6b-8c9d0e1f2a3b";
export const APP_SAAS = "80df1c7e-6bcd-4e8f-9a7c-9d0e1f2a3b4c";

export const POLICY_DEVS = "0e4c6f9d-3b6a-4a81-a3f1-6c7b8a9d0e1f";
export const POLICY_HEALTH = "1f5d7a0e-4c7b-4b92-b4a2-7d8c9b0e1f2a";
export const POLICY_CI = "2a6e8b1f-5d8c-4ca3-85b3-8e9d0c1f2a3b";
export const POLICY_MIXED = "3b7f9c2a-6e9d-4db4-96c4-9f0e1d2a3b4c";
export const POLICY_UNUSED = "4c8a0d3b-7f0e-4ec5-a7d5-a01f2e3b4c5d";

const policyBase = {
  account_id: "023e105f4ecef8ad9ca31a8372d0c353",
  approval_groups: [],
  approval_required: false,
  created_at: "2014-01-01T05:20:00.12345Z",
  isolation_required: false,
  purpose_justification_required: false,
  updated_at: "2014-01-01T05:20:00.12345Z",
};

/** Reusable: used by three apps with different precedence. */
export const policyDevs = {
  ...policyBase,
  id: POLICY_DEVS,
  name: "Allow devs",
  decision: "allow",
  include: [{ group: { id: GROUP_ENG } }, { email_domain: { domain: "example.com" } }],
  require: [{ login_method: { id: IDP_OKTA } }],
  exclude: [{ email: { email: "intern@example.com" } }],
  mfa_config: { allowed_authenticators: ["totp"], mfa_disabled: false, session_duration: "24h" },
  reusable: true,
  session_duration: "24h",
};

export const policyHealth = {
  ...policyBase,
  id: POLICY_HEALTH,
  name: "Public health check",
  decision: "bypass",
  include: [{ everyone: {} }],
};

export const policyCi = {
  ...policyBase,
  id: POLICY_CI,
  name: "CI",
  decision: "non_identity",
  include: [{ service_token: { token_id: TOKEN_CI } }, { any_valid_service_token: {} }],
  session_duration: "15m",
};

/** One rule of every documented kind, plus rules the contract has no kind for. */
export const policyMixed = {
  ...policyBase,
  id: POLICY_MIXED,
  name: "Everything",
  decision: "allow",
  include: [
    { okta: { identity_provider_id: IDP_OKTA, name: "admins" } },
    { azureAD: { id: "aad-group-1", identity_provider_id: IDP_OKTA } },
    { gsuite: { email: "devs@example.com", identity_provider_id: IDP_OKTA } },
    { "github-organization": { identity_provider_id: IDP_OKTA, name: "acme", team: "ops" } },
    { saml: { attribute_name: "role", attribute_value: "admin", identity_provider_id: IDP_OKTA } },
    { oidc: { claim_name: "groups", claim_value: "sre", identity_provider_id: IDP_OKTA } },
    { email_list: { id: "8e3f1a2b-0c4d-4e5f-a6b7-c8d9e0f1a2b3" } },
    { ip: { ip: "10.0.0.0/8" } },
    { geo: { country_code: "US" } },
    { device_posture: { integration_uid: "9f4a2b3c-1d5e-4f6a-b7c8-d9e0f1a2b3c4" } },
    { certificate: {} },
    { common_name: { common_name: "client.example.com" } },
  ],
  require: [
    { auth_method: { auth_method: "mfa" } },
    { ip_list: { id: "a05b3c4d-2e6f-4a7b-8c9d-e0f1a2b3c4d5" } },
  ],
  exclude: [
    {
      external_evaluation: {
        evaluate_url: "https://eval.example.com",
        keys_url: "https://eval.example.com/keys",
      },
    },
    { email: {} },
  ],
};

/** Reusable, attached to no app. */
export const policyUnused = {
  ...policyBase,
  id: POLICY_UNUSED,
  name: "Deny everyone",
  decision: "deny",
  include: [{ everyone: {} }],
  app_count: 0,
  reusable: true,
};

const appBase = {
  aud: "737646a56ab1df6ec9bddc7e5ca84eaf3b0768850f3ffb5d74f1534911fe3893",
  created_at: "2014-01-01T05:20:00.12345Z",
  updated_at: "2014-01-01T05:20:00.12345Z",
};

/** Public destinations: a path, a wildcard host, a path wildcard with an override, an unplaceable wildcard. */
export const appAdmin = {
  ...appBase,
  id: APP_ADMIN,
  name: "Admin Site",
  type: "self_hosted",
  allowed_idps: [IDP_OKTA, IDP_OKTA],
  domain: "test.example.com/admin",
  // Ignored: destinations supersede self_hosted_domains.
  self_hosted_domains: ["test.example.com/admin", "test.anotherexample.com/staff"],
  destinations: [
    { type: "public", uri: "Test.Example.com/admin/" },
    { type: "public", uri: "*.example.com" },
    {
      type: "public",
      uri: "example.com/api/*",
      overrides: [{ behavior: "public", path_pattern: "/api/health" }],
    },
    { type: "public", uri: "example.com/foo*/bar" },
  ],
  session_duration: "24h",
  scim_config: {
    idp_uid: IDP_OKTA,
    remote_uri: "https://scim.example.com",
    authentication: { scheme: "httpbasic", user: "scim", password: FAKE_SCIM_PASSWORD },
  },
};

/** Worker-level Access: one Worker, one Worker's previews, one Worker that does not exist. */
export const appWorker = {
  ...appBase,
  id: APP_WORKER,
  name: "Access for my-worker",
  type: "self_hosted",
  destinations: [
    { type: "worker", worker_id: WORKER_MY },
    { type: "preview_worker", worker_id: WORKER_API },
    { type: "worker", worker_id: WORKER_UNKNOWN },
  ],
  session_duration: "24h",
};

/** Account-level Worker Access. */
export const appAllPreviews = {
  ...appBase,
  id: APP_ALL_PREVIEWS,
  name: "Protect all Worker previews",
  type: "self_hosted",
  destinations: [{ type: "all_preview_workers" }],
};

/** A private destination, an MCP portal destination and a type added after this collector. */
export const appPrivate = {
  ...appBase,
  id: APP_PRIVATE,
  name: "Intranet",
  type: "self_hosted",
  destinations: [
    {
      type: "private",
      cidr: "10.0.0.0/8",
      hostname: "Intranet.Example.internal",
      l4_protocol: "tcp",
      port_range: "443",
      vnet_id: "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f",
    },
    { type: "via_mcp_server_portal", mcp_server_id: "mcp-1" },
    { type: "carrier_pigeon", coop: "north" },
  ],
};

/** No destinations: self_hosted_domains apply. */
export const appSsh = {
  ...appBase,
  id: APP_SSH,
  name: "SSH",
  type: "ssh",
  domain: "ssh.example.com",
  self_hosted_domains: ["ssh.example.com", "test.anotherexample.com/staff"],
};

/** Only a domain. */
export const appVnc = {
  ...appBase,
  id: APP_VNC,
  name: "VNC",
  type: "vnc",
  domain: "VNC.example.com",
  session_duration: "1h",
};

export const appBookmark = {
  id: APP_BOOKMARK,
  name: "Wiki",
  type: "bookmark",
  domain: "https://wiki.example.com",
  app_launcher_visible: true,
};

export const appSaas = {
  ...appBase,
  id: APP_SAAS,
  name: "Salesforce",
  type: "saas",
  saas_app: { auth_type: "oidc", client_id: "client", client_secret: FAKE_SECRET },
};

export const APPS = [
  appAdmin,
  appWorker,
  appAllPreviews,
  appPrivate,
  appSsh,
  appVnc,
  appBookmark,
  appSaas,
];

/** GET /access/apps in pages of four, as `result_info.total_pages` describes. */
export function appsRoute(apps: object[] = APPS) {
  return (q: CfQuery) => {
    const page = Number(q.page ?? 1);
    const items = apps.slice((page - 1) * 4, page * 4);
    return envelope(items, {
      count: items.length,
      page,
      per_page: Number(q.per_page),
      total_count: apps.length,
      total_pages: Math.max(1, Math.ceil(apps.length / 4)),
    });
  };
}

const withPrecedence = (policy: object, precedence: number) => ({ ...policy, precedence });

/** Per-app policies, both the app's own and the reusable ones it uses. */
export const APP_POLICIES: Record<string, object[]> = {
  [APP_ADMIN]: [withPrecedence(policyDevs, 1), withPrecedence(policyHealth, 2)],
  [APP_WORKER]: [withPrecedence(policyCi, 1), withPrecedence(policyDevs, 2)],
  [APP_ALL_PREVIEWS]: [withPrecedence(policyDevs, 1)],
  [APP_PRIVATE]: [withPrecedence(policyMixed, 1)],
  [APP_SSH]: [withPrecedence(policyDevs, 1)],
  [APP_VNC]: [],
  [APP_SAAS]: [withPrecedence(policyDevs, 1)],
  // The bookmark has no policies route: a 404 is read as no policies.
};

export const groupEng = {
  id: GROUP_ENG,
  created_at: "2014-01-01T05:20:00.12345Z",
  name: "Engineering",
  include: [{ okta: { identity_provider_id: IDP_OKTA, name: "engineering" } }],
  require: [],
  exclude: [{ group: { id: GROUP_CONTRACTORS } }],
  is_default: [],
  updated_at: "2014-01-01T05:20:00.12345Z",
};

export const groupContractors = {
  id: GROUP_CONTRACTORS,
  created_at: "2014-01-01T05:20:00.12345Z",
  name: "Contractors",
  include: [{ email_domain: { domain: "contractor.example" } }],
  updated_at: "2014-01-01T05:20:00.12345Z",
};

/** The documented example. */
export const tokenCi = {
  id: TOKEN_CI,
  client_id: FAKE_CLIENT_ID,
  created_at: "2014-01-01T05:20:00.12345Z",
  duration: "60m",
  enabled: true,
  expires_at: "2014-01-01T05:20:00.12345Z",
  last_seen_at: "2014-01-01T05:20:00.12345Z",
  name: "CI/CD token",
  updated_at: "2014-01-01T05:20:00.12345Z",
};

/** Never used, no expiry. */
export const tokenIdle = {
  id: TOKEN_IDLE,
  client_id: "99c04c7e97272575f7610f8320010f68.access.example.com",
  created_at: "2024-03-01T00:00:00Z",
  duration: "forever",
  enabled: true,
  name: "Old integration",
  updated_at: "2024-03-01T00:00:00Z",
};

/** The documented example, with secrets that must never reach the graph. */
export const idpOtp = {
  config: {
    claims: ["email_verified", "preferred_username", "custom_claim_name"],
    client_id: "<your client id>",
    client_secret: FAKE_SECRET,
    conditional_access_enabled: true,
    directory_id: "<your azure directory uuid>",
    email_claim_name: "custom_claim_name",
    prompt: "login",
    support_groups: true,
  },
  name: "Widget Corps IDP",
  type: "onetimepin",
  id: IDP_OTP,
  read_only: true,
  scim_config: {
    enabled: true,
    identity_update_behavior: "automatic",
    scim_base_url: "scim_base_url",
    seat_deprovision: true,
    secret: FAKE_SCIM_PASSWORD,
    user_deprovision: true,
  },
};

export const idpOkta = {
  config: {
    client_id: "okta-client",
    client_secret: FAKE_SECRET,
    okta_account: "https://acme.okta.com",
  },
  name: "Okta",
  type: "okta",
  id: IDP_OKTA,
};

/** Workers API (beta) list entries, only the fields used here. */
export const workers = [
  { id: WORKER_MY, name: "my-worker", created_on: "2019-12-27T18:11:19.117Z" },
  { id: WORKER_API, name: "api-worker", created_on: "2021-05-01T10:00:00.000Z" },
];

export const listInfo = (count: number) => ({
  count,
  page: 1,
  per_page: 1000,
  total_count: count,
  total_pages: 1,
});
