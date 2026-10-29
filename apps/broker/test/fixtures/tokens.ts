// Source: https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/verify/
// and https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/get/
// (200 examples, read 2026-10-29). IDs, status values and the policy shape
// (id, effect, permission_groups with id/meta/name, resources) follow those
// examples. Resource keys follow
// https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/
// and group names follow
// https://developers.cloudflare.com/fundamentals/api/reference/permissions/.
// Expiry dates are set relative to the test clock.

export const ACCOUNT_ID = "023e105f4ecef8ad9ca31a8372d0c353";
export const OTHER_ACCOUNT_ID = "9a7806061c88ada191ed06f989cc3dac";
export const TOKEN_ID = "ed17574386854bf78a67040be0a770b0";
export const ZONE_ID = "22b1de5f1c0e4b3ea97bb1e963b06a43";

export const DAY = 24 * 60 * 60 * 1000;
export const inDays = (days: number, now = Date.now()) => new Date(now + days * DAY).toISOString();

export function verifyResult(overrides: Record<string, unknown> = {}) {
  return {
    id: TOKEN_ID,
    status: "active",
    expires_on: inDays(30),
    not_before: "2018-07-01T05:20:00Z",
    ...overrides,
  };
}

let groupSeq = 0;
/** A permission group as the token details return it. IDs are opaque in tests. */
export function group(name: string) {
  groupSeq++;
  return {
    id: groupSeq.toString(16).padStart(32, "0"),
    meta: { label: name.toLowerCase().replaceAll(" ", "_"), scopes: "com.cloudflare.api.account" },
    name,
  };
}

export const accountResource = (accountId = ACCOUNT_ID) => ({
  [`com.cloudflare.api.account.${accountId}`]: "*",
});

export function policy(
  names: string[],
  resources: Record<string, unknown> = accountResource(),
  effect: "allow" | "deny" = "allow",
) {
  return {
    id: "f267e341f3dd4697bd3b9f71dd96247f",
    effect,
    permission_groups: names.map(group),
    resources,
  };
}

/** The inventory profile of D-14, as far as the permissions reference names it. */
export const INVENTORY_GROUPS = [
  "Account Settings Read",
  "Account API Tokens Read",
  "Account Analytics Read",
  "Zone Read",
  "DNS Read",
  "Workers Routes Read",
  "Pages Metadata Read",
  "Access: Apps and Policies Read",
  "Cloudflare Tunnel Read",
  "Account Security Center Insights",
];

export function detailsResult(overrides: Record<string, unknown> = {}) {
  return {
    id: TOKEN_ID,
    condition: {},
    expires_on: inDays(30),
    issued_on: "2026-10-01T05:20:00Z",
    last_used_on: "2026-10-28T12:34:00Z",
    modified_on: "2026-10-01T05:20:00Z",
    name: "virga inventory",
    not_before: "2026-10-01T05:20:00Z",
    policies: [policy(INVENTORY_GROUPS)],
    status: "active",
    ...overrides,
  };
}
