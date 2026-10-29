// Source: https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/list/
// The first token is the documented 200 example; the others vary it within the schema
// (nested `resources`, no condition, no expiry). Pages hold 5 to 50 tokens, and
// `result_info` has no `total_pages`.

import type { CfQuery } from "@virga/cf-api";
import { envelope } from "@virga/cf-api/testing";

const meta = (label: string) => ({
  category: "category",
  deprecated: "deprecated",
  description: "description",
  editable: "editable",
  eol_at: "2019-12-27T18:11:19.117Z",
  label,
  scopes: "com.cloudflare.api.account",
  visibility: "visibility",
});

export const tokenExample = {
  id: "ed17574386854bf78a67040be0a770b0",
  condition: {
    request_ip: {
      in: ["123.123.123.0/24", "2606:4700::/32"],
      not_in: ["123.123.123.100/24", "2606:4700:4700::/48"],
    },
  },
  creator_email_at_creation: "user@example.com",
  expires_on: "2020-01-01T00:00:00Z",
  issued_on: "2018-07-01T05:20:00Z",
  last_used_on: "2020-01-02T12:34:00Z",
  modified_on: "2018-07-02T05:20:00Z",
  name: "readonly token",
  not_before: "2018-07-01T05:20:00Z",
  policies: [
    {
      id: "f267e341f3dd4697bd3b9f71dd96247f",
      effect: "allow",
      permission_groups: [
        {
          id: "c8fed203ed3043cba015a93ad1616f1f",
          meta: meta("load_balancer_admin"),
          name: "Zone Read",
        },
        {
          id: "82e64a83756745bbbb1c9c2701bf816b",
          meta: meta("fbm_user"),
          name: "Magic Network Monitoring",
        },
      ],
      resources: { "com.cloudflare.api.account.zone.22b1de5f1c0e4b3ea97bb1e963b06a43": "*" },
    },
  ],
  provisioner_id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  provisioner_type: "com.cloudflare.api.oauthtoken",
  status: "active",
};

/** Write access to every zone of the account, nested; no expiry, no IP condition, never used. */
export const tokenDeploy = {
  id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  issued_on: "2024-02-01T00:00:00Z",
  modified_on: "2024-02-01T00:00:00Z",
  name: "deploy",
  policies: [
    {
      id: "1b2c3d4e5f60718293a4b5c6d7e8f90a",
      effect: "allow",
      permission_groups: [
        { id: "e086da7e2179491d91ee5f35b3ca210a", name: "Workers Scripts Write" },
      ],
      resources: {
        "com.cloudflare.api.account.023e105f4ecef8ad9ca31a8372d0c353": {
          "com.cloudflare.api.account.zone.*": "*",
        },
      },
    },
    {
      id: "2c3d4e5f60718293a4b5c6d7e8f90a1b",
      effect: "deny",
      permission_groups: [{ id: "4755a26eedb94da69e1066d98aa820be", name: "DNS Write" }],
      resources: { "com.cloudflare.api.account.zone.22b1de5f1c0e4b3ea97bb1e963b06a43": "*" },
    },
  ],
  status: "active",
};

export const tokenDisabled = {
  id: "1f2e3d4c5b6a79881726354a5b6c7d8e",
  expires_on: "2027-01-01T00:00:00Z",
  issued_on: "2025-01-01T00:00:00Z",
  last_used_on: "2025-06-30T08:00:00Z",
  modified_on: "2025-07-01T00:00:00Z",
  name: "old ci",
  not_before: null,
  policies: [],
  status: "disabled",
};

/** Filler for pagination: enough tokens for two pages. */
export const filler = Array.from({ length: 49 }, (_, i) => ({
  ...tokenDisabled,
  id: `f${String(i).padStart(31, "0")}`,
  name: `filler ${i}`,
}));

export const TOKENS = [tokenExample, tokenDeploy, tokenDisabled, ...filler];

/** GET /tokens in pages of `per_page`, without `total_pages`. */
export function tokensRoute(tokens: object[]) {
  return (q: CfQuery) => {
    const page = Number(q.page);
    const perPage = Number(q.per_page);
    return envelope(tokens.slice((page - 1) * perPage, page * perPage), {
      count: tokens.length,
      page,
      per_page: perPage,
      total_count: tokens.length,
    });
  };
}
