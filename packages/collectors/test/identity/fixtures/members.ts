// Source: https://developers.cloudflare.com/api/resources/accounts/subresources/members/methods/list/
// The first member is the documented 200 example; the others vary it within the schema.
// Role names: https://developers.cloudflare.com/fundamentals/manage-members/roles/
// Pages hold 5 to 50 members, and `result_info` has no `total_pages`.

import type { CfQuery } from "@virga/cf-api";
import { envelope } from "@virga/cf-api/testing";

const grant = (write: boolean) => ({ read: true, write });

const permissions = {
  analytics: grant(false),
  billing: grant(false),
  cache_purge: grant(false),
  dns: grant(false),
  dns_records: grant(false),
  lb: grant(false),
  logs: grant(false),
  organization: grant(false),
  ssl: grant(false),
  waf: grant(false),
  zone_settings: grant(false),
  zones: grant(true),
};

const meta = {
  category: "category",
  deprecated: "deprecated",
  description: "description",
  editable: "editable",
  eol_at: "2019-12-27T18:11:19.117Z",
  label: "load_balancer_admin",
  scopes: "com.cloudflare.api.account",
  visibility: "visibility",
};

export const memberExample = {
  id: "4536bcfad5faccb111b47003c79917fa",
  email: "user@example.com",
  policies: [
    {
      id: "f267e341f3dd4697bd3b9f71dd96247f",
      access: "allow",
      permission_groups: [
        { id: "c8fed203ed3043cba015a93ad1616f1f", meta, name: "Zone Read" },
        { id: "82e64a83756745bbbb1c9c2701bf816b", meta, name: "Magic Network Monitoring" },
      ],
      resource_groups: [
        {
          id: "6d7f2f5f5b1d4a0e9081fdc98d432fd1",
          scope: {
            key: "com.cloudflare.api.account.eb78d65290b24279ba6f44721b3ea3c4",
            objects: [{ key: "com.cloudflare.api.account.zone.23f8d65290b24279ba6f44721b3eaad5" }],
          },
          meta: { key: "key", value: "value" },
          name: "com.cloudflare.api.account.eb78d65290b24279ba6f44721b3ea3c4",
        },
      ],
    },
  ],
  roles: [
    {
      id: "3536bcfad5faccb999b47003c79917fb",
      description: "Administrative access to the entire Account",
      name: "Account Administrator",
      permissions,
    },
  ],
  status: "accepted",
  user: {
    email: "user@example.com",
    id: "023e105f4ecef8ad9ca31a8372d0c353",
    first_name: "John",
    last_name: "Appleseed",
    two_factor_authentication_enabled: true,
  },
};

/** Super Administrator through a legacy role. */
export const memberOwner = {
  id: "5647cdfbe6fbddc222c58114d8a028fb",
  roles: [
    {
      id: "33666b9c79b9a5273fc7344ff42f953d",
      description:
        "Can edit any Cloudflare setting, make purchases, update billing, and manage memberships.",
      name: "Super Administrator - All Privileges",
      permissions,
    },
  ],
  status: "accepted",
  user: { email: "owner@example.com", id: "134f216a0b5d4c6e8f9a0b1c2d3e4f5a" },
};

/** Super Administrator through a policy; a deny policy grants nothing. */
export const memberPolicy = {
  id: "6758de0cf70ceed333d69225e9b139fc",
  email: "admin@example.com",
  policies: [
    {
      id: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
      access: "allow",
      permission_groups: [
        { id: "9b2c3d4e5f60718293a4b5c6d7e8f90a", name: "Super Administrator - All Privileges" },
      ],
      resource_groups: [],
    },
    {
      id: "b2c3d4e5f60718293a4b5c6d7e8f90a1",
      access: "deny",
      permission_groups: [{ id: "0c3d4e5f60718293a4b5c6d7e8f90a1b", name: "Billing" }],
      resource_groups: [],
    },
  ],
  status: "accepted",
};

/** Invited, not yet accepted, no roles. */
export const memberPending = {
  id: "7869ef1d081dffe444e7a336fa24a00d",
  email: "new@example.com",
  status: "pending",
};

/** Filler for pagination: enough members for two pages. */
export const filler = Array.from({ length: 47 }, (_, i) => ({
  id: `e${String(i).padStart(31, "0")}`,
  email: `member${i}@example.com`,
  roles: [{ id: "05784afa30c1afe1440e79d9351c7430", name: "Administrator Read Only", permissions }],
  status: "accepted",
}));

export const MEMBERS = [memberExample, memberOwner, memberPolicy, memberPending, ...filler];

/** GET /members in pages of `per_page`, without `total_pages`. */
export function membersRoute(members: object[]) {
  return (q: CfQuery) => {
    const page = Number(q.page);
    const perPage = Number(q.per_page);
    return envelope(members.slice((page - 1) * perPage, page * perPage), {
      count: members.length,
      page,
      per_page: perPage,
      total_count: members.length,
    });
  };
}
