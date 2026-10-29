import { GraphBuilder, isObject, listByPage, sortedUnique, str } from "../platform/util.ts";
import type { Collector } from "../types.ts";
import { displayName, fitsId } from "./util.ts";

/**
 * developers.cloudflare.com/api/resources/accounts/subresources/members/methods/list
 * (5 to 50 per page; `result_info` has no `total_pages`)
 */
interface CfMember {
  id?: string;
  email?: string;
  status?: string;
  user?: { email?: string };
  roles?: unknown;
  policies?: unknown;
}

const MEMBERS_PER_PAGE = 50;

/** developers.cloudflare.com/fundamentals/manage-members/roles/ */
export const SUPER_ADMIN_ROLE = "Super Administrator - All Privileges";

const names = (value: unknown): (string | null)[] =>
  (Array.isArray(value) ? value : []).filter(isObject).map((item) => str(item.name));

/**
 * Role names of a member: legacy `roles`, plus the roles (permission groups)
 * of its allow policies, which replace legacy roles in the newer member model.
 */
function roles(member: CfMember): string[] {
  const fromPolicies = (Array.isArray(member.policies) ? member.policies : [])
    .filter(isObject)
    .filter((p) => str(p.access) === "allow")
    .flatMap((p) => names(p.permission_groups));
  return sortedUnique([...names(member.roles), ...fromPolicies]);
}

/** Account members with their roles. */
export const membersCollector: Collector<never> = {
  resourceClass: "members",
  permissions: ["Account Settings Read"],

  async plan() {
    return [[]];
  },

  async collect(ctx) {
    const g = new GraphBuilder();
    const path = `/accounts/${ctx.accountId}/members`;
    for (const member of await listByPage<CfMember>(ctx.api, path, MEMBERS_PER_PAGE)) {
      const id = isObject(member) ? str(member.id) : null;
      if (!id || !fitsId(id)) continue;
      const memberRoles = roles(member);
      g.node("member", id, displayName(str(member.email) ?? member.user?.email), {
        status: str(member.status),
        roles: memberRoles,
        super_admin: memberRoles.includes(SUPER_ADMIN_ROLE),
      });
    }
    return g.output();
  },
};
