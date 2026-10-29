import type { SignalRow } from "@virga/graph";
import { GraphBuilder, isObject, listByPage, str } from "../platform/util.ts";
import type { Collector } from "../types.ts";
import { canonicalList, displayName, epochMs, fitsId, sortedSignals } from "./util.ts";

/**
 * developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/list
 * (5 to 50 per page; `result_info` has no `total_pages`). Token values are
 * never part of the listing.
 */
interface CfAccountToken {
  id?: string;
  name?: string;
  status?: string;
  issued_on?: string;
  modified_on?: string;
  expires_on?: string;
  not_before?: string;
  last_used_on?: string;
  policies?: unknown;
  condition?: { request_ip?: { in?: unknown; not_in?: unknown } };
}

const TOKENS_PER_PAGE = 50;

export interface TokenPolicy {
  effect: string | null;
  permission_groups: { id: string; name: string | null }[];
  resources: Record<string, string>;
}

const strings = (value: unknown): string[] =>
  [...new Set((Array.isArray(value) ? value : []).map(str))]
    .filter((v): v is string => v !== null)
    .sort();

/**
 * `resources` is either `{ resource: "*" }` or nested as
 * `{ account: { resource: "*" } }`. A nested map is flattened to its inner
 * entries: an account-owned token can only reach its own account.
 */
function resources(value: unknown): Record<string, string> {
  const entries = (map: unknown): [string, unknown][] => (isObject(map) ? Object.entries(map) : []);
  const flat = entries(value).flatMap(([key, v]): [string, unknown][] =>
    isObject(v) ? entries(v) : [[key, v]],
  );
  return Object.fromEntries(
    flat
      .filter((e): e is [string, string] => typeof e[1] === "string")
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
}

function policies(value: unknown): TokenPolicy[] {
  return canonicalList(
    (Array.isArray(value) ? value : []).filter(isObject).map((p) => {
      const groups = (Array.isArray(p.permission_groups) ? p.permission_groups : [])
        .filter(isObject)
        .flatMap((pg) => {
          const id = str(pg.id);
          return id ? [{ id, name: str(pg.name) }] : [];
        });
      return {
        effect: str(p.effect),
        permission_groups: canonicalList(groups),
        resources: resources(p.resources),
      };
    }),
  );
}

function ipCondition(token: CfAccountToken): { in: string[]; not_in: string[] } | null {
  const ip = token.condition?.request_ip;
  if (!isObject(ip)) return null;
  return { in: strings(ip.in), not_in: strings(ip.not_in) };
}

/** Account-owned API tokens, including recently expired ones, with their last use as a signal. */
export const tokensCollector: Collector<never> = {
  resourceClass: "tokens",
  permissions: ["Account API Tokens Read"],

  async plan() {
    return [[]];
  },

  async collect(ctx) {
    const g = new GraphBuilder();
    const signals: SignalRow[] = [];
    const path = `/accounts/${ctx.accountId}/tokens`;
    const tokens = await listByPage<CfAccountToken>(ctx.api, path, TOKENS_PER_PAGE, {
      include_expired: true,
    });
    for (const token of tokens.filter(isObject)) {
      const id = str(token.id);
      if (!id || !fitsId(id)) continue;
      const tokenId = g.node("account_token", id, displayName(token.name), {
        status: str(token.status),
        issued_on: str(token.issued_on),
        modified_on: str(token.modified_on),
        expires_on: str(token.expires_on),
        not_before: str(token.not_before),
        policies: policies(token.policies),
        ip_condition: ipCondition(token),
      });
      signals.push({ nodeId: tokenId, name: "last_used_on", value: epochMs(token.last_used_on) });
    }
    return { ...g.output(), signals: sortedSignals(signals) };
  },
};
