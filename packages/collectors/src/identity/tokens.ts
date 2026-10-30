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

/** Longest text kept of an entry that does not parse; no address with a prefix is this long. */
const MAX_RAW_CIDR = 64;

const DECIMAL = /^[0-9]{1,3}$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/;

/** Four octets in decimal; a leading zero is refused, because some parsers read it as octal. */
function parseIpv4(text: string): number[] | null {
  const octets = text.split(".");
  if (octets.length !== 4) return null;
  const values = octets.map((o) =>
    DECIMAL.test(o) && (o === "0" || !o.startsWith("0")) ? Number(o) : 256,
  );
  return values.every((v) => v <= 255) ? values : null;
}

/** Eight 16-bit groups, with `::` and an IPv4 tail expanded. */
function parseIpv6(text: string): number[] | null {
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parts = halves.map((half) => (half === "" ? [] : half.split(":")));
  const groups = parts.map((part, i) =>
    part.flatMap((group, j): number[] => {
      const last = i === parts.length - 1 && j === part.length - 1;
      if (last && group.includes(".")) {
        const v4 = parseIpv4(group);
        return v4 ? [(v4[0] ?? 0) * 256 + (v4[1] ?? 0), (v4[2] ?? 0) * 256 + (v4[3] ?? 0)] : [NaN];
      }
      return HEX_GROUP.test(group) ? [Number.parseInt(group, 16)] : [NaN];
    }),
  );
  const [head = [], tail] = groups;
  if ([...head, ...(tail ?? [])].some(Number.isNaN)) return null;
  if (tail === undefined) return head.length === 8 ? head : null;
  const fill = 8 - head.length - tail.length;
  return fill >= 1 ? [...head, ...Array.from({ length: fill }, () => 0), ...tail] : null;
}

/** RFC 5952 text of eight groups; an IPv4-mapped address keeps its IPv4 part as a dotted quad. */
function formatIpv6(groups: number[]): string {
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const [hi = 0, lo = 0] = groups.slice(6);
    return `::ffff:${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  // The longest run of two or more zero groups becomes `::`, the first of equal runs.
  let best = { start: -1, length: 1 };
  for (let i = 0; i < 8; ) {
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > best.length) best = { start: i, length: j - i };
    i = j === i ? i + 1 : j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best.start < 0) return hex.join(":");
  const head = hex.slice(0, best.start).join(":");
  const tail = hex.slice(best.start + best.length).join(":");
  return `${head}::${tail}`;
}

/**
 * One `ip_condition` entry in canonical form, so that rules see one spelling
 * per range (R4-06): IPv4 as a dotted quad, IPv6 as RFC 5952 text, IPv4-mapped
 * IPv6 as `::ffff:a.b.c.d`, and the prefix length in decimal. A single
 * address stays without a prefix. Host bits are kept. An entry that does not
 * parse is kept as given, trimmed and cut, so a rule can tell that it limits
 * nothing.
 */
export function canonicalCidr(entry: string): string {
  const text = entry.trim();
  const slash = text.indexOf("/");
  const address = (slash < 0 ? text : text.slice(0, slash)).toLowerCase();
  const prefix = slash < 0 ? null : text.slice(slash + 1);
  const bits = prefix === null ? null : DECIMAL.test(prefix) ? Number(prefix) : -1;
  const v4 = address.includes(":") ? null : parseIpv4(address);
  const v6 = address.includes(":") ? parseIpv6(address) : null;
  const max = v4 ? 32 : 128;
  if ((v4 || v6) && (bits === null || (bits >= 0 && bits <= max))) {
    const host = v4 ? v4.join(".") : formatIpv6(v6 ?? []);
    return bits === null ? host : `${host}/${bits}`;
  }
  return text.length > MAX_RAW_CIDR ? `${text.slice(0, MAX_RAW_CIDR)}…` : text;
}

/**
 * Canonical, deduplicated and sorted. An entry that is not a string becomes
 * `""`, which parses as nothing: dropping it could make the list look narrower.
 */
const cidrs = (value: unknown): string[] =>
  [
    ...new Set(
      (Array.isArray(value) ? value : []).map((v) =>
        typeof v === "string" ? canonicalCidr(v) : "",
      ),
    ),
  ].sort();

function ipCondition(token: CfAccountToken): { in: string[]; not_in: string[] } | null {
  const ip = token.condition?.request_ip;
  if (!isObject(ip)) return null;
  return { in: cidrs(ip.in), not_in: cidrs(ip.not_in) };
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
