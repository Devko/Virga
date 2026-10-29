import { nodeId } from "@virga/graph";
import { type GraphBuilder, isObject, str } from "../platform/util.ts";
import { bounded, canonicalList } from "./util.ts";

// Access rules, as in the include / require / exclude lists of policies and groups:
// developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/policies/methods/list

export type SelectorKind =
  | "everyone"
  | "email"
  | "email_domain"
  | "email_list"
  | "group"
  | "idp_group"
  | "service_token"
  | "any_valid_service_token"
  | "login_method"
  | "ip"
  | "geo"
  | "device_posture"
  | "certificate"
  | "common_name"
  | "other";

/** `value` is null for everyone, any_valid_service_token and certificate, and the bounded raw rule for other. */
export type Selector =
  | { kind: Exclude<SelectorKind, "idp_group" | "other">; value: string | null }
  | { kind: "idp_group"; value: { idp: string; name: string } }
  | { kind: "other"; value: unknown };

export const SELECTOR_KEYS = ["include", "require", "exclude"] as const;
export type SelectorKey = (typeof SELECTOR_KEYS)[number];

export const EVERYONE_ID = nodeId("everyone", "everyone");

const other = (rule: unknown): Selector => ({ kind: "other", value: bounded(rule) });

function text(
  kind: Exclude<SelectorKind, "idp_group" | "other">,
  value: unknown,
  rule: unknown,
): Selector {
  const v = str(value);
  return v === null ? other(rule) : { kind, value: v };
}

function idpGroup(idp: unknown, name: string | null, rule: unknown): Selector {
  const id = str(idp);
  return id === null || name === null
    ? other(rule)
    : { kind: "idp_group", value: { idp: id, name } };
}

const pair = (a: unknown, b: unknown): string | null => {
  const left = str(a);
  const right = str(b);
  return left === null || right === null ? null : `${left}=${right}`;
};

/** One Access rule, an object with a single key such as `{ "email": { "email": "..." } }`. */
export function selector(rule: unknown): Selector {
  if (!isObject(rule)) return other(rule);
  const keys = Object.keys(rule);
  const key = keys[0];
  const body = key === undefined ? undefined : rule[key];
  if (keys.length !== 1 || key === undefined || !isObject(body)) return other(rule);
  switch (key) {
    case "everyone":
      return { kind: "everyone", value: null };
    case "any_valid_service_token":
      return { kind: "any_valid_service_token", value: null };
    case "certificate":
      return { kind: "certificate", value: null };
    case "email":
      return text("email", body.email, rule);
    case "email_domain":
      return text("email_domain", body.domain, rule);
    case "email_list":
      return text("email_list", body.id, rule);
    case "group":
      return text("group", body.id, rule);
    case "service_token":
      return text("service_token", body.token_id, rule);
    case "login_method":
      return text("login_method", body.id, rule);
    case "ip":
      return text("ip", body.ip, rule);
    case "geo":
      return text("geo", body.country_code, rule);
    case "device_posture":
      return text("device_posture", body.integration_uid, rule);
    case "common_name":
      return text("common_name", body.common_name, rule);
    case "azureAD":
      return idpGroup(body.identity_provider_id, str(body.id), rule);
    case "okta":
      return idpGroup(body.identity_provider_id, str(body.name), rule);
    case "gsuite":
      return idpGroup(body.identity_provider_id, str(body.email), rule);
    case "github-organization": {
      const org = str(body.name);
      const team = str(body.team);
      return idpGroup(body.identity_provider_id, org && team ? `${org}/${team}` : org, rule);
    }
    case "saml":
      return idpGroup(
        body.identity_provider_id,
        pair(body.attribute_name, body.attribute_value),
        rule,
      );
    case "oidc":
      return idpGroup(body.identity_provider_id, pair(body.claim_name, body.claim_value), rule);
    default:
      return other(rule);
  }
}

export const selectors = (rules: unknown): Selector[] =>
  canonicalList((Array.isArray(rules) ? rules : []).map(selector));

/** The node a selector points to, if it has one. */
export function selectedNode(s: Selector): string | null {
  switch (s.kind) {
    case "everyone":
      return EVERYONE_ID;
    case "group":
      return s.value === null ? null : nodeId("access_group", s.value);
    case "service_token":
      return s.value === null ? null : nodeId("service_token", s.value);
    case "login_method":
      return s.value === null ? null : nodeId("identity_provider", s.value);
    case "idp_group":
      return nodeId("identity_provider", s.value.idp);
    default:
      return null;
  }
}

export type Rules = Record<SelectorKey, Selector[]>;

/** The include, require and exclude lists of a policy or group. */
export function rulesOf(source: Record<string, unknown>): Rules {
  return {
    include: selectors(source.include),
    require: selectors(source.require),
    exclude: selectors(source.exclude),
  };
}

/** SELECTS edges from a policy or group, and the everyone node when a rule names it. */
export function addSelects(g: GraphBuilder, src: string, rules: Rules): void {
  for (const key of SELECTOR_KEYS) {
    for (const s of rules[key]) {
      const dst = selectedNode(s);
      if (!dst) continue;
      if (dst === EVERYONE_ID) g.node("everyone", "everyone", "Everyone", {});
      g.edge("SELECTS", src, dst, {}, key);
    }
  }
}
