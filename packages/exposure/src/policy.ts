import type { ExposureDecision } from "@virga/graph";
import { type GraphInput, type GraphNode, isObject, str } from "./read.ts";

export interface Verdict {
  decision: ExposureDecision;
  reasonId: string | null;
  reason: string;
  /**
   * Access admits these requests with an application token, as Service Auth
   * does without a login, so an origin that checks the token lets them in too.
   */
  token?: boolean;
}

const MAX_GROUP_DEPTH = 8;
const DECISIONS = new Set(["allow", "deny", "bypass", "non_identity"]);

/** Selector kinds of the graph contract; anything else is read as `other`. */
const KINDS = new Set([
  "everyone",
  "email",
  "email_domain",
  "email_list",
  "group",
  "idp_group",
  "service_token",
  "any_valid_service_token",
  "login_method",
  "ip",
  "geo",
  "device_posture",
  "certificate",
  "common_name",
  "other",
]);

/** Selectors that match a request by its network, country, device or credential, not by a login. */
const NON_IDENTITY = new Set([
  "ip",
  "geo",
  "certificate",
  "common_name",
  "device_posture",
  "service_token",
  "any_valid_service_token",
]);

/** The credentials a Service Auth policy checks. */
const CREDENTIALS = new Set([
  "service_token",
  "any_valid_service_token",
  "certificate",
  "common_name",
]);

/** A prefix length of 0 spans the whole address family, whatever the address. */
const ANY_ADDRESS = /^[0-9a-f.:]+\/0+$/i;

interface Include {
  /** Selector kinds, with Access groups replaced by their own include lists. */
  kinds: Set<string>;
  /** An `ip` selector for every IPv4 or every IPv6 address. */
  anyAddress: boolean;
  /** A group that is missing from the graph or nested too deep. */
  unresolved: boolean;
}

/**
 * What an include list admits. Its selectors are alternatives, so an Access
 * group adds the selectors of its own include list; its require rules can
 * only narrow it. A selector without the contract's shape counts as `other`.
 */
function readInclude(
  include: unknown,
  graph: GraphInput,
  out: Include = { kinds: new Set(), anyAddress: false, unresolved: false },
  depth = 0,
  seen = new Set<string>(),
): Include {
  for (const item of Array.isArray(include) ? include : []) {
    const selector = isObject(item) ? item : {};
    const kind = typeof selector.kind === "string" ? selector.kind : "";
    if (kind !== "group") {
      out.kinds.add(KINDS.has(kind) ? kind : "other");
      const value = str(selector.value)?.trim();
      if (kind === "ip" && value && ANY_ADDRESS.test(value)) out.anyAddress = true;
      continue;
    }
    const id = `access_group:${str(selector.value) ?? ""}`;
    const group = graph.groups.get(id);
    if (!group || depth >= MAX_GROUP_DEPTH) {
      out.unresolved = true;
      continue;
    }
    if (seen.has(id)) continue;
    seen.add(id);
    readInclude(group.props.include, graph, out, depth + 1, seen);
  }
  return out;
}

const list = (kinds: Iterable<string>) => [...kinds].sort().join(", ");

/** A policy's own verdict. The lowest rank decides the app. */
interface Ranked {
  rank: number;
  verdict: Verdict;
}

const EVERYONE = 0;
const PUBLIC = 1;
const UNKNOWN = 2;

const ranked = (
  rank: number,
  decision: ExposureDecision,
  reasonId: string,
  reason: string,
): Ranked => ({ rank, verdict: { decision, reasonId, reason } });

const undecided = (reasonId: string, reason: string): Ranked =>
  ranked(UNKNOWN, "unknown", reasonId, reason);

/**
 * A Bypass never asks for an identity, so any selector it can match without
 * a login makes the app public, whatever require rules narrow it to. Only a
 * Bypass that may need a login to match is undecided (decision 0003).
 */
function bypassVerdict(id: string, policy: GraphNode, graph: GraphInput): Ranked {
  const include = readInclude(policy.props.include, graph);
  const require = policy.props.require;
  const narrowed =
    Array.isArray(require) && require.length > 0 ? ", narrowed by require rules" : "";
  if (include.kinds.has("everyone")) {
    return ranked(EVERYONE, "public", id, `bypass policy includes everyone${narrowed}`);
  }
  const limits = [...include.kinds].filter((k) => NON_IDENTITY.has(k));
  if (limits.length > 0) {
    const reason = `bypass policy needs no identity, limited by ${list(limits)} selectors${narrowed}`;
    return ranked(PUBLIC, "public", id, reason);
  }
  if (include.unresolved) return undecided(id, "bypass policy refers to an unknown Access group");
  if (include.kinds.has("other")) {
    return undecided(id, "bypass policy has a selector that is not supported");
  }
  if (include.kinds.size > 0) {
    return undecided(id, "bypass policy has identity selectors, which a Bypass cannot evaluate");
  }
  return undecided(id, "bypass policy has no include rules");
}

/**
 * Service Auth admits requests that present a credential, without a login.
 * An IP include of every address admits everyone; an include by anything but
 * a credential is undecided (decision 0003). Null means credentials only.
 */
function serviceAuthVerdict(id: string, policy: GraphNode, graph: GraphInput): Ranked | null {
  const include = readInclude(policy.props.include, graph);
  if (include.anyAddress) {
    const open = ranked(PUBLIC, "public", id, "Service Auth policy includes every IP address");
    return { ...open, verdict: { ...open.verdict, token: true } };
  }
  if (include.unresolved) {
    return undecided(id, "Service Auth policy refers to an unknown Access group");
  }
  if (include.kinds.size === 0) return undecided(id, "Service Auth policy has no include rules");
  const loose = [...include.kinds].filter((k) => !CREDENTIALS.has(k));
  if (loose.length > 0) {
    return undecided(id, `Service Auth policy includes ${list(loose)} selectors`);
  }
  return null;
}

interface Ordered {
  policy: GraphNode | undefined;
  id: string;
  precedence: number;
}

function orderedPolicies(app: GraphNode, graph: GraphInput): Ordered[] {
  return (graph.allows.get(app.id) ?? [])
    .map((e) => ({
      policy: graph.policies.get(e.src),
      id: e.src,
      precedence:
        typeof e.props.precedence === "number" && Number.isFinite(e.props.precedence)
          ? e.props.precedence
          : Number.MAX_SAFE_INTEGER,
    }))
    .sort((a, b) => a.precedence - b.precedence || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * What an Access app decides for the requests it covers. Bypass and Service
 * Auth policies run before Allow and Block, so one that admits requests
 * without a login makes the app public wherever it sits in the order. A Bypass
 * for everyone is named before one limited by selectors; otherwise the first
 * such policy in the order is.
 * developers.cloudflare.com/cloudflare-one/access-controls/policies/#cloudflare-access-policy-order-of-execution
 */
export function appVerdict(app: GraphNode, graph: GraphInput): Verdict {
  const own: Ranked[] = [];
  let allow = false;
  let serviceAuth = false;
  for (const { policy, id } of orderedPolicies(app, graph)) {
    const decision = str(policy?.props.decision);
    if (!policy) {
      own.push(undecided(id, "a policy of this application is missing from the graph"));
    } else if (!decision || !DECISIONS.has(decision)) {
      own.push(undecided(id, "policy action not supported"));
    } else if (decision === "bypass") {
      own.push(bypassVerdict(id, policy, graph));
    } else if (decision === "non_identity") {
      const verdict = serviceAuthVerdict(id, policy, graph);
      if (verdict) own.push(verdict);
      else serviceAuth = true;
    } else if (decision === "allow") {
      allow = true;
    }
  }
  // The sort is stable, so the policy order holds within a rank.
  const [first] = own.sort((a, b) => a.rank - b.rank);
  if (first) return first.verdict;
  if (serviceAuth && !allow) {
    return { decision: "service_auth", reasonId: app.id, reason: "only Service Auth policies" };
  }
  return {
    decision: "access",
    reasonId: app.id,
    reason: allow
      ? "allow policies require identity"
      : "no policy admits anyone; Access denies by default",
  };
}
