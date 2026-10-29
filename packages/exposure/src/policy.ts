import type { ExposureDecision } from "@virga/graph";
import { type GraphInput, type GraphNode, isObject, str } from "./read.ts";

export interface Verdict {
  decision: ExposureDecision;
  reasonId: string | null;
  reason: string;
}

type Tri = true | false | "unknown";

const MAX_GROUP_DEPTH = 8;
const DECISIONS = new Set(["allow", "deny", "bypass", "non_identity"]);

const selectors = (value: unknown): Record<string, unknown>[] =>
  Array.isArray(value) ? value.filter(isObject) : [];

/**
 * Whether an include list admits everyone: an `everyone` selector, or an
 * Access group whose own include does. A group that is not in the graph makes
 * the answer unknown.
 */
function includesEveryone(
  include: unknown,
  graph: GraphInput,
  depth = 0,
  seen = new Set<string>(),
): Tri {
  let result: Tri = false;
  for (const selector of selectors(include)) {
    if (selector.kind === "everyone") return true;
    if (selector.kind !== "group") continue;
    const id = `access_group:${str(selector.value) ?? ""}`;
    const group = graph.groups.get(id);
    if (!group || depth >= MAX_GROUP_DEPTH) {
      result = "unknown";
      continue;
    }
    if (seen.has(id)) continue;
    seen.add(id);
    const nested = includesEveryone(group.props.include, graph, depth + 1, seen);
    if (nested === true) return true;
    if (nested === "unknown") result = "unknown";
  }
  return result;
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
 * Auth policies run before Allow and Block, so a Bypass for everyone makes the
 * app public wherever it sits in the order.
 * developers.cloudflare.com/cloudflare-one/access-controls/policies/#cloudflare-access-policy-order-of-execution
 */
export function appVerdict(app: GraphNode, graph: GraphInput): Verdict {
  const policies = orderedPolicies(app, graph);
  for (const { policy, id } of policies) {
    if (policy?.props.decision !== "bypass") continue;
    if (includesEveryone(policy.props.include, graph) !== true) continue;
    const narrowed = selectors(policy.props.require).length > 0;
    return {
      decision: "public",
      reasonId: id,
      reason: narrowed
        ? "bypass policy includes everyone, narrowed by require rules"
        : "bypass policy includes everyone",
    };
  }

  let allow = false;
  let bypass = false;
  let serviceAuth = false;
  for (const { policy, id } of policies) {
    const unknown = (reason: string): Verdict => ({ decision: "unknown", reasonId: id, reason });
    if (!policy) return unknown("a policy of this application is missing from the graph");
    const decision = str(policy.props.decision);
    if (!decision || !DECISIONS.has(decision)) return unknown("policy action not supported");
    const everyone = includesEveryone(policy.props.include, graph);
    if (decision === "bypass") {
      if (everyone !== false) return unknown("bypass policy refers to an unknown Access group");
      bypass = true;
    } else if (decision === "non_identity") {
      if (everyone !== false) return unknown("Service Auth policy may include everyone");
      serviceAuth = true;
    } else if (decision === "allow") {
      allow = true;
    }
  }
  if (serviceAuth && !allow && !bypass) {
    return { decision: "service_auth", reasonId: app.id, reason: "only Service Auth policies" };
  }
  let reason = "allow policies require identity";
  if (!allow && !bypass) reason = "no policy admits anyone; Access denies by default";
  else if (!allow) reason = "bypass policies are limited by their selectors";
  return { decision: "access", reasonId: app.id, reason };
}
