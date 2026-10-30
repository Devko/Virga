import { canonicalJson, LIMITS, nodeId, sha256 } from "@virga/graph";
import {
  chunk,
  GraphBuilder,
  isObject,
  listByPage,
  nonEmpty,
  sortedUnique,
  str,
  unlessGone,
} from "../platform/util.ts";
import type { Collector, CollectorContext } from "../types.ts";
import { displayName, fitsId } from "./util.ts";

/**
 * developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/methods/list
 * (all tunnel types; `result_info` has no `total_pages`)
 */
interface CfTunnel {
  id?: string;
  name?: string;
  status?: string;
  tun_type?: string;
  config_src?: string;
  /** Deprecated in favour of config_src. */
  remote_config?: boolean;
  deleted_at?: string | null;
}

/** developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/subresources/configurations/methods/get */
interface CfTunnelConfig {
  config?: { ingress?: unknown };
}

const TUNNEL_TYPES = ["cfd_tunnel", "warp_connector"];
const encoder = new TextEncoder();
/**
 * Rules without a hostname are expanded per hostname, so one tunnel's
 * ingress can describe about a million entry points in 96 KB (review R5-06).
 * Past this many the tunnel is marked `ingress_truncated`.
 */
export const MAX_HOSTNAMES_PER_TUNNEL = 1000;
/**
 * The props of one tunnel's `tunnel_hostname` nodes add up to at most this
 * many bytes. One path near the 64 KB props limit, expanded over 1,000
 * hostnames, would otherwise make about 64 MB for one tunnel (R5-06).
 */
export const MAX_HOSTNAME_BYTES_PER_TUNNEL = 1024 * 1024;
/**
 * A node whose own props pass the graph's limit would make the write path
 * refuse the whole chunk, so it is left out and counts toward neither limit
 * above (round 8). Past this many left-out nodes nothing more is emitted, so
 * a crafted ingress cannot make the work grow with rules times hostnames.
 */
export const MAX_OVERSIZED_PER_TUNNEL = 1000;
const OVER_COUNT = `ingress has more than ${MAX_HOSTNAMES_PER_TUNNEL} entry points`;
const OVER_BYTES = `ingress has more than ${MAX_HOSTNAME_BYTES_PER_TUNNEL} bytes of entry point props`;
const OVERSIZED = `an entry point with more than ${LIMITS.propsBytes} bytes of props`;
// At most 10,000 tunnel_hostname nodes and 10 MiB of their props per chunk.
const TUNNELS_PER_CHUNK = 10;
const TUNNELS_PER_PAGE = 1000;

function listTunnels(ctx: CollectorContext): Promise<CfTunnel[]> {
  return listByPage<CfTunnel>(ctx.api, `/accounts/${ctx.accountId}/tunnels`, TUNNELS_PER_PAGE, {
    tun_types: TUNNEL_TYPES.join(","),
    is_deleted: false,
  });
}

// The query already filters on type and deletion; this guards against a server that ignores it.
function live(t: CfTunnel): boolean {
  const type = str(t.tun_type);
  return (type === null || TUNNEL_TYPES.includes(type)) && str(t.deleted_at) === null;
}

function configSource(t: CfTunnel): string | null {
  const src = str(t.config_src);
  if (src) return src;
  if (t.remote_config === true) return "cloudflare";
  if (t.remote_config === false) return "local";
  return null;
}

// Service types from developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/protocols/
const SCHEMES: Record<string, string> = {
  http: "http",
  https: "https",
  ssh: "ssh",
  rdp: "rdp",
  tcp: "tcp",
  smb: "smb",
  unix: "unix",
  "unix+tls": "unix",
  http_status: "http_status",
};

/** `http://localhost:8080` → `http`; `bastion`, `hello_world` and anything unknown → `other`. */
export function originScheme(service: string): string {
  const scheme = /^([a-z][a-z0-9+._-]*):/i.exec(service)?.[1]?.toLowerCase();
  return (scheme && SCHEMES[scheme]) || "other";
}

/**
 * Whether cloudflared validates an Access JWT before it proxies a request
 * that this rule takes. cloudflared builds the validator from the rule's own
 * `originRequest.access` only; an access block at the top of the
 * configuration enforces nothing (review R3-01). Anything but `true` reads as
 * not required, which errs toward reporting exposure.
 * developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/#access
 */
export function accessRequired(rule: Record<string, unknown>): boolean {
  const originRequest = rule.originRequest;
  return (
    isObject(originRequest) &&
    isObject(originRequest.access) &&
    originRequest.access.required === true
  );
}

const URL_START = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * A service value without credentials: `http://user:p@ss@host` → `http://host`.
 * cloudflared parses it with Go's url.Parse: the authority runs from `//` to
 * the first '/', '?' or '#', and the userinfo ends at its last '@'. Userinfo
 * needs an '@', so a value without one is kept. An '@' anywhere else may end
 * a password that holds '/', '?' or '#', or be read as userinfo by another
 * parser, so the whole value is dropped. The result never contains an '@'.
 */
export function withoutCredentials(service: string): string {
  const at = service.lastIndexOf("@");
  if (at < 0) return service;
  const start = URL_START.exec(service)?.[0];
  if (!start) return "";
  const end = service.slice(start.length).search(/[/?#]/);
  if (end >= 0 && at > start.length + end) return "";
  return start + service.slice(at + 1);
}

/**
 * Cloudflare Tunnels and Mesh nodes (`tunnel`), and the entry points of
 * remotely managed tunnels per hostname and ingress rule (`tunnel_hostname`).
 * Locally managed tunnels keep their ingress rules on the origin, out of reach
 * of the API.
 */
export const tunnelsCollector: Collector<string> = {
  resourceClass: "tunnels",
  permissions: ["Cloudflare Tunnel Read"],

  async plan(ctx) {
    const ids = sortedUnique((await listTunnels(ctx)).filter(live).map((t) => str(t.id)));
    return nonEmpty(chunk(ids, TUNNELS_PER_CHUNK));
  },

  async collect(ctx, ids) {
    const g = new GraphBuilder();
    if (ids.length === 0) return g.output();
    const tunnels = new Map<string, CfTunnel>();
    for (const t of (await listTunnels(ctx)).filter(live)) {
      const id = str(t.id);
      if (id) tunnels.set(id, t);
    }
    const truncated: string[] = [];
    for (const id of [...ids].sort()) {
      const tunnel = tunnels.get(id);
      // Absent when it was deleted after the plan step.
      if (!tunnel || !fitsId(id)) continue;
      const type = str(tunnel.tun_type);
      // Mesh nodes have no ingress configuration.
      const src = type === "warp_connector" ? null : configSource(tunnel);
      const leftOut =
        src === "cloudflare" ? await collectIngress(ctx, id, nodeId("tunnel", id), g) : null;
      // Entry points that were left out must not resolve findings (decision 0005).
      if (leftOut) truncated.push(`tunnel ${id}: ${leftOut}`);
      g.node("tunnel", id, displayName(tunnel.name), {
        tunnel_type: type,
        status: str(tunnel.status),
        config_src: src,
        ingress_truncated: leftOut !== null,
      });
    }
    return { ...g.output(), truncated };
  },
};

interface IngressRule {
  /** Lowercase; null for a rule that matches every hostname. */
  hostname: string | null;
  path: string;
  /** Without credentials. */
  service: string;
  scheme: string;
  accessRequired: boolean;
}

function ingressRules(ingress: unknown): IngressRule[] {
  return (Array.isArray(ingress) ? ingress.filter(isObject) : []).flatMap((rule) => {
    const service = str(rule.service);
    // cloudflared refuses a rule without a service.
    if (!service) return [];
    const hostname = str(rule.hostname)?.toLowerCase() ?? null;
    return [
      {
        // cloudflared reads `*` like a missing hostname: the rule matches every hostname.
        hostname: hostname === "*" ? null : hostname,
        path: str(rule.path) ?? "",
        service: withoutCredentials(service),
        scheme: originScheme(service),
        accessRequired: accessRequired(rule),
      },
    ];
  });
}

/**
 * Native IDs of one tunnel's hostname nodes: `<tunnel_id>:<hostname>:<path>`.
 * The tunnel ID keeps two tunnels that serve the same hostname apart, and the
 * ':' keeps a hostname and a path from combining into another hostname's ID
 * (review R5-04). An ID over the graph's limit takes `sha256:<hex>` for the
 * path, which stays whole in props (R5-05). A pair that still cannot have
 * its ID, because an earlier pair holds it (a hostname may contain ':', a
 * path may read like a hash) or the hostname alone is too long, gets a hash
 * of hostname and path instead. A crafted rule that holds that one too fails
 * the chunk: no rule is dropped without a signal.
 */
function hostnameIds(tunnelId: string): (hostname: string, path: string) => Promise<string> {
  const used = new Set<string>();
  return async (hostname, path) => {
    let id = `${tunnelId}:${hostname}:${path}`;
    if (!fitsId(id)) id = `${tunnelId}:${hostname}:sha256:${await sha256(path)}`;
    if (used.has(id) || !fitsId(id)) {
      id = `${tunnelId}:sha256:${await sha256(JSON.stringify([hostname, path]))}`;
      if (used.has(id) || !fitsId(id)) {
        throw new RangeError("a tunnel ingress rule has no node ID of its own");
      }
    }
    used.add(id);
    return id;
  };
}

/**
 * One `tunnel_hostname` per rule and hostname it can take a request for.
 * cloudflared takes the first rule that matches the hostname and path, and a
 * rule without a hostname matches every hostname (review R3-02). Such a rule
 * yields a `via_fallthrough` node for every hostname in the ingress, unless
 * it answers with a status code. A rule never applies to a hostname after an
 * earlier rule took that hostname on the same path or on every path (no
 * path), so each hostname and path has one node whatever the rule's
 * position. Hostnames that only DNS sends to the tunnel stay unknown to the
 * collector.
 *
 * Returns why entry points were left out, or null when every one was
 * emitted. Past MAX_HOSTNAMES_PER_TUNNEL nodes or MAX_HOSTNAME_BYTES_PER_TUNNEL
 * bytes of their props nothing more is emitted (review R5-06), not even a
 * smaller node that would still fit. A node over the graph's props limit is
 * left out on its own: it holds no ID and counts toward neither (round 8).
 * The work is linear in the number of rules: a rule without a hostname visits
 * only the hostnames no earlier rule took whole, a path such a rule took is
 * never expanded again, each rule is measured once, not once per hostname,
 * and past MAX_OVERSIZED_PER_TUNNEL left-out nodes nothing more is emitted.
 */
async function collectIngress(
  ctx: CollectorContext,
  id: string,
  tunnelNode: string,
  g: GraphBuilder,
): Promise<string | null> {
  const path = `/accounts/${ctx.accountId}/cfd_tunnel/${id}/configurations`;
  const result = await unlessGone(ctx.api.get<CfTunnelConfig | null>(path));
  const config = isObject(result?.config) ? result.config : {};
  const rules = ingressRules(config.ingress);
  const nextId = hostnameIds(id);
  // Hostnames that no earlier rule took on every path, in sorted order.
  const open = new Set(sortedUnique(rules.map((r) => r.hostname)));
  // Paths that a rule without a hostname took for every hostname.
  const takenPaths = new Set<string>();
  // Per path, the hostnames that a hostname rule took on it.
  const takenPairs = new Map<string, Set<string>>();
  // Per hostname, the bytes it adds to a node's props.
  const hostnameBytes = new Map<string, number>();
  let count = 0;
  let bytes = 0;
  let oversized = 0;
  // The cap or the budget, once a node would pass it.
  let over: string | null = null;

  const reason = (): string | null => {
    if (oversized === 0) return over;
    return over ? `${over} and ${OVERSIZED}` : `ingress has ${OVERSIZED}`;
  };

  /**
   * The props of a rule's nodes, and their size with an empty hostname,
   * counted like the graph's write path: UTF-8 bytes of the canonical JSON.
   */
  const template = (rule: IngressRule) => {
    const props = {
      hostname: "",
      path: rule.path,
      service: rule.service,
      origin_scheme: rule.scheme,
      tunnel_id: id,
      access_required: rule.accessRequired,
      via_fallthrough: rule.hostname === null,
    };
    return { props, bytes: encoder.encode(canonicalJson(props)).length };
  };

  /** Emits one node unless it is over a limit; false when nothing more is emitted. */
  const emit = async (t: ReturnType<typeof template>, hostname: string): Promise<boolean> => {
    // A hostname adds the UTF-8 bytes of its JSON string without the quotes.
    let extra = hostnameBytes.get(hostname);
    if (extra === undefined) {
      extra = encoder.encode(JSON.stringify(hostname)).length - 2;
      hostnameBytes.set(hostname, extra);
    }
    const size = t.bytes + extra;
    // The write path would refuse the whole chunk for this node alone.
    if (size > LIMITS.propsBytes) {
      if (oversized === MAX_OVERSIZED_PER_TUNNEL) return false;
      oversized++;
      return true;
    }
    if (count === MAX_HOSTNAMES_PER_TUNNEL) {
      over = OVER_COUNT;
      return false;
    }
    if (bytes + size > MAX_HOSTNAME_BYTES_PER_TUNNEL) {
      over = OVER_BYTES;
      return false;
    }
    count++;
    bytes += size;
    const nativeId = await nextId(hostname, t.props.path);
    const props = { ...t.props, hostname };
    const hostId = g.node("tunnel_hostname", nativeId, displayName(hostname), props);
    g.edge("ROUTES_TO", hostId, tunnelNode);
    return true;
  };

  for (const rule of rules) {
    if (takenPaths.has(rule.path)) continue;
    const taken = takenPairs.get(rule.path);
    if (rule.hostname !== null) {
      if (!open.has(rule.hostname) || taken?.has(rule.hostname)) continue;
      if (taken) taken.add(rule.hostname);
      else takenPairs.set(rule.path, new Set([rule.hostname]));
      if (rule.path === "") open.delete(rule.hostname);
      if (!(await emit(template(rule), rule.hostname))) return reason();
      continue;
    }
    if (rule.scheme !== "http_status") {
      const t = template(rule);
      for (const hostname of open) {
        if (taken?.has(hostname)) continue;
        if (!(await emit(t, hostname))) return reason();
      }
    }
    // A rule without a hostname or path takes every request: none after it applies.
    if (rule.path === "") break;
    takenPaths.add(rule.path);
  }
  return reason();
}
