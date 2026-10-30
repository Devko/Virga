import { sha256 } from "@virga/graph";
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
const TUNNELS_PER_CHUNK = 25;
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
    for (const id of [...ids].sort()) {
      const tunnel = tunnels.get(id);
      // Absent when it was deleted after the plan step.
      if (!tunnel || !fitsId(id)) continue;
      const type = str(tunnel.tun_type);
      // Mesh nodes have no ingress configuration.
      const src = type === "warp_connector" ? null : configSource(tunnel);
      const tunnelId = g.node("tunnel", id, displayName(tunnel.name), {
        tunnel_type: type,
        status: str(tunnel.status),
        config_src: src,
      });
      if (src === "cloudflare") await collectIngress(ctx, id, tunnelId, g);
    }
    return g.output();
  },
};

interface IngressRule {
  /** Lowercase; null for a rule that matches every hostname. */
  hostname: string | null;
  path: string;
  service: string;
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
        service,
        accessRequired: accessRequired(rule),
      },
    ];
  });
}

/**
 * Native IDs of one tunnel's hostname nodes: `<tunnel_id>:<hostname>:<path>`.
 * The tunnel ID keeps two tunnels that serve the same hostname apart, and the
 * ':' keeps a hostname and a path from combining into another hostname's ID
 * (review R5-04). A hostname may still hold a ':' itself, so a pair whose ID
 * an earlier pair holds gets a hash of hostname and path instead; a crafted
 * rule that holds that one too fails the chunk rather than hide a node.
 */
function hostnameIds(tunnelId: string): (hostname: string, path: string) => Promise<string> {
  const used = new Set<string>();
  return async (hostname, path) => {
    let id = `${tunnelId}:${hostname}:${path}`;
    if (used.has(id)) {
      id = `${tunnelId}:sha256:${await sha256(JSON.stringify([hostname, path]))}`;
      if (used.has(id)) throw new RangeError("two tunnel ingress rules share a node ID");
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
 */
async function collectIngress(
  ctx: CollectorContext,
  id: string,
  tunnelNode: string,
  g: GraphBuilder,
): Promise<void> {
  const path = `/accounts/${ctx.accountId}/cfd_tunnel/${id}/configurations`;
  const result = await unlessGone(ctx.api.get<CfTunnelConfig | null>(path));
  const config = isObject(result?.config) ? result.config : {};
  const rules = ingressRules(config.ingress);
  const nextId = hostnameIds(id);
  // Hostnames that no earlier rule took on every path, in sorted order.
  const open = new Set(sortedUnique(rules.map((r) => r.hostname)));
  // Paths that a rule without a hostname took for every hostname.
  const takenPaths = new Set<string>();
  // Hostname and path pairs that a hostname rule took.
  const takenPairs = new Set<string>();
  const pair = (hostname: string, path: string) => JSON.stringify([hostname, path]);

  const emit = async (rule: IngressRule, hostname: string) => {
    const nativeId = await nextId(hostname, rule.path);
    if (!fitsId(nativeId)) return;
    const hostId = g.node("tunnel_hostname", nativeId, hostname, {
      hostname,
      path: rule.path,
      service: withoutCredentials(rule.service),
      origin_scheme: originScheme(rule.service),
      tunnel_id: id,
      access_required: rule.accessRequired,
      via_fallthrough: rule.hostname === null,
    });
    g.edge("ROUTES_TO", hostId, tunnelNode);
  };

  for (const rule of rules) {
    if (takenPaths.has(rule.path)) continue;
    if (rule.hostname !== null) {
      const key = pair(rule.hostname, rule.path);
      if (!open.has(rule.hostname) || takenPairs.has(key)) continue;
      takenPairs.add(key);
      if (rule.path === "") open.delete(rule.hostname);
      await emit(rule, rule.hostname);
      continue;
    }
    if (originScheme(rule.service) !== "http_status") {
      for (const hostname of open) {
        if (!takenPairs.has(pair(hostname, rule.path))) await emit(rule, hostname);
      }
    }
    takenPaths.add(rule.path);
    if (rule.path === "") open.clear();
  }
}
