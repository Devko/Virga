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
  config?: { ingress?: unknown; originRequest?: unknown };
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
 * (`originRequest.access.required`). Settings at the top of the configuration
 * apply to every rule that does not set its own. A rule's own `access` object
 * is read without merging in the top-level one, and anything but `true` reads
 * as not required: both err toward reporting exposure.
 * developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/#access
 */
export function accessRequired(rule: Record<string, unknown>, defaults: unknown): boolean {
  const access = (originRequest: unknown) =>
    isObject(originRequest) && isObject(originRequest.access) ? originRequest.access : null;
  return (access(rule.originRequest) ?? access(defaults))?.required === true;
}

/** Drops credentials from a URL-style service value: `http://user:pw@host` → `http://host`. */
const withoutUserinfo = (service: string): string =>
  service.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@]*@/i, "$1");

/**
 * Cloudflare Tunnels and Mesh nodes (`tunnel`), and the public hostnames of
 * remotely managed tunnels (`tunnel_hostname`). Locally managed tunnels keep
 * their ingress rules on the origin, out of reach of the API.
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

async function collectIngress(
  ctx: CollectorContext,
  id: string,
  tunnelNode: string,
  g: GraphBuilder,
): Promise<void> {
  const path = `/accounts/${ctx.accountId}/cfd_tunnel/${id}/configurations`;
  const result = await unlessGone(ctx.api.get<CfTunnelConfig | null>(path));
  const config = isObject(result?.config) ? result.config : {};
  const ingress = config.ingress;
  const seen = new Set<string>();
  for (const rule of Array.isArray(ingress) ? ingress.filter(isObject) : []) {
    const hostname = str(rule.hostname)?.toLowerCase();
    const service = str(rule.service);
    // The catch-all rule has no hostname.
    if (!hostname || !service) continue;
    const rulePath = str(rule.path) ?? "";
    // The tunnel ID keeps two tunnels that serve the same hostname apart.
    const nativeId = `${id}:${hostname}${rulePath}`;
    // cloudflared uses the first matching rule, so a repeated hostname and path never applies.
    if (seen.has(nativeId) || !fitsId(nativeId)) continue;
    seen.add(nativeId);
    const hostId = g.node("tunnel_hostname", nativeId, hostname, {
      hostname,
      path: rulePath,
      service: withoutUserinfo(service),
      origin_scheme: originScheme(service),
      tunnel_id: id,
      access_required: accessRequired(rule, config.originRequest),
    });
    g.edge("ROUTES_TO", hostId, tunnelNode);
  }
}
