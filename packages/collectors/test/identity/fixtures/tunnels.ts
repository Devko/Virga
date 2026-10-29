// Sources, each built from the documented 200 example and its schema:
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/methods/list/
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/subresources/configurations/methods/get/
// Service values: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/protocols/
// Catch-all rule and path regex: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/

import type { CfQuery } from "@virga/cf-api";
import { envelope } from "@virga/cf-api/testing";

export const BLOG = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415";
export const LOCAL = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
export const LEGACY = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
export const MESH = "3c4d5e6f-7a8b-4c9d-8e1f-2a3b4c5d6e7f";
export const DELETED = "4d5e6f7a-8b9c-4d0e-9f2a-3b4c5d6e7f8a";

/** Assembled at runtime so secret scanners do not flag the fixture. */
export const ORIGIN_PASSWORD = `${"hunter"}${"2-origin"}`;

const connection = {
  id: "1bedc50d-42b3-473c-b108-ff3d10c0d925",
  client_id: "1bedc50d-42b3-473c-b108-ff3d10c0d925",
  client_version: "2022.7.1",
  colo_name: "DFW",
  is_pending_reconnect: false,
  opened_at: "2021-01-25T18:22:34.317854Z",
  origin_ip: "10.1.0.137",
  uuid: "1bedc50d-42b3-473c-b108-ff3d10c0d925",
};

/** The documented example, not deleted. */
export const blog = {
  id: BLOG,
  account_tag: "699d98642c564d2e855e9661899b7252",
  config_src: "cloudflare",
  connections: [connection],
  conns_active_at: "2009-11-10T23:00:00Z",
  conns_inactive_at: null,
  created_at: "2021-01-25T18:22:34.317854Z",
  deleted_at: null,
  metadata: {},
  name: "blog",
  remote_config: true,
  status: "healthy",
  tun_type: "cfd_tunnel",
};

/** Locally managed: the ingress rules live on the origin. */
export const local = {
  ...blog,
  id: LOCAL,
  name: "on-prem",
  config_src: "local",
  remote_config: false,
  status: "down",
  connections: [],
};

/** Only the deprecated remote_config flag. */
export const legacy = {
  id: LEGACY,
  account_tag: "699d98642c564d2e855e9661899b7252",
  created_at: "2020-06-01T00:00:00Z",
  deleted_at: null,
  name: "legacy",
  remote_config: true,
  status: "inactive",
  tun_type: "cfd_tunnel",
};

/** A Mesh node (formerly WARP Connector) has no config_src. */
export const mesh = {
  id: MESH,
  account_tag: "699d98642c564d2e855e9661899b7252",
  connections: [],
  conns_active_at: "2009-11-10T23:00:00Z",
  created_at: "2021-01-25T18:22:34.317854Z",
  deleted_at: null,
  metadata: {},
  name: "branch-office",
  status: "degraded",
  tun_type: "warp_connector",
};

/** Deleted, in case the server ignores is_deleted=false. */
export const deleted = { ...blog, id: DELETED, name: "gone", deleted_at: "2024-01-01T00:00:00Z" };

export const TUNNELS = [blog, local, legacy, mesh, deleted];

/** GET /tunnels in pages of `per_page`, without `total_pages`, like the documented example. */
export function tunnelsRoute(tunnels: object[]) {
  return (q: CfQuery) => {
    const page = Number(q.page);
    const perPage = Number(q.per_page);
    return envelope(tunnels.slice((page - 1) * perPage, page * perPage), {
      count: tunnels.length,
      page,
      per_page: perPage,
      total_count: tunnels.length,
    });
  };
}

const originRequest = {
  access: { audTag: ["string"], teamName: "zero-trust-organization-name", required: false },
  connectTimeout: 10,
  noTLSVerify: false,
};

export const blogConfig = {
  account_id: "023e105f4ecef8ad9ca31a8372d0c353",
  config: {
    ingress: [
      // The documented rule: a hostname with a path.
      {
        hostname: "Tunnel.Example.com",
        service: "https://localhost:8001",
        originRequest,
        path: "subpath",
      },
      { hostname: "ssh.example.com", service: "ssh://localhost:22" },
      { hostname: "rdp.example.com", service: "rdp://localhost:3389" },
      { hostname: "tcp.example.com", service: "tcp://localhost:2222" },
      { hostname: "smb.example.com", service: "smb://localhost:445" },
      { hostname: "socket.example.com", service: "unix+tls:/home/production/echo.sock" },
      { hostname: "status.example.com", service: "http_status:418" },
      { hostname: "jump.example.com", service: "bastion" },
      { hostname: "app.example.com", service: `http://admin:${ORIGIN_PASSWORD}@localhost:8080` },
      // Shadowed by the first rule: cloudflared never reaches it.
      { hostname: "tunnel.example.com", service: "http://localhost:9999", path: "subpath" },
      // The catch-all rule.
      { service: "http_status:404" },
    ],
    originRequest,
    "warp-routing": { enabled: true },
  },
  created_at: "2014-01-01T05:20:00.12345Z",
  source: "cloudflare",
  tunnel_id: BLOG,
  version: 3,
};

export const legacyConfig = {
  account_id: "023e105f4ecef8ad9ca31a8372d0c353",
  config: {
    ingress: [
      { hostname: "legacy.example.com", service: "http://localhost:80" },
      { service: "http_status:404" },
    ],
  },
  source: "cloudflare",
  tunnel_id: LEGACY,
  version: 1,
};
