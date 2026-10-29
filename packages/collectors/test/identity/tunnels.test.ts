import { describe, expect, it } from "vitest";
import { originScheme, tunnelsCollector } from "../../src/identity/tunnels.ts";
import { tunnelsRoutes } from "./fixtures/routes.ts";
import {
  BLOG,
  DELETED,
  LEGACY,
  LOCAL,
  local,
  MESH,
  ORIGIN_PASSWORD,
  TUNNELS,
  tunnelsRoute,
} from "./fixtures/tunnels.ts";
import {
  BASE,
  callPaths,
  context,
  denied,
  edgeIds,
  expectDeterministic,
  expectNoPermission,
  expectProps,
  node,
  nodeIds,
  run,
  without,
} from "./helpers.ts";

const routes = tunnelsRoutes;

describe("tunnels collector", () => {
  it("lists cfd tunnels and Mesh nodes that are not deleted, in chunks of 25", async () => {
    const { chunks, calls, output } = await run(tunnelsCollector, routes);
    expect(chunks).toEqual([[BLOG, LOCAL, LEGACY, MESH].sort()]);
    expect(calls[0]).toBe(
      `GET ${BASE}/tunnels?tun_types=cfd_tunnel,warp_connector&is_deleted=false&page=1&per_page=1000`,
    );
    // The fixture serves a deleted tunnel too, as if the server ignored is_deleted=false.
    expect(TUNNELS.map((t) => t.id)).toContain(DELETED);
    expect(nodeIds(output, "tunnel")).not.toContain(`tunnel:${DELETED}`);
  });

  it("follows pages until a short page, since result_info has no total_pages", async () => {
    const many = Array.from({ length: 1001 }, (_, i) => ({
      ...local,
      id: `t-${String(i).padStart(4, "0")}`,
    }));
    const { ctx, transport } = context({ [`${BASE}/tunnels`]: tunnelsRoute(many) });
    const plan = await tunnelsCollector.plan(ctx);
    expect(transport.calls.map((c) => /page=(\d+)/.exec(c)?.[1])).toEqual(["1", "2"]);
    expect(plan.flat()).toHaveLength(1001);
    expect(plan.map((c) => c.length).slice(-2)).toEqual([25, 1]);
  });

  it("emits tunnel nodes with the contract props", async () => {
    const { output } = await run(tunnelsCollector, routes);
    expectProps(output, "tunnel", ["tunnel_type", "status", "config_src"]);
    expect(node(output, `tunnel:${BLOG}`)).toEqual({
      type: "tunnel",
      nativeId: BLOG,
      name: "blog",
      props: { tunnel_type: "cfd_tunnel", status: "healthy", config_src: "cloudflare" },
    });
    expect(node(output, `tunnel:${LOCAL}`).props).toEqual({
      tunnel_type: "cfd_tunnel",
      status: "down",
      config_src: "local",
    });
    // Falls back to the deprecated remote_config flag.
    expect(node(output, `tunnel:${LEGACY}`).props?.config_src).toBe("cloudflare");
    expect(node(output, `tunnel:${MESH}`)).toEqual({
      type: "tunnel",
      nativeId: MESH,
      name: "branch-office",
      props: { tunnel_type: "warp_connector", status: "degraded", config_src: null },
    });
  });

  it("reads the ingress configuration of remotely managed tunnels only", async () => {
    const { calls } = await run(tunnelsCollector, routes);
    expect(callPaths(calls).filter((p) => p.endsWith("/configurations"))).toEqual(
      [BLOG, LEGACY].sort().map((id) => `${BASE}/cfd_tunnel/${id}/configurations`),
    );
  });

  it("emits tunnel_hostname nodes with ROUTES_TO, skipping the catch-all rule", async () => {
    const { output } = await run(tunnelsCollector, routes);
    expectProps(output, "tunnel_hostname", [
      "hostname",
      "path",
      "service",
      "origin_scheme",
      "tunnel_id",
    ]);
    expect(nodeIds(output, "tunnel_hostname")).toEqual([
      "tunnel_hostname:app.example.com",
      "tunnel_hostname:jump.example.com",
      "tunnel_hostname:legacy.example.com",
      "tunnel_hostname:rdp.example.com",
      "tunnel_hostname:smb.example.com",
      "tunnel_hostname:socket.example.com",
      "tunnel_hostname:ssh.example.com",
      "tunnel_hostname:status.example.com",
      "tunnel_hostname:tcp.example.com",
      "tunnel_hostname:tunnel.example.comsubpath",
    ]);
    expect(node(output, "tunnel_hostname:tunnel.example.comsubpath")).toEqual({
      type: "tunnel_hostname",
      nativeId: "tunnel.example.comsubpath",
      name: "tunnel.example.com",
      props: {
        hostname: "tunnel.example.com",
        path: "subpath",
        // The first rule wins; the later rule for the same hostname and path never applies.
        service: "https://localhost:8001",
        origin_scheme: "https",
        tunnel_id: BLOG,
      },
    });
    expect(node(output, "tunnel_hostname:ssh.example.com").props).toEqual({
      hostname: "ssh.example.com",
      path: "",
      service: "ssh://localhost:22",
      origin_scheme: "ssh",
      tunnel_id: BLOG,
    });
    expect(edgeIds(output, "ROUTES_TO")).toContain(
      `ROUTES_TO:tunnel_hostname:legacy.example.com->tunnel:${LEGACY}`,
    );
    expect(edgeIds(output, "ROUTES_TO")).toHaveLength(10);
    expect(output.edges.filter((e) => e.dst === `tunnel:${BLOG}`).map((e) => e.src)).toHaveLength(
      9,
    );
  });

  it("parses the origin scheme of every service type", async () => {
    const { output } = await run(tunnelsCollector, routes);
    const scheme = (host: string) => node(output, `tunnel_hostname:${host}`).props?.origin_scheme;
    expect(scheme("rdp.example.com")).toBe("rdp");
    expect(scheme("tcp.example.com")).toBe("tcp");
    expect(scheme("smb.example.com")).toBe("smb");
    expect(scheme("socket.example.com")).toBe("unix");
    expect(scheme("status.example.com")).toBe("http_status");
    expect(scheme("jump.example.com")).toBe("other");
    expect(scheme("app.example.com")).toBe("http");

    const cases: [string, string][] = [
      ["http://localhost:8000", "http"],
      ["HTTPS://localhost:8000", "https"],
      ["unix:/home/production/echo.sock", "unix"],
      ["unix+tls:/home/production/echo.sock", "unix"],
      ["http_status:404", "http_status"],
      ["hello_world", "other"],
      ["bastion", "other"],
      ["localhost:8000", "other"],
      ["socks5://localhost:1080", "other"],
      ["", "other"],
    ];
    for (const [service, expected] of cases) expect(originScheme(service), service).toBe(expected);
  });

  it("drops credentials from the service URL", async () => {
    const { output } = await run(tunnelsCollector, routes);
    expect(node(output, "tunnel_hostname:app.example.com").props?.service).toBe(
      "http://localhost:8080",
    );
    expect(JSON.stringify(output)).not.toContain(ORIGIN_PASSWORD);
  });

  it("emits the tunnel without hostnames when its configuration is gone", async () => {
    const { output } = await run(
      tunnelsCollector,
      without(routes, `${BASE}/cfd_tunnel/${BLOG}/configurations`),
    );
    expect(nodeIds(output, "tunnel")).toContain(`tunnel:${BLOG}`);
    expect(nodeIds(output, "tunnel_hostname")).toEqual(["tunnel_hostname:legacy.example.com"]);
  });

  it("skips a tunnel deleted after the plan step", async () => {
    const { ctx } = context(routes);
    const later = context({ ...routes, [`${BASE}/tunnels`]: tunnelsRoute([local]) }).ctx;
    const [ids] = await tunnelsCollector.plan(ctx);
    const out = await tunnelsCollector.collect(later, ids ?? []);
    expect(nodeIds(out)).toEqual([`tunnel:${LOCAL}`]);
  });

  it("runs one empty chunk without tunnels", async () => {
    const { chunks, output } = await run(tunnelsCollector, {
      [`${BASE}/tunnels`]: tunnelsRoute([]),
    });
    expect(chunks).toEqual([[]]);
    expect(output.nodes).toEqual([]);
  });

  it("is deterministic", async () => {
    await expectDeterministic(tunnelsCollector, routes);
  });

  it("surfaces 403 as NoPermissionError", async () => {
    await expectNoPermission(tunnelsCollector, { [`${BASE}/tunnels`]: denied() });
    await expectNoPermission(tunnelsCollector, {
      ...routes,
      [`${BASE}/cfd_tunnel/${BLOG}/configurations`]: denied(),
    });
  });
});
