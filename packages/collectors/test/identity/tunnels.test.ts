import { envelope } from "@virga/cf-api/testing";
import { describe, expect, it } from "vitest";
import {
  accessRequired,
  originScheme,
  tunnelsCollector,
  withoutCredentials,
} from "../../src/identity/tunnels.ts";
import { tunnelsRoutes } from "./fixtures/routes.ts";
import {
  BLOG,
  blogConfig,
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
const blogHost = (host: string) => `tunnel_hostname:${BLOG}:${host}`;
const legacyHost = (host: string) => `tunnel_hostname:${LEGACY}:${host}`;

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
      "access_required",
    ]);
    expect(nodeIds(output, "tunnel_hostname")).toEqual(
      [
        blogHost("admin.example.com"),
        blogHost("app.example.com"),
        blogHost("jump.example.com"),
        blogHost("rdp.example.com"),
        blogHost("smb.example.com"),
        blogHost("socket.example.com"),
        blogHost("ssh.example.com"),
        blogHost("status.example.com"),
        blogHost("tcp.example.com"),
        blogHost("tunnel.example.comsubpath"),
        legacyHost("legacy.example.com"),
        legacyHost("open.example.com"),
        legacyHost("ssh.example.com"),
        legacyHost("wiki.example.com"),
      ].sort(),
    );
    expect(node(output, blogHost("tunnel.example.comsubpath"))).toEqual({
      type: "tunnel_hostname",
      nativeId: `${BLOG}:tunnel.example.comsubpath`,
      name: "tunnel.example.com",
      props: {
        hostname: "tunnel.example.com",
        path: "subpath",
        // The first rule wins; the later rule for the same hostname and path never applies.
        service: "https://localhost:8001",
        origin_scheme: "https",
        tunnel_id: BLOG,
        access_required: false,
      },
    });
    expect(node(output, blogHost("ssh.example.com")).props).toEqual({
      hostname: "ssh.example.com",
      path: "",
      service: "ssh://localhost:22",
      origin_scheme: "ssh",
      tunnel_id: BLOG,
      access_required: false,
    });
    // Two tunnels serve ssh.example.com, each with its own node and origin.
    expect(node(output, legacyHost("ssh.example.com")).props).toMatchObject({
      service: "ssh://localhost:2222",
      tunnel_id: LEGACY,
    });
    expect(edgeIds(output, "ROUTES_TO")).toContain(
      `ROUTES_TO:${legacyHost("legacy.example.com")}->tunnel:${LEGACY}`,
    );
    expect(edgeIds(output, "ROUTES_TO")).toHaveLength(14);
    expect(output.edges.filter((e) => e.dst === `tunnel:${BLOG}`).map((e) => e.src)).toHaveLength(
      10,
    );
  });

  it("reads originRequest.access.required per rule, falling back to the top-level setting", async () => {
    const { output } = await run(tunnelsCollector, routes);
    const required = (id: string) => node(output, id).props?.access_required;
    expect(required(blogHost("admin.example.com"))).toBe(true);
    expect(required(blogHost("app.example.com"))).toBe(false);
    expect(required(legacyHost("legacy.example.com"))).toBe(true);
    expect(required(legacyHost("wiki.example.com"))).toBe(true);
    expect(required(legacyHost("open.example.com"))).toBe(false);

    const access = (required: unknown) => ({ access: { required, teamName: "t", audTag: ["a"] } });
    const cases: [Record<string, unknown>, unknown, boolean][] = [
      [{}, undefined, false],
      [{ originRequest: access(true) }, undefined, true],
      [{ originRequest: access(false) }, access(true), false],
      // Without required in its own access object, the rule does not inherit it.
      [{ originRequest: { access: { teamName: "t" } } }, access(true), false],
      [{ originRequest: { connectTimeout: 5 } }, access(true), true],
      [{}, access(true), true],
      [{ originRequest: access("true") }, undefined, false],
      [{ originRequest: "access" }, access(true), true],
    ];
    for (const [rule, defaults, expected] of cases) {
      expect(accessRequired(rule, defaults), JSON.stringify([rule, defaults])).toBe(expected);
    }
  });

  it("parses the origin scheme of every service type", async () => {
    const { output } = await run(tunnelsCollector, routes);
    const scheme = (host: string) => node(output, blogHost(host)).props?.origin_scheme;
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
    expect(node(output, blogHost("app.example.com")).props?.service).toBe("http://localhost:8080");
    expect(JSON.stringify(output)).not.toContain(ORIGIN_PASSWORD);
  });

  it("R2-04: drops the whole password when it contains '@'", async () => {
    const config = {
      ...blogConfig,
      config: {
        ingress: [
          { hostname: "app.example.com", service: "http://admin:s3cr@tPass@10.0.0.5:8080" },
          { service: "http_status:404" },
        ],
      },
    };
    const { output } = await run(tunnelsCollector, {
      ...routes,
      [`${BASE}/cfd_tunnel/${BLOG}/configurations`]: envelope(config),
    });
    expect(node(output, blogHost("app.example.com")).props).toMatchObject({
      service: "http://10.0.0.5:8080",
      origin_scheme: "http",
    });
    const json = JSON.stringify(output);
    for (const part of ["admin", "s3cr", "tPass"]) expect(json).not.toContain(part);
  });

  it("R2-04: keeps no part of a credential in any service value", () => {
    const cases: [string, string][] = [
      ["http://localhost:8080", "http://localhost:8080"],
      ["ssh://localhost:22", "ssh://localhost:22"],
      ["unix+tls:/home/production/echo.sock", "unix+tls:/home/production/echo.sock"],
      ["bastion", "bastion"],
      ["http://admin:pw@localhost:8080", "http://localhost:8080"],
      ["HTTPS://admin@Origin.internal", "HTTPS://Origin.internal"],
      ["tcp://user:p@ss@w@rd@10.0.0.5:22", "tcp://10.0.0.5:22"],
      ["http://admin:s3cr%40t:x@[::1]:8080", "http://[::1]:8080"],
      ["http://a:b@host:80?debug=1", "http://host:80?debug=1"],
      ["ssh://u:p\\q@host:22", "ssh://host:22"],
      // The authority ends at the first '/', '?' or '#', so this '@' cannot be
      // told apart from a password holding one of those: the value is dropped.
      ["ssh://admin:pa/ss@host:22", ""],
      ["ssh://admin:pa?ss@host:22", ""],
      ["ssh://admin:pa#ss@host:22", ""],
      ["http://host/path@x", ""],
      // URL parsers disagree on these; none of them is kept.
      ["http:admin:secret@host", ""],
      ["http:\\\\admin:secret@host", ""],
      [" http://admin:secret@host", ""],
      ["unix:/run/admin:secret@x.sock", ""],
    ];
    for (const [service, expected] of cases) {
      expect(withoutCredentials(service), service).toBe(expected);
    }
  });

  it("emits the tunnel without hostnames when its configuration is gone", async () => {
    const { output } = await run(
      tunnelsCollector,
      without(routes, `${BASE}/cfd_tunnel/${BLOG}/configurations`),
    );
    expect(nodeIds(output, "tunnel")).toContain(`tunnel:${BLOG}`);
    expect(nodeIds(output, "tunnel_hostname")).toEqual(
      ["legacy", "open", "ssh", "wiki"].map((h) => legacyHost(`${h}.example.com`)),
    );
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
