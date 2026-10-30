import { envelope } from "@virga/cf-api/testing";
import { sha256 } from "@virga/graph";
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
const blogHost = (host: string, path = "") => `tunnel_hostname:${BLOG}:${host}:${path}`;
const legacyHost = (host: string, path = "") => `tunnel_hostname:${LEGACY}:${host}:${path}`;

/** The fixture routes with the blog tunnel serving this configuration. */
const withBlogConfig = (config: object) => ({
  ...routes,
  [`${BASE}/cfd_tunnel/${BLOG}/configurations`]: envelope({ ...blogConfig, config }),
});

const required = { access: { required: true, teamName: "acme", audTag: ["aud1"] } };

/** The part after the tunnel ID for a pair whose contract ID another pair holds. */
const pairHash = async (host: string, path: string) =>
  `sha256:${await sha256(JSON.stringify([host, path]))}`;

/** The blog tunnel's hostname nodes, as `ID → props`. */
async function blogHostnames(ingress: object[]) {
  const { output } = await run(tunnelsCollector, withBlogConfig({ ingress }));
  return Object.fromEntries(
    output.nodes
      .filter((n) => n.type === "tunnel_hostname" && n.props?.tunnel_id === BLOG)
      .map((n) => [n.nativeId.slice(BLOG.length + 1), n.props]),
  );
}

const hostProps = (
  hostname: string,
  path: string,
  service: string,
  access_required: boolean,
  via_fallthrough: boolean,
) => ({
  hostname,
  path,
  service,
  origin_scheme: originScheme(service),
  tunnel_id: BLOG,
  access_required,
  via_fallthrough,
});

describe("tunnels collector", () => {
  it("lists cfd tunnels and Mesh nodes that are not deleted, in chunks of 10", async () => {
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
    expect(plan.map((c) => c.length).slice(-2)).toEqual([10, 1]);
  });

  it("emits tunnel nodes with the contract props", async () => {
    const { output } = await run(tunnelsCollector, routes);
    expectProps(output, "tunnel", ["tunnel_type", "status", "config_src", "ingress_truncated"]);
    expect(node(output, `tunnel:${BLOG}`)).toEqual({
      type: "tunnel",
      nativeId: BLOG,
      name: "blog",
      props: {
        tunnel_type: "cfd_tunnel",
        status: "healthy",
        config_src: "cloudflare",
        ingress_truncated: false,
      },
    });
    expect(node(output, `tunnel:${LOCAL}`).props).toEqual({
      tunnel_type: "cfd_tunnel",
      status: "down",
      config_src: "local",
      ingress_truncated: false,
    });
    // Falls back to the deprecated remote_config flag.
    expect(node(output, `tunnel:${LEGACY}`).props?.config_src).toBe("cloudflare");
    expect(node(output, `tunnel:${MESH}`)).toEqual({
      type: "tunnel",
      nativeId: MESH,
      name: "branch-office",
      props: {
        tunnel_type: "warp_connector",
        status: "degraded",
        config_src: null,
        ingress_truncated: false,
      },
    });
  });

  it("reads the ingress configuration of remotely managed tunnels only", async () => {
    const { calls } = await run(tunnelsCollector, routes);
    expect(callPaths(calls).filter((p) => p.endsWith("/configurations"))).toEqual(
      [BLOG, LEGACY].sort().map((id) => `${BASE}/cfd_tunnel/${id}/configurations`),
    );
  });

  it("emits tunnel_hostname nodes with ROUTES_TO, none for a catch-all with a status code", async () => {
    const { output } = await run(tunnelsCollector, routes);
    expectProps(output, "tunnel_hostname", [
      "hostname",
      "path",
      "service",
      "origin_scheme",
      "tunnel_id",
      "access_required",
      "via_fallthrough",
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
        blogHost("tunnel.example.com", "subpath"),
        legacyHost("legacy.example.com"),
        legacyHost("open.example.com"),
        legacyHost("ssh.example.com"),
        legacyHost("wiki.example.com"),
      ].sort(),
    );
    expect(node(output, blogHost("tunnel.example.com", "subpath"))).toEqual({
      type: "tunnel_hostname",
      nativeId: `${BLOG}:tunnel.example.com:subpath`,
      name: "tunnel.example.com",
      props: {
        hostname: "tunnel.example.com",
        path: "subpath",
        // The first rule wins; the later rule for the same hostname and path never applies.
        service: "https://localhost:8001",
        origin_scheme: "https",
        tunnel_id: BLOG,
        access_required: false,
        via_fallthrough: false,
      },
    });
    expect(node(output, blogHost("ssh.example.com")).props).toEqual({
      hostname: "ssh.example.com",
      path: "",
      service: "ssh://localhost:22",
      origin_scheme: "ssh",
      tunnel_id: BLOG,
      access_required: false,
      via_fallthrough: false,
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

  it("R3-01: reads originRequest.access.required from the rule's own block only", async () => {
    const { output } = await run(tunnelsCollector, routes);
    const required = (id: string) => node(output, id).props?.access_required;
    expect(required(blogHost("admin.example.com"))).toBe(true);
    expect(required(blogHost("app.example.com"))).toBe(false);
    // The legacy tunnel sets access only at the top of its configuration.
    expect(required(legacyHost("legacy.example.com"))).toBe(false);
    expect(required(legacyHost("wiki.example.com"))).toBe(false);
    expect(required(legacyHost("open.example.com"))).toBe(false);

    const access = (required: unknown) => ({ access: { required, teamName: "t", audTag: ["a"] } });
    const cases: [Record<string, unknown>, boolean][] = [
      [{}, false],
      [{ originRequest: access(true) }, true],
      [{ originRequest: access(false) }, false],
      [{ originRequest: { access: { teamName: "t" } } }, false],
      [{ originRequest: { connectTimeout: 5 } }, false],
      [{ originRequest: access("true") }, false],
      [{ originRequest: "access" }, false],
      [{ originRequest: { access: "required" } }, false],
    ];
    for (const [rule, expected] of cases) {
      expect(accessRequired(rule), JSON.stringify(rule)).toBe(expected);
    }
  });

  it("R3-01: a top-level access block does not make a rule require an Access token", async () => {
    // The review's scenario: cloudflared builds the JWT validator from the
    // rule's own originRequest.access only, so this SSH origin is open.
    const config = {
      originRequest: required,
      ingress: [
        { hostname: "ssh.example.com", service: "ssh://localhost:22" },
        { service: "http_status:404" },
      ],
    };
    const { output } = await run(tunnelsCollector, withBlogConfig(config));
    expect(node(output, blogHost("ssh.example.com")).props).toMatchObject({
      service: "ssh://localhost:22",
      access_required: false,
    });
  });

  it("R3-02: a path-only rule before a hostname rule is an entry point of that hostname", async () => {
    // Case A of the review: https://app.example.com/debug/… reaches
    // localhost:6060 without a token check.
    const nodes = await blogHostnames([
      { path: "^/debug", service: "http://localhost:6060" },
      { hostname: "app.example.com", service: "http://localhost:8080", originRequest: required },
      { service: "http_status:404" },
    ]);
    expect(nodes).toEqual({
      "app.example.com:^/debug": hostProps(
        "app.example.com",
        "^/debug",
        "http://localhost:6060",
        false,
        true,
      ),
      "app.example.com:": hostProps("app.example.com", "", "http://localhost:8080", true, false),
    });
  });

  it("R3-02: a catch-all origin behind a path-restricted hostname is an entry point of that hostname", async () => {
    // Case B of the review: every path of app.example.com but /admin reaches
    // the catch-all origin without a token check.
    const nodes = await blogHostnames([
      {
        hostname: "app.example.com",
        path: "^/admin",
        service: "http://localhost:9000",
        originRequest: required,
      },
      { service: "http://localhost:8080" },
    ]);
    expect(nodes).toEqual({
      "app.example.com:^/admin": hostProps(
        "app.example.com",
        "^/admin",
        "http://localhost:9000",
        true,
        false,
      ),
      "app.example.com:": hostProps("app.example.com", "", "http://localhost:8080", false, true),
    });
  });

  it("R3-02: a rule without a hostname yields a node per hostname, with its own access_required", async () => {
    const { output } = await run(
      tunnelsCollector,
      withBlogConfig({
        originRequest: required,
        ingress: [
          { hostname: "a.example.com", path: "^/one", service: "http://localhost:1" },
          // Answers with a status code: no entry point.
          { path: "^/blocked", service: "http_status:403" },
          { path: "^/metrics", service: "http://localhost:9090", originRequest: required },
          { hostname: "B.example.com", path: "^/two", service: "http://localhost:2" },
          // cloudflared reads `*` as no hostname.
          { hostname: "*", path: "^/ssh", service: "ssh://localhost:22" },
          { service: "http://localhost:8080" },
        ],
      }),
    );
    const fallthrough = output.nodes.filter((n) => n.props?.via_fallthrough === true);
    expect(fallthrough.map((n) => [n.nativeId.slice(BLOG.length + 1), n.name]).sort()).toEqual(
      [
        ["a.example.com:", "a.example.com"],
        ["a.example.com:^/metrics", "a.example.com"],
        ["a.example.com:^/ssh", "a.example.com"],
        ["b.example.com:", "b.example.com"],
        ["b.example.com:^/metrics", "b.example.com"],
        ["b.example.com:^/ssh", "b.example.com"],
      ].sort(),
    );
    expect(node(output, blogHost("b.example.com", "^/metrics")).props).toEqual(
      hostProps("b.example.com", "^/metrics", "http://localhost:9090", true, true),
    );
    expect(node(output, blogHost("a.example.com", "^/ssh")).props).toEqual(
      hostProps("a.example.com", "^/ssh", "ssh://localhost:22", false, true),
    );
    // Every fall-through node routes to its tunnel.
    for (const n of fallthrough) {
      expect(edgeIds(output, "ROUTES_TO")).toContain(
        `ROUTES_TO:tunnel_hostname:${n.nativeId}->tunnel:${BLOG}`,
      );
    }
    expect(nodeIds(output, "tunnel_hostname")).not.toContain(blogHost("*", "^/ssh"));
  });

  it("R3-02: skips a rule for a hostname that an earlier rule takes whole or on the same path", async () => {
    const nodes = await blogHostnames([
      // Takes every request to app.example.com.
      { hostname: "app.example.com", service: "http://localhost:8080", originRequest: required },
      { path: "^/debug", service: "http://localhost:6060" },
      { hostname: "app.example.com", path: "^/admin", service: "http://localhost:9000" },
      // Takes /blocked of every hostname, so the next rule never applies.
      { path: "^/blocked", service: "http_status:403" },
      { hostname: "web.example.com", path: "^/blocked", service: "http://localhost:7000" },
      // The first rule for a hostname and path applies.
      { hostname: "web.example.com", path: "^/api", service: "http://localhost:7001" },
      { path: "^/api", service: "http://localhost:7002" },
      { service: "http://localhost:8081" },
    ]);
    expect(nodes).toEqual({
      "app.example.com:": hostProps("app.example.com", "", "http://localhost:8080", true, false),
      "web.example.com:^/debug": hostProps(
        "web.example.com",
        "^/debug",
        "http://localhost:6060",
        false,
        true,
      ),
      "web.example.com:^/api": hostProps(
        "web.example.com",
        "^/api",
        "http://localhost:7001",
        false,
        false,
      ),
      "web.example.com:": hostProps("web.example.com", "", "http://localhost:8081", false, true),
    });
  });

  it("R5-04: a hostname and a path never combine into another hostname's ID", async () => {
    // Case 1 of the review: both rules had the ID <tid>:ssh.example.com, so
    // the SSH origin got no node.
    expect(
      await blogHostnames([
        { hostname: "ssh", path: ".example.com", service: "http_status:404" },
        { hostname: "ssh.example.com", service: "ssh://localhost:22" },
        { service: "http_status:404" },
      ]),
    ).toEqual({
      "ssh:.example.com": hostProps("ssh", ".example.com", "http_status:404", false, false),
      "ssh.example.com:": hostProps("ssh.example.com", "", "ssh://localhost:22", false, false),
    });
    // Case 2: the rule with a token check took the ID of the one without.
    expect(
      await blogHostnames([
        {
          hostname: "app.example.co",
          path: "m",
          service: "http://localhost:8080",
          originRequest: required,
        },
        { hostname: "app.example.com", service: "ssh://localhost:22" },
        { service: "http_status:404" },
      ]),
    ).toEqual({
      "app.example.co:m": hostProps("app.example.co", "m", "http://localhost:8080", true, false),
      "app.example.com:": hostProps("app.example.com", "", "ssh://localhost:22", false, false),
    });
  });

  it("R5-04: shadows by hostname and path, and gives a pair whose ID is taken a hashed one", async () => {
    // A hostname with ':' still meets another pair's ID. The first pair keeps
    // it; the next one gets a hash of hostname and path instead of no node.
    const nodes = await blogHostnames([
      { hostname: "a.example.com:x", service: "http://localhost:1" },
      { hostname: "a.example.com", path: "x:", service: "ssh://localhost:22" },
      { service: "http_status:404" },
    ]);
    expect(nodes).toEqual({
      "a.example.com:x:": hostProps("a.example.com:x", "", "http://localhost:1", false, false),
      [await pairHash("a.example.com", "x:")]: hostProps(
        "a.example.com",
        "x:",
        "ssh://localhost:22",
        false,
        false,
      ),
    });
  });

  it("R5-04: fails the chunk when a crafted rule holds the hashed ID too", async () => {
    const taken = await pairHash("a.example.com", "x:");
    const ingress = [
      { hostname: "sha256", path: taken.slice("sha256:".length), service: "http://localhost:1" },
      { hostname: "a.example.com:x", service: "http://localhost:2" },
      { hostname: "a.example.com", path: "x:", service: "ssh://localhost:22" },
      { service: "http_status:404" },
    ];
    await expect(run(tunnelsCollector, withBlogConfig({ ingress }))).rejects.toThrow(RangeError);
  });

  it("R5-05: hashes the path of an ID over 512 characters instead of dropping the node", async () => {
    // The review's rule: a 474-character regex made a 526-character ID, the
    // fall-through node was dropped, and only the token-checked rule remained.
    const path = `^/debug/(${Array.from({ length: 95 }, (_, i) => `p${i}x`).join("|")})`;
    expect(path).toHaveLength(474);
    expect(
      await blogHostnames([
        { path, service: "ssh://localhost:22" },
        { hostname: "app.example.com", service: "http://localhost:8080", originRequest: required },
        { service: "http_status:404" },
      ]),
    ).toEqual({
      [`app.example.com:sha256:${await sha256(path)}`]: hostProps(
        "app.example.com",
        path,
        "ssh://localhost:22",
        false,
        true,
      ),
      "app.example.com:": hostProps("app.example.com", "", "http://localhost:8080", true, false),
    });
  });

  it("R5-05: keeps a 600-character path-only rule apart from a path that reads like its hash", async () => {
    const path = `^/${"a".repeat(598)}`;
    const hashed = `sha256:${await sha256(path)}`;
    expect(
      await blogHostnames([
        { hostname: "app.example.com", path: hashed, service: "http://localhost:1" },
        { path, service: "ssh://localhost:22" },
        { hostname: "app.example.com", service: "http://localhost:8080" },
      ]),
    ).toEqual({
      [`app.example.com:${hashed}`]: hostProps(
        "app.example.com",
        hashed,
        "http://localhost:1",
        false,
        false,
      ),
      [await pairHash("app.example.com", path)]: hostProps(
        "app.example.com",
        path,
        "ssh://localhost:22",
        false,
        true,
      ),
      "app.example.com:": hostProps("app.example.com", "", "http://localhost:8080", false, false),
    });
  });

  it("R5-05: gives a hostname too long for the contract ID the hashed pair ID", async () => {
    const hostname = `${"a".repeat(480)}.example.com`;
    expect(
      await blogHostnames([
        { hostname, service: "ssh://localhost:22" },
        { service: "http_status:404" },
      ]),
    ).toEqual({
      [await pairHash(hostname, "")]: hostProps(hostname, "", "ssh://localhost:22", false, false),
    });
  });

  describe("R5-06: at most 1,000 entry points per tunnel", () => {
    const pathRules = (n: number) =>
      Array.from({ length: n }, (_, i) => ({ path: `^/p${i}`, service: "http://localhost:8080" }));
    const hostRules = (n: number) =>
      Array.from({ length: n }, (_, i) => ({
        hostname: `h${i}.example.com`,
        service: "http://localhost:8081",
      }));

    /** The blog tunnel's hostname node count and its ingress_truncated. */
    async function blogIngress(ingress: object[]) {
      const { output } = await run(tunnelsCollector, withBlogConfig({ ingress }));
      const hostnames = output.nodes.filter(
        (n) => n.type === "tunnel_hostname" && n.props?.tunnel_id === BLOG,
      );
      const routes = output.edges.filter(
        (e) => e.type === "ROUTES_TO" && e.dst === `tunnel:${BLOG}`,
      );
      expect(routes).toHaveLength(hostnames.length);
      // The other tunnel of the chunk is collected as before.
      expect(node(output, `tunnel:${LEGACY}`).props?.ingress_truncated).toBe(false);
      expect(nodeIds(output, "tunnel_hostname")).toContain(legacyHost("wiki.example.com"));
      return {
        count: hostnames.length,
        truncated: node(output, `tunnel:${BLOG}`).props?.ingress_truncated,
        ids: hostnames.map((n) => n.nativeId.slice(BLOG.length + 1)),
      };
    }

    it("R5-06: stops at 1,000 for the review's 96 KB configuration and marks the tunnel", async () => {
      // Case 1 of the review: 1,000 path-only and 1,000 hostname rules gave 1,001,001 nodes.
      const ingress = [...pathRules(1000), ...hostRules(1000), { service: "http_status:404" }];
      expect(JSON.stringify(ingress).length).toBeGreaterThan(95_000);
      const started = Date.now();
      const { count, truncated, ids } = await blogIngress(ingress);
      expect(Date.now() - started).toBeLessThan(2_000);
      expect(count).toBe(1000);
      expect(truncated).toBe(true);
      // Rule order, then hostnames in sorted order: the first path-only rule
      // reaches all 1,000 hostnames.
      expect(ids.every((id) => id.endsWith(":^/p0"))).toBe(true);
    });

    it("R5-06: marks the review's 200 by 200 configuration truncated", async () => {
      // Case 2 of the review: 40,201 nodes.
      const ingress = [...pathRules(200), ...hostRules(200), { service: "http_status:404" }];
      expect(await blogIngress(ingress)).toMatchObject({ count: 1000, truncated: true });
    });

    it("R5-06: is not truncated at exactly 1,000 entry points, and is at 1,001", async () => {
      const at = await blogIngress([...hostRules(1000), { service: "http_status:404" }]);
      expect(at).toMatchObject({ count: 1000, truncated: false });
      const over = await blogIngress([...hostRules(1001), { service: "http_status:404" }]);
      expect(over).toMatchObject({ count: 1000, truncated: true });
    });

    it("R5-06: does not count rules that yield no node, and stops expanding after a catch-all", async () => {
      // Status-code rules without a hostname, shadowed rules and rules after a
      // catch-all origin yield nothing, however many there are.
      const blocked = Array.from({ length: 5000 }, (_, i) => ({
        path: `^/b${i}`,
        service: "http_status:403",
      }));
      const ingress = [
        ...hostRules(999),
        ...blocked,
        { hostname: "h0.example.com", service: "http://localhost:9" },
        { service: "http://localhost:8080" },
        ...pathRules(5000),
      ];
      const { count, truncated, ids } = await blogIngress(ingress);
      // The hostname rules take every path of their hostnames, so the
      // catch-all origin and the path rules after it reach none of them.
      expect(count).toBe(999);
      expect(truncated).toBe(false);
      expect(ids.every((id) => id.endsWith(".example.com:"))).toBe(true);
    });
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
