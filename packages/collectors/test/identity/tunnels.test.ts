import { envelope } from "@virga/cf-api/testing";
import {
  applyBatch,
  beginScan,
  canonicalJson,
  LIMITS,
  migrate,
  prepareBatch,
  sha256,
} from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
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
  legacyConfig,
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
  NOW,
  node,
  nodeIds,
  type Routes,
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

const encoder = new TextEncoder();
/** Size of props as the graph's write path counts it: UTF-8 bytes of the canonical JSON. */
const propsBytes = (props: object | undefined) => encoder.encode(canonicalJson(props ?? {})).length;

/** The part after the tunnel ID for a pair whose contract ID another pair holds. */
const pairHash = async (host: string, path: string) =>
  `sha256:${await sha256(JSON.stringify([host, path]))}`;

/** Writes each chunk through the graph's write path, as the scan Workflow does, and reads the rows back. */
async function written(routes: Routes) {
  const db = openNodeDatabase();
  try {
    migrate(db);
    beginScan(db, { id: "scan-1", kind: "fixture", at: NOW });
    const { ctx } = context(routes);
    for (const unit of await tunnelsCollector.plan(ctx)) {
      const { nodes, edges } = await tunnelsCollector.collect(ctx, unit);
      const batch = { scanId: "scan-1", resourceClass: "tunnels", nodes, edges };
      applyBatch(db, await prepareBatch(batch, NOW));
    }
    const rows = db.query<{ id: string; type: string; props: string }>(
      "SELECT id, type, props FROM nodes ORDER BY id",
    );
    return {
      rows: rows.map((r) => ({ ...r, props: JSON.parse(r.props) as Record<string, unknown> })),
      edges: db.query<{ id: string }>("SELECT id FROM edges ORDER BY id").map((r) => r.id),
    };
  } finally {
    db.close();
  }
}

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

  describe("R5-06: at most 1,000 entry points and 1 MiB of their props per tunnel", () => {
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
        bytes: hostnames.reduce((sum, n) => sum + propsBytes(n.props), 0),
        reasons: output.truncated,
        output,
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
      expect(at).toMatchObject({ count: 1000, truncated: false, reasons: [] });
      const over = await blogIngress([...hostRules(1001), { service: "http_status:404" }]);
      expect(over).toMatchObject({ count: 1000, truncated: true });
    });

    describe("R5-06: byte budget", () => {
      const BUDGET = 1024 * 1024;
      const OVER_BUDGET = `tunnel ${BLOG}: ingress has more than 1048576 bytes of entry point props`;
      const service = "http://localhost:8080";
      const host = (i: number) => `b${String(i).padStart(2, "0")}.example.com`;
      const bytesOf = (hostname: string, path: string, fallthrough = false) =>
        propsBytes(hostProps(hostname, path, service, false, fallthrough));
      // 3 UTF-8 bytes but one UTF-16 unit each: counting characters would undercount.
      const EURO = "€".repeat(1000);

      /** 20 hostname rules whose nodes' props add up to `total` bytes. */
      function rules(total: number) {
        const each = Math.floor(total / 20);
        return Array.from({ length: 20 }, (_, i) => {
          const size = i < 19 ? each : total - 19 * each;
          const path = `^/${EURO}${"a".repeat(size - bytesOf(host(i), `^/${EURO}`))}`;
          expect(bytesOf(host(i), path)).toBe(size);
          return { hostname: host(i), path, service };
        });
      }

      it("R5-06: emits every entry point when their props take exactly 1 MiB", async () => {
        const at = await blogIngress([...rules(BUDGET), { service: "http_status:404" }]);
        expect(at).toMatchObject({ count: 20, truncated: false, bytes: BUDGET, reasons: [] });
      });

      it("R5-06: leaves out the node one byte over 1 MiB and every node after it", async () => {
        const small = { hostname: "z.example.com", service };
        const over = await blogIngress([
          ...rules(BUDGET + 1),
          small,
          { service: "http_status:404" },
        ]);
        expect(over).toMatchObject({ count: 19, truncated: true, reasons: [OVER_BUDGET] });
        expect(over.bytes).toBe(19 * Math.floor((BUDGET + 1) / 20));
        expect(over.ids.filter((id) => id.startsWith(host(19)) || id.startsWith("z."))).toEqual([]);
      });

      it("R5-06: stops the review's path near the props limit, expanded over 1,000 hostnames, at 1 MiB", async () => {
        // The longest hostname of h0 to h999 gets props of exactly the graph's 64 KB limit.
        const longest = "h999.example.com";
        const path = `^/${"a".repeat(LIMITS.propsBytes - bytesOf(longest, "^/", true))}`;
        expect(bytesOf(longest, path, true)).toBe(LIMITS.propsBytes);
        // Without the budget this one tunnel made about 64 MB of props.
        expect(1000 * bytesOf("h0.example.com", path, true)).toBeGreaterThan(64_000_000);
        const ingress = [{ path, service }, ...hostRules(1000), { service: "http_status:404" }];
        const { count, truncated, bytes, ids, reasons, output } = await blogIngress(ingress);
        expect({ count, truncated, reasons }).toEqual({
          count: 16,
          truncated: true,
          reasons: [OVER_BUDGET],
        });
        expect(bytes).toBeLessThanOrEqual(BUDGET);
        // All from the path-only rule, whose path makes the IDs too long to keep.
        expect(ids.every((id) => id.includes(":sha256:"))).toBe(true);
        // The graph's write path takes every node of the chunk.
        const batch = await prepareBatch({ scanId: "s", resourceClass: "tunnels", ...output });
        expect(batch.nodes.length).toBe(output.nodes.length);
      });
    });

    it("0005: reports a truncated reason for each tunnel with ingress_truncated", async () => {
      const ingress = [...hostRules(1001), { service: "http_status:404" }];
      const { output } = await run(tunnelsCollector, {
        ...withBlogConfig({ ingress }),
        [`${BASE}/cfd_tunnel/${LEGACY}/configurations`]: envelope({
          ...legacyConfig,
          config: { ingress },
        }),
      });
      for (const id of [BLOG, LEGACY]) {
        expect(node(output, `tunnel:${id}`).props?.ingress_truncated).toBe(true);
      }
      // One chunk, tunnels in ID order.
      expect(output.truncated).toEqual([
        `tunnel ${LEGACY}: ingress has more than 1000 entry points`,
        `tunnel ${BLOG}: ingress has more than 1000 entry points`,
      ]);
      // The fixture's own configurations truncate nothing.
      expect((await run(tunnelsCollector, routes)).output.truncated).toEqual([]);
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

    describe("round 8: an entry point over the graph's props limit", () => {
      const OVERSIZED = `tunnel ${BLOG}: ingress has an entry point with more than 65536 bytes of props`;
      const service = "http://localhost:8080";
      const notFound = { service: "http_status:404" };

      /** A path that gives the node of `hostname` props of exactly `size` bytes. */
      function pathOf(hostname: string, size: number, fallthrough = false) {
        const bytes = (path: string) =>
          propsBytes(hostProps(hostname, path, service, false, fallthrough));
        // 3 UTF-8 bytes but one UTF-16 unit each: counting characters would undercount.
        const prefix = `^/${"€".repeat(20_000)}`;
        const path = `${prefix}${"a".repeat(size - bytes(prefix))}`;
        expect(bytes(path)).toBe(size);
        return path;
      }
      /** A hostname rule whose node's props are one byte over the limit. */
      const oversized = (hostname: string) => ({
        hostname,
        path: pathOf(hostname, LIMITS.propsBytes + 1),
        service,
      });
      /** Hostname rules whose 16 nodes take exactly the 1 MiB budget. */
      const fullBudget = () =>
        Array.from({ length: 16 }, (_, i) => {
          const hostname = `f${String(i).padStart(2, "0")}.example.com`;
          return { hostname, path: pathOf(hostname, LIMITS.propsBytes), service };
        });

      it("round 8: the write path takes the chunk instead of refusing every tunnel in it", async () => {
        // One node over the limit made prepareBatch refuse the whole chunk, so
        // no tunnel of the chunk was refreshed.
        const ingress = [{ hostname: "a.example.com", service }, oversized("big.example.com")];
        const { rows, edges } = await written(withBlogConfig({ ingress: [...ingress, notFound] }));
        expect(rows.filter((r) => r.type === "tunnel_hostname").map((r) => r.id)).toEqual(
          [
            blogHost("a.example.com"),
            ...["legacy", "open", "ssh", "wiki"].map((h) => legacyHost(`${h}.example.com`)),
          ].sort(),
        );
        expect(
          Object.fromEntries(
            rows.filter((r) => r.type === "tunnel").map((r) => [r.id, r.props.ingress_truncated]),
          ),
        ).toEqual({
          [`tunnel:${BLOG}`]: true,
          [`tunnel:${LOCAL}`]: false,
          [`tunnel:${LEGACY}`]: false,
          [`tunnel:${MESH}`]: false,
        });
        expect(edges.filter((id) => id.startsWith("ROUTES_TO:"))).toHaveLength(5);
      });

      it("round 8: leaves out the node and its ROUTES_TO edge, marks the tunnel and emits later nodes", async () => {
        const { output, ...result } = await blogIngress([
          { hostname: "a.example.com", service },
          oversized("big.example.com"),
          { hostname: "c.example.com", service },
          notFound,
        ]);
        expect(result).toMatchObject({
          count: 2,
          truncated: true,
          ids: ["a.example.com:", "c.example.com:"],
          reasons: [OVERSIZED],
        });
        expect(JSON.stringify(output)).not.toContain("big.example.com");
      });

      it("round 8: emits props of exactly 65,536 bytes and leaves out 65,537, as the write path counts them", async () => {
        const at = { hostname: "at.example.com", path: pathOf("at.example.com", 65_536), service };
        const over = oversized("over.example.com");
        const { output, ...result } = await blogIngress([at, over, notFound]);
        expect(result).toMatchObject({
          count: 1,
          truncated: true,
          ids: [`at.example.com:sha256:${await sha256(at.path)}`],
          bytes: LIMITS.propsBytes,
          reasons: [OVERSIZED],
        });
        // The write path takes the node at the limit and refuses the one over it.
        await prepareBatch({ scanId: "s", resourceClass: "tunnels", ...output });
        const props = hostProps(over.hostname, over.path, service, false, false);
        const node = { type: "tunnel_hostname" as const, nativeId: "n", name: null, props };
        await expect(
          prepareBatch({ scanId: "s", resourceClass: "tunnels", nodes: [node], edges: [] }),
        ).rejects.toThrow(RangeError);
      });

      it("round 8: leaves out an oversized via_fallthrough node, with one reason for the tunnel", async () => {
        // The path gives a.example.com props of exactly the limit; the longer
        // hostnames go one and two bytes over it.
        const path = pathOf("a.example.com", LIMITS.propsBytes, true);
        const { ids, ...result } = await blogIngress([
          { path, service },
          { hostname: "a.example.com", service },
          { hostname: "bb.example.com", service },
          { hostname: "ccc.example.com", service },
          notFound,
        ]);
        expect(result).toMatchObject({ count: 4, truncated: true, reasons: [OVERSIZED] });
        expect(ids).toEqual(
          [
            `a.example.com:sha256:${await sha256(path)}`,
            "a.example.com:",
            "bb.example.com:",
            "ccc.example.com:",
          ].sort(),
        );
      });

      it("round 8: counts the left-out node toward neither the 1,000-node cap nor the byte budget", async () => {
        // The cap: 1,000 nodes that fit, before and after the oversized one.
        const hosts = hostRules(1000);
        const plain = await blogIngress([...hosts, notFound]);
        expect(plain).toMatchObject({ count: 1000, truncated: false });
        for (const ingress of [
          [oversized("big.example.com"), ...hosts, notFound],
          [...hosts, oversized("big.example.com"), notFound],
        ]) {
          const capped = await blogIngress(ingress);
          expect(capped).toMatchObject({ count: 1000, truncated: true, reasons: [OVERSIZED] });
          // The other nodes have the IDs they have without the oversized rule.
          expect(capped.ids).toEqual(plain.ids);
        }
        // The budget: 16 nodes of 65,536 bytes take exactly 1 MiB.
        const full = fullBudget();
        const fits = await blogIngress([...full, notFound]);
        const budget = await blogIngress([oversized("big.example.com"), ...full, notFound]);
        expect(budget).toMatchObject({
          count: 16,
          truncated: true,
          bytes: 1024 * 1024,
          reasons: [OVERSIZED],
        });
        expect(budget.ids).toEqual(fits.ids);
      });

      it("round 8: names the cap or the budget and the oversized node when both apply", async () => {
        const cap = await blogIngress([oversized("big.example.com"), ...hostRules(1001), notFound]);
        expect(cap).toMatchObject({
          count: 1000,
          truncated: true,
          reasons: [
            `tunnel ${BLOG}: ingress has more than 1000 entry points and an entry point with more than 65536 bytes of props`,
          ],
        });
        const budget = await blogIngress([
          oversized("big.example.com"),
          ...fullBudget(),
          { hostname: "z.example.com", service },
          notFound,
        ]);
        expect(budget).toMatchObject({
          count: 16,
          truncated: true,
          reasons: [
            `tunnel ${BLOG}: ingress has more than 1048576 bytes of entry point props and an entry point with more than 65536 bytes of props`,
          ],
        });
      });

      it("round 8: a left-out node holds no ID, so the others have the IDs they have without its rule", async () => {
        // A crafted pair that meets the left-out node's ID keeps the plain ID;
        // when the node fits, the pair gets the hashed one (R5-04).
        const pair = { hostname: "a.example.com", path: "x:", service: "ssh://localhost:22" };
        const long = `http://localhost:1/${"a".repeat(LIMITS.propsBytes)}`;
        const over = await blogIngress([{ hostname: "a.example.com:x", service: long }, pair]);
        const alone = await blogIngress([pair]);
        expect(alone.ids).toEqual(["a.example.com:x:"]);
        expect(over).toMatchObject({ count: 1, truncated: true, reasons: [OVERSIZED] });
        expect(over.ids).toEqual(alone.ids);
        const fits = await blogIngress([{ hostname: "a.example.com:x", service }, pair]);
        expect(fits.ids).toEqual(["a.example.com:x:", await pairHash("a.example.com", "x:")]);
      });

      it("round 8: leaves out at most 1,000 nodes, then emits nothing more", async () => {
        // A path-only rule over the limit reaches every hostname of the ingress.
        const path = `^/${"a".repeat(LIMITS.propsBytes)}`;
        const at = await blogIngress([{ path, service }, ...hostRules(1000), notFound]);
        expect(at).toMatchObject({ count: 1000, truncated: true, reasons: [OVERSIZED] });
        const over = await blogIngress([{ path, service }, ...hostRules(1001), notFound]);
        expect(over).toMatchObject({ count: 0, truncated: true, reasons: [OVERSIZED] });
      });

      it("round 8: measures a long rule once, not once per hostname", async () => {
        // Measured per node, these 999 left-out nodes made about 4 GB of JSON.
        const path = `^/${"a".repeat(2_000_000)}`;
        const long = `http://localhost:8080/${"b".repeat(2_000_000)}`;
        const started = Date.now();
        const { count, truncated, reasons } = await blogIngress([
          { path, service: long },
          ...hostRules(999),
          notFound,
        ]);
        expect(Date.now() - started).toBeLessThan(2_000);
        expect({ count, truncated, reasons }).toEqual({
          count: 999,
          truncated: true,
          reasons: [OVERSIZED],
        });
      });
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
