import { replaceExposure } from "@virga/graph";
import { afterEach, describe, expect, it, vi } from "vitest";
import { evaluateExposure } from "../src/index.ts";
import {
  allWorkers,
  EVERYONE,
  type Expected,
  Graph,
  host,
  load,
  type Options,
  other,
  publicPath,
  rowCount,
  type Selector,
  sorted,
  summarize,
  worker,
} from "./graph.ts";

const CD = (h: string) => `worker_custom_domain:${h}`;
const TH = (h: string, tunnel = "tun-1") => `tunnel_hostname:${tunnel}:${h}`;
const APP = (id: string) => `access_app:${id}`;
const POLICY = (id: string) => `access_policy:${id}`;
const EMAIL: Selector = { kind: "email_domain", value: "example.com" };
const TOKEN: Selector = { kind: "service_token", value: "token-1" };

const DEV = "w.my-subdomain.workers.dev";
const PREVIEW = "abcd1234-w.my-subdomain.workers.dev";
const V_PREVIEW = "12345678-v.my-subdomain.workers.dev";

interface Case {
  name: string;
  build: (g: Graph) => void;
  options?: Options;
  expect: Expected[];
}

/** One Worker `w` with a route, a Custom Domain, workers.dev and a version URL. */
function workerEntries(g: Graph, props = {}) {
  g.script("w", props);
  g.route("r1", "example.com/*", "w");
  g.customDomain("app.example.com", "w");
  g.workersDev(DEV, "w");
  g.previewUrl(PREVIEW, "w", "abcd1234-5678-90ab-cdef-000000000000");
}

const allowApp = (g: Graph, id: string, targets: unknown[]) =>
  g.app(id, targets, [g.policy(`${id}-allow`, "allow", [EMAIL])]);
const bypassApp = (g: Graph, id: string, targets: unknown[]) =>
  g.app(id, targets, [g.policy(`${id}-bypass`, "bypass", [EVERYONE])]);

const cases: Case[] = [
  // Entry points
  {
    name: "a Custom Domain without an Access app is public",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
    },
    expect: [[CD("app.example.com"), "/", "public", 2, null]],
  },
  {
    name: "a route's path prefix comes from its pattern",
    build: (g) => {
      g.script("w");
      g.route("r1", "example.com/api/*", "w");
      g.route("r2", "https://example.com/v1*", "w");
      g.route("r3", "example.com", "w");
      g.route("r4", "example.com/status", null);
    },
    expect: [
      ["worker_route:r1", "/api/*", "public", 2, null],
      ["worker_route:r2", "/v1*", "public", 2, null],
      ["worker_route:r3", "/", "public", 2, null],
      ["worker_route:r4", "/status", "public", 2, null],
    ],
  },
  {
    name: "every entry point type is evaluated",
    build: (g) => {
      workerEntries(g);
      g.pages("site");
      g.r2Domain("pub-0113a9e4549cf9b1ff1bf56e04da0cef.r2.dev", "b1", "r2_dev", true);
      g.tunnelHostname("ssh.example.com");
    },
    expect: [
      [CD("app.example.com"), "/", "public", 2, null],
      ["pages_domain:site.pages.dev", "/", "public", 2, null],
      ["pages_preview:*.site.pages.dev", "/", "public", 2, null],
      ["r2_public_domain:pub-0113a9e4549cf9b1ff1bf56e04da0cef.r2.dev", "/", "public", 2, null],
      [TH("ssh.example.com"), "/", "public", 2, null],
      [`worker_preview_url:${PREVIEW}`, "/", "public", 2, null],
      ["worker_route:r1", "/", "public", 2, null],
      [`workers_dev:${DEV}`, "/", "public", 2, null],
    ],
  },
  {
    name: "a disabled R2 domain is no entry point, one with unknown state is unknown",
    build: (g) => {
      g.r2Domain("pub-64a5c7c3a5d24a0d8a3d0e7f2b1c9e88.r2.dev", "b1", "r2_dev", false);
      g.r2Domain("files.example.com", "b2", "custom", false);
      g.r2Domain("cdn.example.com", "b3", "custom", null);
    },
    expect: [["r2_public_domain:cdn.example.com", "/", "unknown", 0, null]],
  },
  {
    name: "stale workers.dev and preview nodes of a script that turned them off are skipped",
    build: (g) => workerEntries(g, { workers_dev: false, preview_urls: false }),
    expect: [
      [CD("app.example.com"), "/", "public", 2, null],
      ["worker_route:r1", "/", "public", 2, null],
    ],
  },

  // Hostname apps
  {
    name: "a host app covers the whole host",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "a1", [host("app.example.com")]);
    },
    expect: [[CD("app.example.com"), "/", "access", 2, APP("a1")]],
  },
  {
    name: "a host app on /admin yields / public and /admin access",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "a1", [host("app.example.com", "/admin")]);
    },
    expect: [
      [CD("app.example.com"), "/", "public", 2, null],
      [CD("app.example.com"), "/admin", "access", 2, APP("a1")],
    ],
  },
  {
    name: "an app path covers whole path segments only",
    build: (g) => {
      g.script("w");
      g.route("r1", "example.com/administrator*", "w");
      g.route("r2", "example.com/admin/users/*", "w");
      allowApp(g, "a1", [host("example.com", "/admin")]);
    },
    expect: [
      ["worker_route:r1", "/administrator*", "public", 2, null],
      ["worker_route:r2", "/admin/users/*", "access", 2, APP("a1")],
    ],
  },
  {
    name: "a wildcard app covers one label, not the apex or deeper hosts",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      g.customDomain("example.com", "w");
      g.customDomain("a.b.example.com", "w");
      allowApp(g, "a1", [host("*.example.com")]);
    },
    expect: [
      [CD("a.b.example.com"), "/", "public", 2, null],
      [CD("app.example.com"), "/", "access", 1, APP("a1")],
      [CD("example.com"), "/", "public", 2, null],
    ],
  },
  {
    name: "an exact host beats a wildcard",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      g.customDomain("other.example.com", "w");
      // `*app` also matches `app` and has as many literal characters.
      bypassApp(g, "aw", [host("*.example.com"), host("*app.example.com")]);
      allowApp(g, "ae", [host("app.example.com")]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 2, APP("ae")],
      [CD("other.example.com"), "/", "public", 1, POLICY("aw-bypass")],
    ],
  },
  {
    name: "a longer path beats a shorter one",
    build: (g) => {
      g.script("w");
      g.customDomain("example.com", "w");
      allowApp(g, "root", [host("example.com")]);
      bypassApp(g, "admin", [host("example.com", "/admin")]);
      allowApp(g, "reports", [host("example.com", "/admin/reports")]);
    },
    expect: [
      [CD("example.com"), "/", "access", 2, APP("root")],
      [CD("example.com"), "/admin", "public", 2, POLICY("admin-bypass")],
      [CD("example.com"), "/admin/reports", "access", 2, APP("reports")],
    ],
  },
  {
    name: "path and label wildcards in app destinations",
    build: (g) => {
      workerEntries(g);
      allowApp(g, "root", [host("app.example.com")]);
      bypassApp(g, "static", [host("app.example.com", "/static/*")]);
      allowApp(g, "previews", [host("*-w.my-subdomain.workers.dev")]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 2, APP("root")],
      [CD("app.example.com"), "/static/*", "public", 2, POLICY("static-bypass")],
      [`worker_preview_url:${PREVIEW}`, "/", "access", 1, APP("previews")],
      ["worker_route:r1", "/", "public", 2, null],
      [`workers_dev:${DEV}`, "/", "public", 2, null],
    ],
  },
  {
    name: "an app path /alpha/* covers the paths below /alpha, not /alpha itself",
    build: (g) => {
      g.script("w");
      g.customDomain("example.com", "w");
      g.route("alpha", "example.com/alpha", "w");
      allowApp(g, "root", [host("example.com")]);
      bypassApp(g, "alpha", [host("example.com", "/alpha/*")]);
    },
    expect: [
      [CD("example.com"), "/", "access", 2, APP("root")],
      [CD("example.com"), "/alpha/*", "public", 2, POLICY("alpha-bypass")],
      ["worker_route:alpha", "/alpha", "access", 2, APP("root")],
      ["worker_route:alpha", "/alpha/*", "public", 2, POLICY("alpha-bypass")],
    ],
  },
  {
    name: "an app path /* covers the whole host",
    build: (g) => {
      g.script("w");
      g.customDomain("example.com", "w");
      bypassApp(g, "all", [host("example.com", "/*")]);
      allowApp(g, "admin", [host("example.com", "/admin")]);
    },
    expect: [
      [CD("example.com"), "/", "public", 2, POLICY("all-bypass")],
      [CD("example.com"), "/admin", "access", 2, APP("admin")],
    ],
  },
  {
    name: "an app path with a trailing slash cannot be placed",
    build: (g) => {
      g.script("w");
      g.customDomain("example.com", "w");
      allowApp(g, "root", [host("example.com")]);
      bypassApp(g, "admin", [host("example.com", "/admin/")]);
    },
    expect: [
      [CD("example.com"), "/", "access", 2, APP("root")],
      [CD("example.com"), "/admin", "unknown", 0, APP("admin")],
    ],
  },
  {
    name: "host and path precedence that select different decisions are unknown",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "host", [host("app.example.com")]);
      bypassApp(g, "path", [host("*.example.com", "/admin")]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 2, APP("host")],
      [CD("app.example.com"), "/admin", "unknown", 0, APP("host")],
    ],
  },
  {
    name: "host and path precedence that agree decide",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "host", [host("app.example.com")]);
      allowApp(g, "path", [host("*.example.com", "/admin")]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 2, APP("host")],
      [CD("app.example.com"), "/admin", "access", 2, APP("host")],
    ],
  },
  {
    name: "apps with the same destination that disagree are unknown",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "a1", [host("app.example.com")]);
      bypassApp(g, "a2", [host("app.example.com")]);
    },
    expect: [[CD("app.example.com"), "/", "unknown", 0, APP("a1")]],
  },
  {
    name: "app paths are placed inside a route's path prefix",
    build: (g) => {
      g.script("w");
      g.route("api", "example.com/api/*", "w");
      g.route("all", "example.com/*", "w");
      allowApp(g, "api", [host("example.com", "/api")]);
      bypassApp(g, "admin", [host("example.com", "/admin")]);
    },
    expect: [
      ["worker_route:all", "/", "public", 2, null],
      ["worker_route:all", "/admin", "public", 2, POLICY("admin-bypass")],
      ["worker_route:all", "/api", "access", 2, APP("api")],
      ["worker_route:api", "/api/*", "access", 2, APP("api")],
    ],
  },
  {
    name: "a wildcard route behind a matching wildcard app",
    build: (g) => {
      g.script("w");
      g.route("r", "*.example.com/*", "w");
      allowApp(g, "a1", [host("*.example.com")]);
    },
    expect: [["worker_route:r", "/", "access", 1, APP("a1")]],
  },
  {
    name: "a wildcard route with only some hosts behind Access is public",
    build: (g) => {
      g.script("w");
      g.route("r", "*.example.com/*", "w");
      allowApp(g, "admin", [host("admin.example.com")]);
    },
    expect: [["worker_route:r", "/", "public", 1, null]],
  },
  {
    name: "a wildcard route with one host bypassed is public",
    build: (g) => {
      g.script("w");
      g.route("r", "*.example.com/*", "w");
      allowApp(g, "all", [host("*.example.com")]);
      bypassApp(g, "status", [host("status.example.com")]);
    },
    expect: [["worker_route:r", "/", "public", 1, POLICY("status-bypass")]],
  },
  {
    name: "a *zone route also serves the apex",
    build: (g) => {
      g.zone("zone-1", "example.com");
      g.script("w");
      g.route("r", "*example.com/*", "w");
      allowApp(g, "sub", [host("*.example.com")]);
    },
    expect: [["worker_route:r", "/", "public", 1, null]],
  },
  {
    name: "a *zone route behind apex and wildcard apps",
    build: (g) => {
      g.zone("zone-1", "example.com");
      g.script("w");
      g.route("r", "*example.com/*", "w");
      allowApp(g, "apex", [host("example.com")]);
      allowApp(g, "sub", [host("*.example.com")]);
    },
    expect: [["worker_route:r", "/", "access", 1, APP("apex")]],
  },
  {
    name: "a *sub route inside the zone also serves hosts ending in sub",
    build: (g) => {
      g.zone("zone-1", "example.com");
      g.script("w");
      g.route("r", "*sub.example.com/*", "w");
      allowApp(g, "sub", [host("sub.example.com"), host("*.sub.example.com")]);
    },
    expect: [["worker_route:r", "/", "public", 1, null]],
  },
  {
    name: "a Pages preview wildcard behind Access",
    build: (g) => {
      g.pages("site", ["www.example.com"]);
      allowApp(g, "previews", [host("*.site.pages.dev")]);
    },
    expect: [
      ["pages_domain:site.pages.dev", "/", "public", 2, null],
      ["pages_domain:www.example.com", "/", "public", 2, null],
      ["pages_preview:*.site.pages.dev", "/", "access", 1, APP("previews")],
    ],
  },

  // Tunnels
  {
    name: "a tunnel hostname behind Access",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      allowApp(g, "ssh", [host("ssh.example.com")]);
    },
    expect: [[TH("ssh.example.com"), "/", "access", 2, APP("ssh")]],
  },
  {
    name: "a tunnel path anchored inside an Access path",
    build: (g) => {
      g.tunnelHostname("web.example.com", "^/admin/", "http://localhost:8080");
      allowApp(g, "admin", [host("web.example.com", "/admin")]);
    },
    expect: [[TH("web.example.com^/admin/"), "/admin/*", "access", 2, APP("admin")]],
  },
  {
    name: "an unanchored tunnel path is read as all paths with lower confidence",
    build: (g) => {
      g.tunnelHostname("img.example.com", "\\.(jpg|png)$", "http://localhost:8080");
      allowApp(g, "private", [host("img.example.com", "/private")]);
    },
    expect: [
      [TH("img.example.com\\.(jpg|png)$"), "/", "public", 1, null],
      [TH("img.example.com\\.(jpg|png)$"), "/private", "access", 1, APP("private")],
    ],
  },
  {
    name: "a wildcard tunnel hostname behind a wildcard app",
    build: (g) => {
      g.tunnelHostname("*.internal.example.com", "", "http://localhost:8080");
      allowApp(g, "internal", [host("*.internal.example.com")]);
    },
    expect: [[TH("*.internal.example.com"), "/", "access", 1, APP("internal")]],
  },
  {
    name: "two tunnels that serve the same hostname are separate entry points",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.tunnelHostname("ssh.example.com", "", "ssh://localhost:22", { tunnelId: "tun-2" });
    },
    expect: [
      [TH("ssh.example.com"), "/", "public", 2, null],
      [TH("ssh.example.com", "tun-2"), "/", "public", 2, null],
    ],
  },
  {
    name: "a tunnel hostname whose cloudflared requires an Access token is never public",
    build: (g) => {
      const required = { accessRequired: true };
      g.tunnelHostname("bare.example.com", "", "http://localhost:8080", required);
      g.tunnelHostname("open.example.com", "", "http://localhost:8080", required);
      g.tunnelHostname("staff.example.com", "", "http://localhost:8080", required);
      g.tunnelHostname("ci.example.com", "", "http://localhost:8080", required);
      g.tunnelHostname("web.example.com", "", "http://localhost:8080", required);
      bypassApp(g, "open", [host("open.example.com")]);
      allowApp(g, "staff", [host("staff.example.com")]);
      g.app("ci", [host("ci.example.com")], [g.policy("ci-token", "non_identity", [TOKEN])]);
      allowApp(g, "web", [host("web.example.com", "", [publicPath("/health")])]);
    },
    expect: [
      [TH("bare.example.com"), "/", "access", 1, TH("bare.example.com")],
      [TH("ci.example.com"), "/", "service_auth", 2, APP("ci")],
      [TH("open.example.com"), "/", "access", 1, TH("open.example.com")],
      [TH("staff.example.com"), "/", "access", 2, APP("staff")],
      [TH("web.example.com"), "/", "access", 2, APP("web")],
      [TH("web.example.com"), "/health", "access", 1, TH("web.example.com")],
    ],
  },
  {
    name: "a tunnel hostname that requires an Access token stays unknown where Access is undecided",
    build: (g) => {
      g.tunnelHostname("ssh.example.com", "", "ssh://localhost:22", { accessRequired: true });
      allowApp(g, "a1", [host("ssh.example.com")]);
      bypassApp(g, "a2", [host("ssh.example.com")]);
    },
    expect: [[TH("ssh.example.com"), "/", "unknown", 0, APP("a1")]],
  },

  // Worker-level Access
  {
    name: "a Worker-level app covers every entry point of its Worker",
    build: (g) => {
      workerEntries(g);
      g.script("v");
      g.customDomain("v.example.com", "v");
      allowApp(g, "w", [worker("w")]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 2, APP("w")],
      [CD("v.example.com"), "/", "public", 2, null],
      [`worker_preview_url:${PREVIEW}`, "/", "access", 2, APP("w")],
      ["worker_route:r1", "/", "access", 2, APP("w")],
      [`workers_dev:${DEV}`, "/", "access", 2, APP("w")],
    ],
  },
  {
    name: "a Worker-level target may name the Worker ID",
    build: (g) => {
      g.script("w", { worker_id: "c81a2d22c29840ed9d61681a3270dbff" });
      g.customDomain("app.example.com", "w");
      allowApp(g, "w", [worker("c81a2d22c29840ed9d61681a3270dbff")]);
    },
    expect: [[CD("app.example.com"), "/", "access", 2, APP("w")]],
  },
  {
    name: "scope previews covers only preview URLs",
    build: (g) => {
      workerEntries(g);
      allowApp(g, "w", [worker("w", "previews")]);
    },
    expect: [
      [CD("app.example.com"), "/", "public", 2, null],
      [`worker_preview_url:${PREVIEW}`, "/", "access", 2, APP("w")],
      ["worker_route:r1", "/", "public", 2, null],
      [`workers_dev:${DEV}`, "/", "public", 2, null],
    ],
  },
  {
    name: "a previews target beats an all-traffic target on preview URLs",
    build: (g) => {
      workerEntries(g);
      allowApp(g, "all", [worker("w")]);
      bypassApp(g, "previews", [worker("w", "previews")]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 2, APP("all")],
      [`worker_preview_url:${PREVIEW}`, "/", "public", 2, POLICY("previews-bypass")],
      ["worker_route:r1", "/", "access", 2, APP("all")],
      [`workers_dev:${DEV}`, "/", "access", 2, APP("all")],
    ],
  },
  {
    name: "hostname and path apps take precedence over Worker-level Access",
    build: (g) => {
      workerEntries(g);
      allowApp(g, "w", [worker("w")]);
      bypassApp(g, "host", [host("app.example.com")]);
      bypassApp(g, "path", [host(DEV, "/admin")]);
    },
    expect: [
      [CD("app.example.com"), "/", "public", 2, POLICY("host-bypass")],
      [`worker_preview_url:${PREVIEW}`, "/", "access", 2, APP("w")],
      ["worker_route:r1", "/", "access", 2, APP("w")],
      [`workers_dev:${DEV}`, "/", "access", 2, APP("w")],
      [`workers_dev:${DEV}`, "/admin", "public", 2, POLICY("path-bypass")],
    ],
  },
  {
    name: "an all_workers destination covers every Worker but not Pages",
    build: (g) => {
      workerEntries(g);
      g.pages("site");
      allowApp(g, "all", [allWorkers()]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 1, APP("all")],
      ["pages_domain:site.pages.dev", "/", "public", 2, null],
      ["pages_preview:*.site.pages.dev", "/", "public", 2, null],
      [`worker_preview_url:${PREVIEW}`, "/", "access", 1, APP("all")],
      ["worker_route:r1", "/", "access", 1, APP("all")],
      [`workers_dev:${DEV}`, "/", "access", 1, APP("all")],
    ],
  },
  {
    name: "a Worker-level bypass beats account-level Access",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      g.script("v");
      g.customDomain("v.example.com", "v");
      allowApp(g, "all", [allWorkers()]);
      bypassApp(g, "public", [worker("w")]);
    },
    expect: [
      [CD("app.example.com"), "/", "public", 2, POLICY("public-bypass")],
      [CD("v.example.com"), "/", "access", 1, APP("all")],
    ],
  },
  {
    name: "all_workers with scope previews covers only preview URLs",
    build: (g) => {
      workerEntries(g);
      allowApp(g, "previews", [allWorkers("previews")]);
    },
    expect: [
      [CD("app.example.com"), "/", "public", 2, null],
      [`worker_preview_url:${PREVIEW}`, "/", "access", 1, APP("previews")],
      ["worker_route:r1", "/", "public", 2, null],
      [`workers_dev:${DEV}`, "/", "public", 2, null],
    ],
  },
  {
    name: "on preview URLs Worker targets beat all_preview_workers, which beats all_workers",
    build: (g) => {
      workerEntries(g);
      g.script("v");
      g.previewUrl(V_PREVIEW, "v", "12345678-0000-4000-8000-000000000000");
      bypassApp(g, "all", [allWorkers()]);
      allowApp(g, "previews", [allWorkers("previews")]);
      bypassApp(g, "w", [worker("w")]);
    },
    expect: [
      [CD("app.example.com"), "/", "public", 2, POLICY("w-bypass")],
      [`worker_preview_url:${PREVIEW}`, "/", "public", 2, POLICY("w-bypass")],
      [`worker_preview_url:${V_PREVIEW}`, "/", "access", 1, APP("previews")],
      ["worker_route:r1", "/", "public", 2, POLICY("w-bypass")],
      [`workers_dev:${DEV}`, "/", "public", 2, POLICY("w-bypass")],
    ],
  },
  {
    name: "two all_workers applications that disagree are unknown",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "a1", [allWorkers()]);
      bypassApp(g, "a2", [allWorkers()]);
    },
    expect: [[CD("app.example.com"), "/", "unknown", 0, APP("a1")]],
  },

  // Policies
  {
    name: "only Service Auth policies yield service_auth",
    build: (g) => {
      g.tunnelHostname("api.example.com", "", "http://localhost:8080");
      g.app("api", [host("api.example.com")], [g.policy("token", "non_identity", [TOKEN])]);
    },
    expect: [[TH("api.example.com"), "/", "service_auth", 2, APP("api")]],
  },
  {
    name: "Service Auth next to an allow policy is access",
    build: (g) => {
      g.tunnelHostname("api.example.com", "", "http://localhost:8080");
      g.app(
        "api",
        [host("api.example.com")],
        [g.policy("token", "non_identity", [TOKEN]), g.policy("staff", "allow", [EMAIL])],
      );
    },
    expect: [[TH("api.example.com"), "/", "access", 2, APP("api")]],
  },
  {
    name: "a bypass limited to an IP range is access",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.app(
        "ssh",
        [host("ssh.example.com")],
        [g.policy("office", "bypass", [{ kind: "ip", value: "192.0.2.0/24" }])],
      );
    },
    expect: [[TH("ssh.example.com"), "/", "access", 2, APP("ssh")]],
  },
  {
    name: "a bypass for everyone narrowed by require rules is still public",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.app(
        "ssh",
        [host("ssh.example.com")],
        [g.policy("geo", "bypass", [EVERYONE], [{ kind: "geo", value: "PT" }])],
      );
    },
    expect: [[TH("ssh.example.com"), "/", "public", 2, POLICY("geo")]],
  },
  {
    name: "a bypass through a group that includes everyone is public",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.group("all", [EVERYONE]);
      g.group("outer", [{ kind: "group", value: "all" }]);
      g.app(
        "ssh",
        [host("ssh.example.com")],
        [g.policy("via-group", "bypass", [{ kind: "group", value: "outer" }])],
      );
    },
    expect: [[TH("ssh.example.com"), "/", "public", 2, POLICY("via-group")]],
  },
  {
    name: "a bypass for everyone wins over an allow policy ordered before it",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.app(
        "ssh",
        [host("ssh.example.com")],
        [g.policy("staff", "allow", [EMAIL]), g.policy("open", "bypass", [EVERYONE])],
      );
    },
    expect: [[TH("ssh.example.com"), "/", "public", 2, POLICY("open")]],
  },
  {
    name: "an allow policy for everyone still requires a login",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.app("ssh", [host("ssh.example.com")], [g.policy("anyone", "allow", [EVERYONE])]);
    },
    expect: [[TH("ssh.example.com"), "/", "access", 2, APP("ssh")]],
  },
  {
    name: "an app without policies denies by default",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.app("ssh", [host("ssh.example.com")]);
    },
    expect: [[TH("ssh.example.com"), "/", "access", 2, APP("ssh")]],
  },
  {
    name: "an unsupported policy action is unknown",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.app("ssh", [host("ssh.example.com")], [g.policy("odd", "isolate", [EVERYONE])]);
    },
    expect: [[TH("ssh.example.com"), "/", "unknown", 0, POLICY("odd")]],
  },
  {
    name: "a bypass that refers to a missing group is unknown",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.app(
        "ssh",
        [host("ssh.example.com")],
        [g.policy("gone", "bypass", [{ kind: "group", value: "deleted" }])],
      );
    },
    expect: [[TH("ssh.example.com"), "/", "unknown", 0, POLICY("gone")]],
  },
  {
    name: "Service Auth that includes everyone is unknown",
    build: (g) => {
      g.tunnelHostname("ssh.example.com");
      g.app("ssh", [host("ssh.example.com")], [g.policy("svc", "non_identity", [EVERYONE])]);
    },
    expect: [[TH("ssh.example.com"), "/", "unknown", 0, POLICY("svc")]],
  },

  // Destination overrides
  {
    name: "a destination override makes a path public",
    build: (g) => {
      workerEntries(g);
      allowApp(g, "host", [host("app.example.com", "", [publicPath("/health")])]);
      allowApp(g, "w", [worker("w", "all", [publicPath("/webhooks/*")])]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 2, APP("host")],
      [CD("app.example.com"), "/health", "public", 2, APP("host")],
      [CD("app.example.com"), "/webhooks/*", "access", 2, APP("host")],
      [`worker_preview_url:${PREVIEW}`, "/", "access", 2, APP("w")],
      [`worker_preview_url:${PREVIEW}`, "/webhooks/*", "public", 2, APP("w")],
      ["worker_route:r1", "/", "access", 2, APP("w")],
      ["worker_route:r1", "/webhooks/*", "public", 2, APP("w")],
      [`workers_dev:${DEV}`, "/", "access", 2, APP("w")],
      [`workers_dev:${DEV}`, "/webhooks/*", "public", 2, APP("w")],
    ],
  },
  {
    name: "an override with an unknown behavior is unknown",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "host", [
        host("app.example.com", "", [{ behavior: "private", path_pattern: "/x" }]),
      ]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 2, APP("host")],
      [CD("app.example.com"), "/x", "unknown", 0, APP("host")],
    ],
  },
  {
    name: "an override on all_workers makes the path public on every Worker",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      g.pages("site");
      allowApp(g, "all", [allWorkers("all", [publicPath("/.well-known/*")])]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 1, APP("all")],
      [CD("app.example.com"), "/.well-known/*", "public", 1, APP("all")],
      ["pages_domain:site.pages.dev", "/", "public", 2, null],
      ["pages_preview:*.site.pages.dev", "/", "public", 2, null],
    ],
  },
  {
    name: "an exact override path is read with its subpaths, erring toward public",
    build: (g) => {
      g.script("w");
      g.route("r1", "example.com/health/live", "w");
      allowApp(g, "host", [host("example.com", "", [publicPath("/health")])]);
    },
    expect: [["worker_route:r1", "/health/live", "public", 2, APP("host")]],
  },
  {
    name: "an override path wildcard that cannot be placed is unknown",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "host", [host("app.example.com", "", [publicPath("/files*/raw")])]);
    },
    expect: [
      [CD("app.example.com"), "/", "access", 2, APP("host")],
      [CD("app.example.com"), "/files*", "unknown", 0, APP("host")],
    ],
  },
  {
    name: "an override of an app that is public anyway stays public",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      bypassApp(g, "open", [
        host("app.example.com", "", [{ behavior: "other", path_pattern: "/x" }]),
      ]);
    },
    expect: [
      [CD("app.example.com"), "/", "public", 2, POLICY("open-bypass")],
      [CD("app.example.com"), "/x", "public", 2, POLICY("open-bypass")],
    ],
  },

  // Unknown
  ...(["partial", "no_permission", "error", null] as const).map(
    (status): Case => ({
      name: `access coverage ${status ?? "missing"} makes every entry point unknown`,
      build: (g) => {
        g.script("w");
        g.customDomain("app.example.com", "w");
        g.route("r1", "example.com/api/*", "w");
        allowApp(g, "a1", [host("app.example.com")]);
      },
      options: { coverage: { access: status } },
      expect: [
        [CD("app.example.com"), "/", "unknown", 0, null],
        ["worker_route:r1", "/api/*", "unknown", 0, null],
      ],
    }),
  ),
  {
    name: "without a current scan every entry point is unknown",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
    },
    options: { noScan: true },
    expect: [[CD("app.example.com"), "/", "unknown", 0, null]],
  },
  {
    name: "an uninterpreted target for the entry point's host is unknown",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      g.customDomain("www.example.org", "w");
      allowApp(g, "odd", [other({ type: "public", uri: "app.example.com/a*b*c" })]);
    },
    expect: [
      [CD("app.example.com"), "/", "unknown", 0, APP("odd")],
      [CD("www.example.org"), "/", "public", 2, null],
    ],
  },
  {
    name: "an uninterpreted target without hosts could apply anywhere",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      g.tunnelHostname("ssh.example.org");
      allowApp(g, "odd", [other({ type: "future_destination" })]);
    },
    expect: [
      [CD("app.example.com"), "/", "unknown", 0, APP("odd")],
      [TH("ssh.example.org"), "/", "unknown", 0, APP("odd")],
    ],
  },
  {
    name: "an uninterpreted target type named like an object property stays uninterpreted",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "odd", [other({ type: "constructor" }), other({ type: "__proto__" })]);
    },
    expect: [[CD("app.example.com"), "/", "unknown", 0, APP("odd")]],
  },
  {
    name: "an uninterpreted Worker target applies to that Worker only",
    build: (g) => {
      g.script("w", { worker_id: "id-w" });
      g.customDomain("app.example.com", "w");
      g.script("v", { worker_id: "id-v" });
      g.customDomain("v.example.com", "v");
      allowApp(g, "odd", [other({ type: "worker", worker_id: "id-w", extra: true })]);
    },
    expect: [
      [CD("app.example.com"), "/", "unknown", 0, APP("odd")],
      [CD("v.example.com"), "/", "public", 2, null],
    ],
  },
  {
    name: "a hostname target that does not parse is not interpretable",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "bad", [host("not a host")]);
    },
    expect: [[CD("app.example.com"), "/", "unknown", 0, APP("bad")]],
  },
  ...[
    { kind: "hostname", host: "app.example.com", path: "" },
    { kind: "hostname", host: "app.example.com", path: null, overrides: [] },
    { kind: "worker", script: "w", scope: "all", overrides: "/x" },
    { kind: "worker", script: "w", scope: "everything", overrides: [] },
    { ...allWorkers(), overrides: [{ behavior: "public" }] },
    { ...allWorkers(), overrides: [{ path_pattern: "/x" }] },
  ].map(
    (target): Case => ({
      name: `a target off the contract's shape is not interpretable: ${JSON.stringify(target)}`,
      build: (g) => {
        g.script("w");
        g.customDomain("app.example.com", "w");
        allowApp(g, "odd", [target]);
      },
      expect: [[CD("app.example.com"), "/", "unknown", 0, APP("odd")]],
    }),
  ),
  {
    name: "an uninterpreted all_workers destination applies to Workers only",
    build: (g) => {
      workerEntries(g);
      g.tunnelHostname("ssh.example.com");
      allowApp(g, "all", [other({ type: "all_workers", overrides: "?" })]);
    },
    expect: [
      [CD("app.example.com"), "/", "unknown", 0, APP("all")],
      [TH("ssh.example.com"), "/", "public", 2, null],
      [`worker_preview_url:${PREVIEW}`, "/", "unknown", 0, APP("all")],
      ["worker_route:r1", "/", "unknown", 0, APP("all")],
      [`workers_dev:${DEV}`, "/", "unknown", 0, APP("all")],
    ],
  },
  {
    name: "an uninterpreted all_preview_workers destination applies to preview URLs only",
    build: (g) => {
      workerEntries(g);
      allowApp(g, "previews", [other({ type: "all_preview_workers", overrides: "?" })]);
    },
    expect: [
      [CD("app.example.com"), "/", "public", 2, null],
      [`worker_preview_url:${PREVIEW}`, "/", "unknown", 0, APP("previews")],
      ["worker_route:r1", "/", "public", 2, null],
      [`workers_dev:${DEV}`, "/", "public", 2, null],
    ],
  },
  {
    name: "a round 1 all_workers target carried as other is not read as one",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      bypassApp(g, "w", [worker("w")]);
      allowApp(g, "all", [other({ type: "all_workers" })]);
    },
    expect: [[CD("app.example.com"), "/", "unknown", 0, APP("all")]],
  },
  {
    name: "private and MCP portal destinations do not protect public entry points",
    build: (g) => {
      g.script("w");
      g.customDomain("app.example.com", "w");
      allowApp(g, "private", [
        { kind: "private", cidr: "10.0.0.0/8", hostname: null, port_range: null },
        other({ type: "via_mcp_server_portal", mcp_server_id: "mcp-1" }),
      ]);
    },
    expect: [[CD("app.example.com"), "/", "public", 2, null]],
  },
  {
    name: "an app path wildcard that cannot be placed is unknown below its literal start",
    build: (g) => {
      g.script("w");
      g.customDomain("example.com", "w");
      allowApp(g, "root", [host("example.com")]);
      bypassApp(g, "odd", [host("example.com", "/foo*/bar")]);
    },
    expect: [
      [CD("example.com"), "/", "access", 2, APP("root")],
      [CD("example.com"), "/foo*", "unknown", 0, APP("odd")],
    ],
  },
  {
    name: "a route pattern that does not parse is unknown",
    build: (g) => {
      g.script("w");
      g.route("r1", "example.com/*.jpg", "w");
      g.route("r2", "a.*.example.com/*", "w");
    },
    expect: [
      ["worker_route:r1", "/", "unknown", 0, null],
      ["worker_route:r2", "/", "unknown", 0, null],
    ],
  },
];

describe("evaluateExposure", () => {
  it.each(cases)("$name", async (c) => {
    const g = new Graph();
    c.build(g);
    const db = await load(g, c.options);
    try {
      const rows = evaluateExposure(db);
      expect(summarize(rows)).toEqual(sorted(c.expect));
      for (const row of rows) expect(row.reason).toMatch(/\S/);
    } finally {
      db.close();
    }
  });
});

describe("evaluateExposure as a step", () => {
  afterEach(() => vi.restoreAllMocks());

  async function sample() {
    const g = new Graph();
    workerEntries(g);
    g.pages("site");
    g.tunnelHostname("ssh.example.com");
    allowApp(g, "w", [worker("w")]);
    bypassApp(g, "admin", [host("app.example.com", "/admin")]);
    allowApp(g, "ssh", [host("ssh.example.com")]);
    return load(g);
  }

  it("reads only: no writes and no clock", async () => {
    const db = await sample();
    try {
      const changes = rowCount(db, "changes");
      vi.spyOn(Date, "now").mockImplementation(() => {
        throw new Error("evaluateExposure must not read the clock");
      });
      const rows = evaluateExposure(db);
      expect(rows.length).toBeGreaterThan(0);
      expect(rowCount(db, "changes")).toBe(changes);
      expect(rowCount(db, "exposure")).toBe(0);
    } finally {
      db.close();
    }
  });

  it("is deterministic and its rows fit the exposure table", async () => {
    const db = await sample();
    try {
      const rows = evaluateExposure(db);
      expect(evaluateExposure(db)).toEqual(rows);
      replaceExposure(db, rows, 2);
      expect(rowCount(db, "exposure")).toBe(rows.length);
    } finally {
      db.close();
    }
  });

  it("ignores tombstoned apps and policy links", async () => {
    const db = await sample();
    try {
      db.run("UPDATE nodes SET deleted_at = 3 WHERE id = 'access_app:w'");
      db.run("UPDATE edges SET deleted_at = 3 WHERE type = 'ALLOWS' AND dst = 'access_app:ssh'");
      const rows = summarize(evaluateExposure(db));
      expect(rows).toContainEqual(["worker_route:r1", "/", "public", 2, null]);
      expect(rows).toContainEqual([TH("ssh.example.com"), "/", "access", 2, APP("ssh")]);
    } finally {
      db.close();
    }
  });
});
