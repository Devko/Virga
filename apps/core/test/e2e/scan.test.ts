import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { createReader } from "@virga/cf-api";
import { fixtureTransport } from "@virga/cf-api/testing";
import { COLLECTORS, RESOURCE_CLASSES } from "@virga/collectors";
import { evaluateExposure } from "@virga/exposure";
import { sha256 } from "@virga/graph";
import { evaluateRules, RULES } from "@virga/rules";
import { beforeAll, describe, expect, it } from "vitest";
import type { AccountGraph } from "../../src/account-graph.ts";
import { d1ScanIndex, upsertAccount } from "../../src/index-db.ts";
import { runScan } from "../../src/scan/run.ts";
import type { ScanSummary } from "../../src/scan/types.ts";
import { fakeStep } from "../fake-step.ts";
import { type GraphStub, graphOf, newAccountId, scanRun, sql } from "../helpers.ts";
import {
  type AccountState,
  CLEAN,
  EXPOSURE,
  FLOOD_HOSTNAMES,
  fakeAccount,
  initialState,
  LONG_PATH,
  LONG_PATH_SHA256,
  NOW,
  R2_DEV_HOST,
  type Routes,
  SECRET_VALUES,
  SEEDED,
  TUNNEL_EDGE,
  tunnelHostname,
} from "./account.ts";

// A full scan of a fake account: the real collectors over fixtureTransport,
// the real scan orchestration (runScan), and an AccountGraph Durable Object
// running the real exposure evaluator and findings lifecycle over all rules.
// Six scans: the seeded account, the same account unchanged, the account
// whose r2.dev flag on one bucket and env vars of one Pages project cannot be
// read, the account with r2.dev turned off on that bucket, the account with
// 1,000 harmless ingress rules before the edge tunnel's own rules, which then
// fall past the cap, and the account with those rules gone again (decision
// 0005).
//
// A case marked `mismatch` in account.ts fails because two packages disagree
// on the graph contract; it runs as `it.fails` until the mismatch is fixed.

const DAY = 86_400_000;

interface FindingRow {
  fingerprint: string;
  rule_id: string;
  severity: string;
  status: string;
  evidence: string;
  first_seen: number;
  resolved_at: number | null;
}

interface ExposureDbRow {
  entry_id: string;
  path_prefix: string;
  decision: string;
  confidence: number;
  reason_id: string | null;
  reason: string | null;
}

interface TunnelRow {
  id: string;
  type: string;
  /** `tunnel_id` of a tunnel hostname. */
  tunnel: string | null;
  /** `ingress_truncated` of a tunnel. */
  truncated: number | null;
  seen_scan: string;
  deleted_at: number | null;
}

interface Snapshot {
  scanId: string;
  summary: ScanSummary;
  /** Tunnel and tunnel hostname nodes after the scan, tombstones too. */
  tunnels: TunnelRow[];
  coverage: { resource_class: string; status: string; detail: string | null }[];
  ruleRuns: {
    rule_id: string;
    status: string;
    hits: number;
    undecided: number;
    missing: string | null;
    error: string | null;
  }[];
  findings: FindingRow[];
  subjects: Map<string, string>;
  exposure: ExposureDbRow[];
  /** Every API call of the scan, as `GET /path?query` or `POST /graphql`. */
  calls: string[];
  /** Paths the collectors read that the fake account does not serve. */
  unserved: string[];
  /** The JSON of every step result: what the Workflow engine would keep. */
  stepResults: string;
}

let accountId: string;
let stub: GraphStub;
let state: AccountState;
let first: Snapshot;
let second: Snapshot;
let unreadable: Snapshot;
let third: Snapshot;
let fourth: Snapshot;
let fifth: Snapshot;

async function scan(name: string, now: number): Promise<Snapshot> {
  const scanId = `${name}-${accountId}`;
  const calls: string[] = [];
  const unserved: string[] = [];
  const transports: { routes: Routes; calls: string[] }[] = [];
  const steps = fakeStep();
  const summary = await runScan(
    {
      step: steps.step,
      graph: () => stub,
      index: d1ScanIndex(env.INDEX),
      reader: (id) => {
        const { routes, graphql } = fakeAccount(id, state);
        const transport = fixtureTransport(routes, { graphql });
        transports.push({ routes, calls: transport.calls });
        return createReader(transport);
      },
      // The production default, so the scan runs every phase 1 collector.
      collectors: COLLECTORS,
      clock: () => now + 60_000,
    },
    { accountId, scanId, now },
  );
  for (const t of transports) {
    for (const call of t.calls) {
      calls.push(call);
      const path = call.replace(/^GET /, "").split("?")[0] ?? "";
      if (call.startsWith("GET ") && !(path in t.routes)) unserved.push(path);
    }
  }
  const subjects = new Map(
    (
      await sql<{ fingerprint: string; node_id: string }>(
        stub,
        "SELECT fingerprint, node_id FROM finding_nodes WHERE role = 'subject'",
      )
    ).map((r) => [r.fingerprint, r.node_id]),
  );
  return {
    scanId,
    summary,
    tunnels: await sql<TunnelRow>(
      stub,
      `SELECT id, type, props ->> '$.tunnel_id' AS tunnel,
              props ->> '$.ingress_truncated' AS truncated, seen_scan, deleted_at
       FROM nodes WHERE type IN ('tunnel', 'tunnel_hostname') ORDER BY id`,
    ),
    coverage: await sql(
      stub,
      `SELECT resource_class, status, detail FROM coverage WHERE scan_id = ?
       ORDER BY resource_class`,
      scanId,
    ),
    ruleRuns: await sql(
      stub,
      `SELECT rule_id, status, hits, undecided, missing, error FROM rule_runs WHERE scan_id = ?
       ORDER BY rule_id`,
      scanId,
    ),
    findings: await sql<FindingRow>(
      stub,
      `SELECT fingerprint, rule_id, severity, status, evidence, first_seen, resolved_at
       FROM findings ORDER BY fingerprint`,
    ),
    subjects,
    exposure: await sql<ExposureDbRow>(
      stub,
      `SELECT entry_id, path_prefix, decision, confidence, reason_id, reason FROM exposure
       ORDER BY entry_id, path_prefix`,
    ),
    calls,
    unserved: [...new Set(unserved)].sort(),
    stepResults: JSON.stringify(steps.records.map((r) => r.result ?? null)),
  };
}

const byFingerprint = (snapshot: Snapshot, fingerprint: string) =>
  snapshot.findings.find((f) => f.fingerprint === fingerprint);

beforeAll(async () => {
  accountId = newAccountId();
  state = initialState();
  await upsertAccount(env.INDEX, { id: accountId, name: "Fake account" }, NOW);
  stub = graphOf(accountId);
  await runInDurableObject(stub, (graph: AccountGraph) => {
    graph.evaluators = { exposure: evaluateExposure, rules: evaluateRules, ruleSet: RULES };
  });

  first = await scan("seeded", NOW);
  second = await scan("unchanged", NOW + DAY);
  state.publicAssetsR2Dev = null;
  state.handbookEnvVars = false;
  unreadable = await scan("unreadable", NOW + DAY + DAY / 2);
  state.handbookEnvVars = true;
  state.publicAssetsR2Dev = false;
  third = await scan("r2-dev-off", NOW + 2 * DAY);
  state.edgeIngressFlood = true;
  fourth = await scan("ingress-flood", NOW + 3 * DAY);
  state.edgeIngressFlood = false;
  fifth = await scan("ingress-fits", NOW + 4 * DAY);
}, 60_000);

const ALL = () => [first, second, unreadable, third, fourth, fifth];

describe("every scan", () => {
  it("seeds cases and clean counterparts for every phase 1 rule but CF-001", () => {
    const phase1 = RULES.map((r) => r.id)
      .filter((id) => id !== "CF-001")
      .sort();
    expect([...new Set(SEEDED.map((c) => c.rule))].sort()).toEqual(phase1);
    expect([...new Set(CLEAN.map((c) => c.rule))].sort()).toEqual(phase1);
  });

  it("only reads, and only paths that the fake account serves", () => {
    for (const s of ALL()) {
      expect(s.calls.length, s.scanId).toBeGreaterThan(0);
      for (const call of s.calls) expect(call).toMatch(/^(GET \/|POST \/graphql$)/);
      expect(s.calls).toContain("POST /graphql");
      expect(s.unserved, s.scanId).toEqual([]);
    }
  });

  it("keeps secret values out of the graph and the step results", async () => {
    // Durable Object SQL allows few terms in a compound SELECT: one query per table.
    const columns = [
      "id || name || props FROM nodes",
      "id || props FROM edges",
      "evidence FROM findings",
      "payload FROM insights",
      "COALESCE(before, '') || COALESCE(after, '') FROM changes",
      "node_id || COALESCE(value, '') FROM signals",
      "reason FROM exposure",
    ];
    const stored: string[] = [];
    for (const column of columns) {
      const rows = await sql<{ text: string | null }>(
        stub,
        `SELECT ${column.replace(" FROM", " AS text FROM")}`,
      );
      stored.push(...rows.map((r) => r.text ?? ""));
    }
    const steps = ALL()
      .map((s) => s.stepResults)
      .join("\n");
    for (const secret of SECRET_VALUES) {
      expect(stored.filter((text) => text.includes(secret))).toEqual([]);
      expect(steps.includes(secret)).toBe(false);
    }
  });
});

describe("first scan of the seeded account", () => {
  it("completes every phase 1 class and the exposure step", async () => {
    expect(first.summary.status).toBe("complete");
    expect(first.coverage).toEqual(
      [...RESOURCE_CLASSES, "exposure"]
        .sort()
        .map((resource_class) => ({ resource_class, status: "complete", detail: null })),
    );
    expect(Object.keys(first.summary.classes).sort()).toEqual([...RESOURCE_CLASSES].sort());
    expect((await scanRun(first.scanId))?.status).toBe("complete");
  });

  it("R5-04: emits tunnel hostname IDs in the form of the graph contract", async () => {
    const rows = await sql<{ id: string; hostname: string; path: string; tunnel: string }>(
      stub,
      `SELECT id, props ->> '$.hostname' AS hostname, props ->> '$.path' AS path,
              props ->> '$.tunnel_id' AS tunnel
       FROM nodes WHERE type = 'tunnel_hostname' AND deleted_at IS NULL ORDER BY id`,
    );
    // The graph is read after every scan: the fifth swept the flood of the fourth.
    expect(rows.filter((r) => /^f\d{4}\.example\.com$/.test(r.hostname))).toEqual([]);
    expect(rows.map((r) => r.hostname).sort()).toEqual([
      "app.example.com",
      "dash.example.com",
      "dash.example.com",
      "git.example.com",
      "kb.example.com",
      "kb.example.com",
      "lab.example.com",
      "lab.example.com",
      "ops.example.com",
      "ops.example.com",
      "ssh",
      "ssh.example.com",
      "vault.example.com",
      "wiki.example.com",
    ]);
    for (const r of rows) {
      const id = tunnelHostname(r.tunnel, r.hostname, r.path);
      const long = id.length - "tunnel_hostname:".length > 512;
      const path = long ? `sha256:${await sha256(r.path)}` : r.path;
      expect(r.id).toBe(tunnelHostname(r.tunnel, r.hostname, path));
    }
  });

  it("R5-05: keeps a path-only rule whose node ID is over 512 characters", async () => {
    expect(await sha256(LONG_PATH)).toBe(LONG_PATH_SHA256);
    const [row] = await sql<{ path: string }>(
      stub,
      "SELECT props ->> '$.path' AS path FROM nodes WHERE native_id LIKE '%:sha256:%'",
    );
    expect(row?.path).toBe(LONG_PATH);
  });

  it("R3-02: emits an entry point per hostname for ingress rules without a hostname", async () => {
    const rows = await sql<{ entry: string; via_fallthrough: number; access_required: number }>(
      stub,
      `SELECT (props ->> '$.hostname') || (props ->> '$.path') AS entry,
              props ->> '$.via_fallthrough' AS via_fallthrough,
              props ->> '$.access_required' AS access_required
       FROM nodes WHERE type = 'tunnel_hostname' AND deleted_at IS NULL ORDER BY entry`,
    );
    // The catch-all of the ops tunnel does not reach vault.example.com, whose
    // rule takes every path; catch-alls with a status code yield nothing.
    expect(rows.filter((r) => r.via_fallthrough === 1)).toEqual([
      { entry: "dash.example.com^/debug", via_fallthrough: 1, access_required: 0 },
      { entry: "kb.example.com^/debug", via_fallthrough: 1, access_required: 0 },
      { entry: `lab.example.com${LONG_PATH}`, via_fallthrough: 1, access_required: 0 },
      { entry: "ops.example.com", via_fallthrough: 1, access_required: 0 },
    ]);
    expect(rows.filter((r) => r.via_fallthrough !== 1).every((r) => r.via_fallthrough === 0)).toBe(
      true,
    );
  });

  describe("exposure", () => {
    for (const e of EXPOSURE) {
      const test = e.mismatch ? it.fails : it;
      test(`${e.case}: ${e.entry}`, () => {
        const rows = first.exposure
          .filter((r) => r.entry_id === e.entry)
          .map(({ entry_id, reason, ...rest }) => rest);
        expect(rows).toEqual(e.rows);
      });
    }

    it("decides every entry point", () => {
      expect(first.exposure.length).toBeGreaterThan(EXPOSURE.length);
      expect(first.exposure.filter((r) => r.decision === "unknown")).toEqual([]);
    });
  });

  describe("rules", () => {
    it("leaves CF-001 not evaluated: packages and vulns do not exist yet", () => {
      expect(first.ruleRuns.find((r) => r.rule_id === "CF-001")).toEqual({
        rule_id: "CF-001",
        status: "not_evaluated",
        hits: 0,
        undecided: 0,
        missing: JSON.stringify(["packages", "vulns"]),
        error: null,
      });
      expect(first.findings.filter((f) => f.rule_id === "CF-001")).toEqual([]);
    });

    it("evaluates every other rule", () => {
      expect(first.ruleRuns.map((r) => r.rule_id)).toEqual(RULES.map((r) => r.id).sort());
      expect(first.ruleRuns.filter((r) => r.rule_id !== "CF-001")).toEqual(
        RULES.filter((r) => r.id !== "CF-001")
          .map((r) => r.id)
          .sort()
          .map((rule_id) => ({
            rule_id,
            status: "evaluated",
            hits: expect.any(Number),
            // Every entry point is decided, so no rule has an undecided row.
            undecided: 0,
            missing: null,
            error: null,
          })),
      );
      expect(first.summary.rules).toMatchObject({
        status: "complete",
        rules: RULES.length,
        notEvaluated: 1,
        errors: 0,
        undecided: 0,
      });
    });
  });

  describe("findings for the seeded cases", () => {
    for (const c of SEEDED) {
      const test = c.mismatch ? it.fails : it;
      test(`${c.rule}: ${c.case}`, () => {
        const finding = byFingerprint(first, c.fingerprint);
        expect(finding).toMatchObject({ rule_id: c.rule, severity: c.severity, status: "open" });
      });
    }

    it("CF-024: names the Pages env var, its environment and pattern, never its value", () => {
      const fingerprint = "CF-024:pages_project:handbook";
      expect(first.subjects.get(fingerprint)).toBe("pages_project:handbook");
      expect(JSON.parse(byFingerprint(first, fingerprint)?.evidence ?? "{}")).toEqual({
        variables: [
          {
            environment: "production",
            name: "CF_API_TOKEN",
            kind: "plain_text",
            secret_pattern: "cfat_",
          },
        ],
        patterns: ["cfat_"],
        versions: null,
      });
    });

    it("reports nothing beyond the seeded cases", () => {
      const expected = new Set(SEEDED.map((c) => c.fingerprint));
      expect(first.findings.map((f) => f.fingerprint).filter((f) => !expected.has(f))).toEqual([]);
    });
  });

  describe("no findings for the clean counterparts", () => {
    it("has every clean subject in the graph", async () => {
      const ids = CLEAN.map((c) => c.subject);
      const found = await sql<{ id: string }>(
        stub,
        "SELECT id FROM nodes WHERE deleted_at IS NULL AND id IN (SELECT value FROM json_each(?))",
        JSON.stringify(ids),
      );
      expect(found.map((r) => r.id).sort()).toEqual([...new Set(ids)].sort());
    });

    it("CF-024: inspects the plain-text env vars of a clean Pages project and skips its secret env var", async () => {
      const [row] = await sql<{ vars: string }>(
        stub,
        "SELECT props ->> '$.plain_text_vars' AS vars FROM nodes WHERE id = 'pages_project:landing'",
      );
      const url = {
        name: "API_BASE",
        kind: "plain_text",
        looks_secret: false,
        secret_pattern: null,
      };
      expect(JSON.parse(row?.vars ?? "null")).toEqual([
        { ...url, environment: "preview" },
        { ...url, environment: "production" },
      ]);
    });

    for (const c of CLEAN) {
      it(`${c.rule}: ${c.case}`, () => {
        const hits = first.findings.filter(
          (f) => f.rule_id === c.rule && first.subjects.get(f.fingerprint) === c.subject,
        );
        expect(hits).toEqual([]);
      });
    }
  });
});

describe("second scan of the unchanged account", () => {
  it("changes no graph row", () => {
    expect(second.summary.status).toBe("complete");
    for (const [cls, result] of Object.entries(second.summary.classes)) {
      expect(result, cls).toMatchObject({ status: "complete", changed: 0 });
    }
    expect(second.exposure).toEqual(first.exposure);
    // Collectors are deterministic for an unchanged account.
    expect(second.calls).toEqual(first.calls);
  });

  it("changes no finding", () => {
    expect(second.summary.rules).toMatchObject({ opened: 0, resolved: 0 });
    expect(second.findings).toEqual(first.findings);
    expect(second.ruleRuns).toEqual(first.ruleRuns);
  });
});

describe("scan after the r2.dev flag and the handbook env vars can no longer be read", () => {
  const fingerprint = "CF-021:r2_bucket:public-assets";
  const entry = `r2_public_domain:${R2_DEV_HOST}`;

  it("R4-02: keeps the r2.dev entry point and decides it unknown", () => {
    expect(unreadable.summary.classes.storage).toMatchObject({ status: "complete", changed: 1 });
    expect(unreadable.exposure.filter((r) => r.entry_id === entry)).toEqual([
      {
        entry_id: entry,
        path_prefix: "/",
        decision: "unknown",
        confidence: 0,
        reason_id: null,
        reason: expect.any(String),
      },
    ]);
  });

  it("R4-02: leaves the open CF-021 finding open as undecided", () => {
    expect(unreadable.ruleRuns.find((r) => r.rule_id === "CF-021")).toMatchObject({
      status: "evaluated",
      hits: 0,
      undecided: 1,
    });
    expect(unreadable.summary.rules).toMatchObject({ opened: 0, resolved: 0 });
    expect(byFingerprint(unreadable, fingerprint)).toMatchObject({ status: "open" });
    expect(unreadable.findings).toEqual(second.findings);
  });

  it("R5-07: leaves the open Pages finding of CF-024 open as undecided", () => {
    // The Worker finding (mailer) is still decided; handbook is undecided.
    expect(unreadable.ruleRuns.find((r) => r.rule_id === "CF-024")).toMatchObject({
      status: "evaluated",
      hits: 1,
      undecided: 1,
    });
    expect(byFingerprint(unreadable, "CF-024:pages_project:handbook")).toMatchObject({
      status: "open",
    });
  });
});

describe("third scan, after r2.dev is turned off on public-assets", () => {
  const fingerprint = "CF-021:r2_bucket:public-assets";

  it("resolves the CF-021 finding", () => {
    expect(third.summary.rules).toMatchObject({ opened: 0, resolved: 1 });
    const finding = byFingerprint(third, fingerprint);
    expect(finding).toMatchObject({ status: "resolved", severity: "high" });
    expect(finding?.resolved_at).toEqual(expect.any(Number));
  });

  it("keeps every other finding as it was", () => {
    const others = (s: Snapshot) => s.findings.filter((f) => f.fingerprint !== fingerprint);
    expect(others(third)).toEqual(others(second));
  });

  it("tombstones the r2.dev entry point and drops its exposure", async () => {
    expect(third.summary.classes.storage).toMatchObject({
      status: "complete",
      swept: { nodes: 1, edges: 1 },
    });
    const [node] = await sql<{ deleted_at: number | null }>(
      stub,
      "SELECT deleted_at FROM nodes WHERE id = ?",
      `r2_public_domain:${R2_DEV_HOST}`,
    );
    expect(node?.deleted_at).toEqual(expect.any(Number));
    expect(third.exposure).toEqual(
      first.exposure.filter((r) => r.entry_id !== `r2_public_domain:${R2_DEV_HOST}`),
    );
  });
});

// Decision 0005, in three scans: the third has an exposed SSH entry point on
// the edge tunnel with an open CF-004 finding; the fourth puts 1,000 harmless
// rules before it, so it falls past the cap; the fifth has them gone again.
const TUNNEL_RULES = ["CF-004", "CF-010", "CF-011"];
const edge = `tunnel:${TUNNEL_EDGE}`;
const ssh = tunnelHostname(TUNNEL_EDGE, "ssh.example.com");
const flood = (r: TunnelRow) => /^tunnel_hostname:[^:]+:f\d{4}\.example\.com:$/.test(r.id);
const edgeEntries = (s: Snapshot) =>
  s.tunnels.filter((r) => r.type === "tunnel_hostname" && r.tunnel === TUNNEL_EDGE);
const live = (rows: TunnelRow[]) => rows.filter((r) => r.deleted_at === null).map((r) => r.id);
const tunnelNode = (s: Snapshot, id: string) => s.tunnels.find((r) => r.id === id);

describe("fourth scan, after 1,000 harmless rules push the edge tunnel's own rules past the cap", () => {
  const reason = `truncated (1): tunnel ${TUNNEL_EDGE}: ingress has more than 1000 entry points`;

  it("R5-06: emits the 1,000 harmless entry points and marks the tunnel", () => {
    expect(tunnelNode(fourth, edge)?.truncated).toBe(1);
    const seen = edgeEntries(fourth).filter((r) => r.seen_scan === fourth.scanId);
    expect(seen).toHaveLength(FLOOD_HOSTNAMES);
    expect(seen.every(flood)).toBe(true);
    const others = fourth.tunnels.filter((r) => r.type === "tunnel" && r.id !== edge);
    expect(others.map((t) => t.truncated)).toEqual(others.map(() => 0));
  });

  it("0005: records tunnels coverage partial with the reason and ends the scan partial", async () => {
    expect(fourth.summary.status).toBe("partial");
    expect((await scanRun(fourth.scanId))?.status).toBe("partial");
    const tunnels = fourth.summary.classes.tunnels;
    expect(tunnels).toMatchObject({ status: "partial", truncated: 1, detail: reason });
    // Every chunk was written; collection did not stop at the truncated one.
    expect(tunnels?.done).toBe(tunnels?.chunks);
    expect(fourth.coverage).toEqual(
      [...RESOURCE_CLASSES, "exposure"]
        .sort()
        .map((resource_class) =>
          resource_class === "tunnels"
            ? { resource_class, status: "partial", detail: reason }
            : { resource_class, status: "complete", detail: null },
        ),
    );
  });

  it("0005: does not sweep tunnels, so the entry point past the cap stays", () => {
    expect(fourth.summary.classes.tunnels?.swept).toBeUndefined();
    expect(tunnelNode(fourth, ssh)).toMatchObject({ deleted_at: null, seen_scan: third.scanId });
    // Every entry point of the third scan is still there, next to the flood.
    const before = live(third.tunnels);
    expect(live(fourth.tunnels).filter((id) => before.includes(id))).toEqual(before);
    expect(live(edgeEntries(fourth))).toHaveLength(FLOOD_HOSTNAMES + 3);
  });

  it("0005: leaves CF-004, CF-010 and CF-011 not evaluated and evaluates the other rules", () => {
    expect(fourth.ruleRuns.filter((r) => TUNNEL_RULES.includes(r.rule_id))).toEqual(
      TUNNEL_RULES.map((rule_id) => ({
        rule_id,
        status: "not_evaluated",
        hits: 0,
        undecided: 0,
        missing: JSON.stringify(["tunnels"]),
        error: null,
      })),
    );
    expect(fourth.ruleRuns.filter((r) => !TUNNEL_RULES.includes(r.rule_id))).toEqual(
      third.ruleRuns.filter((r) => !TUNNEL_RULES.includes(r.rule_id)),
    );
    expect(fourth.summary.rules).toMatchObject({ status: "complete", notEvaluated: 4 });
  });

  it("0005: keeps the open CF-004 finding of the SSH hostname open and changes no finding", () => {
    expect(fourth.summary.rules).toMatchObject({ opened: 0, resolved: 0 });
    expect(byFingerprint(fourth, `CF-004:${ssh}`)).toMatchObject({ status: "open" });
    expect(fourth.findings).toEqual(third.findings);
  });

  it("R5-06: decides every entry point of the truncated tunnel unknown, and the others as before", () => {
    const entries = new Set(live(edgeEntries(fourth)));
    const ofEdge = fourth.exposure.filter((r) => entries.has(r.entry_id));
    expect(new Set(ofEdge.map((r) => r.entry_id))).toEqual(entries);
    for (const r of ofEdge) {
      expect(r).toMatchObject({ decision: "unknown", confidence: 0, reason_id: edge });
    }
    expect(fourth.exposure.filter((r) => !entries.has(r.entry_id))).toEqual(
      third.exposure.filter((r) => !entries.has(r.entry_id)),
    );
  });
});

describe("fifth scan, after the harmless rules are gone again", () => {
  it("0005: completes every class and the scan again", async () => {
    expect(fifth.summary.status).toBe("complete");
    expect((await scanRun(fifth.scanId))?.status).toBe("complete");
    expect(fifth.coverage).toEqual(third.coverage);
    expect(fifth.calls).toEqual(third.calls);
  });

  it("0005: sweeps the harmless entry points and keeps the tunnel's own", () => {
    expect(fifth.summary.classes.tunnels).toMatchObject({
      status: "complete",
      swept: { nodes: FLOOD_HOSTNAMES, edges: FLOOD_HOSTNAMES },
    });
    expect(tunnelNode(fifth, edge)?.truncated).toBe(0);
    expect(tunnelNode(fifth, ssh)).toMatchObject({ deleted_at: null, seen_scan: fifth.scanId });
    expect(live(fifth.tunnels)).toEqual(live(third.tunnels));
    expect(
      edgeEntries(fifth)
        .filter((r) => r.deleted_at !== null)
        .every(flood),
    ).toBe(true);
  });

  it("0005: evaluates the tunnel rules again, with the findings of the third scan", () => {
    expect(fifth.ruleRuns).toEqual(third.ruleRuns);
    expect(fifth.summary.rules).toMatchObject({ opened: 0, resolved: 0, notEvaluated: 1 });
    expect(byFingerprint(fifth, `CF-004:${ssh}`)).toMatchObject({ status: "open" });
    expect(fifth.findings).toEqual(third.findings);
    expect(fifth.exposure).toEqual(third.exposure);
  });
});
