import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EXPORT_CHUNK, EXPORT_MAX, EXPORT_MAX_BYTES } from "../src/export.ts";
import { CSP } from "../src/http.ts";
import {
  detectionFinding,
  MAX_EVIDENCE_BYTES,
  OCSF_VERSION,
  UNTRUSTED_PATHS,
} from "../src/ocsf.ts";
import type { FindingSeverity, FindingStatus, FindingView } from "../src/rpc.ts";
import { ADMIN, ORIGIN, VIEWER } from "./config.ts";
import {
  ACCOUNT,
  BIG_ACCOUNT,
  EMPTY_ACCOUNT,
  exportFindings,
  finding,
  findings,
  HOSTILE,
  HOSTILE_ACCOUNT,
  hostileFinding,
  INVISIBLE,
  MANY_ACCOUNT,
  UNKNOWN_ACCOUNT,
} from "./fixtures.ts";
import { call, serveCerts, signer, tokenFor } from "./helpers.ts";
import { calls } from "./worker.ts";

type OcsfRecord = Record<string, unknown> & {
  finding_info: Record<string, unknown>;
  metadata: Record<string, unknown>;
  unmapped: { virga: Record<string, unknown> };
};

let viewer: string;
let admin: string;

beforeEach(async () => {
  serveCerts(await signer());
  viewer = await tokenFor(VIEWER);
  admin = await tokenFor(ADMIN);
  calls.length = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
});

const exportPath = (accountId: string, query = "") =>
  `/api/accounts/${accountId}/findings/export${query === "" ? "" : `?${query}`}`;

const download = (path: string, headers: Record<string, string> = {}, token = viewer) =>
  call(path, { token, headers });

/** The body as UTF-8; workerd warns when `text()` reads a type it does not know as text. */
const bodyText = async (response: Response) =>
  new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(await response.arrayBuffer());

async function records(response: Response): Promise<OcsfRecord[]> {
  expect(response.status).toBe(200);
  return (await response.json()) as OcsfRecord[];
}

/** The `rel="next"` URL of a response, or null. */
const nextLink = (response: Response) =>
  /^<(\/api\/[^>]+)>; rel="next"$/.exec(response.headers.get("link") ?? "")?.[1] ?? null;

/** Follows `rel="next"` links from `path` and returns every record and response size. */
async function exportAll(path: string) {
  const all: OcsfRecord[] = [];
  const sizes: number[] = [];
  for (let next: string | null = path; next !== null; ) {
    const response = await download(next);
    const text = await bodyText(response.clone());
    sizes.push(new TextEncoder().encode(text).length);
    all.push(...(await records(response)));
    next = nextLink(response);
  }
  return { all, sizes };
}

describe("OCSF export", () => {
  it("serves the findings as OCSF Detection Findings for download", async () => {
    const response = await download(exportPath(ACCOUNT));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("content-disposition")).toBe(
      `attachment; filename="virga-findings-${ACCOUNT}.ocsf.json"`,
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("content-security-policy")).toBe(CSP);
    expect(response.headers.get("virga-export-count")).toBe("2");
    expect(response.headers.get("link")).toBeNull();

    const [first, second] = await records(response);
    const f = findings[0] as FindingView;
    expect(first).toEqual({
      metadata: {
        version: OCSF_VERSION,
        product: { name: "Virga", vendor_name: "Virga" },
        profiles: ["cloud"],
      },
      category_uid: 2,
      category_name: "Findings",
      class_uid: 2004,
      class_name: "Detection Finding",
      activity_id: 2,
      activity_name: "Update",
      type_uid: 200402,
      type_name: "Detection Finding: Update",
      severity_id: 5,
      severity: "Critical",
      status_id: 1,
      status: "New",
      status_code: "open",
      time: f.firstSeen,
      message: f.title,
      is_alert: true,
      finding_info: {
        uid: "CF-001:worker_script:api",
        title: f.title,
        analytic: { uid: "CF-001", name: f.title, type_id: 1, type: "Rule", version: "1" },
        created_time: f.firstSeen,
        first_seen_time: f.firstSeen,
        last_seen_time: f.lastSeen,
        modified_time: f.lastSeen,
      },
      cloud: {
        provider: "Cloudflare",
        account: { uid: ACCOUNT, type_id: 99, type: "Cloudflare Account" },
      },
      resources: [{ uid: "worker_script:api", type: "worker_script", role_id: 1, role: "Target" }],
      evidences: [{ data: { hosts: ["api.example.com"] } }],
      unmapped: { virga: { untrusted: [...UNTRUSTED_PATHS] } },
    });
    expect(OCSF_VERSION).toBe("1.9.0");
    expect(second?.finding_info.uid).toBe(findings[1]?.fingerprint);
    expect(second?.evidences).toEqual([{ data: findings[1]?.evidence }]);
    expect(calls).toEqual([{ method: "listFindings", args: [ACCOUNT, { limit: EXPORT_CHUNK }] }]);
  });

  it("maps every severity and status", () => {
    const severities: [FindingSeverity, number, string][] = [
      ["critical", 5, "Critical"],
      ["high", 4, "High"],
      ["medium", 3, "Medium"],
      ["low", 2, "Low"],
      ["info", 1, "Informational"],
    ];
    const statuses: [FindingStatus, number, string, boolean][] = [
      ["open", 1, "New", true],
      ["suppressed", 3, "Suppressed", false],
      ["resolved", 4, "Resolved", false],
    ];
    const seen = Date.UTC(2026, 9, 2);
    for (const [severity, severityId, severityName] of severities) {
      for (const [status, statusId, statusName, alert] of statuses) {
        const record = detectionFinding(
          {
            ...finding,
            severity,
            status,
            resolvedAt: status === "resolved" ? seen + 5 : null,
            suppressedUntil: status === "suppressed" ? seen + 9 : null,
          },
          ACCOUNT,
        ) as OcsfRecord;
        expect(record, `${severity} ${status}`).toMatchObject({
          severity_id: severityId,
          severity: severityName,
          status_id: statusId,
          status: statusName,
          status_code: status,
          is_alert: alert,
        });
        expect(record.unmapped.virga.resolved_time).toBe(
          status === "resolved" ? seen + 5 : undefined,
        );
        expect(record.unmapped.virga.suppressed_until).toBe(
          status === "suppressed" ? seen + 9 : undefined,
        );
      }
    }

    // The activity: closed when resolved, created when seen in one scan only, updated after.
    const activity = (f: Partial<FindingView>) => {
      const r = detectionFinding({ ...finding, ...f }, ACCOUNT);
      return [r.activity_id, r.activity_name, r.type_uid, r.type_name];
    };
    expect(activity({ firstSeen: seen, lastSeen: seen })).toEqual([
      1,
      "Create",
      200401,
      "Detection Finding: Create",
    ]);
    expect(activity({ firstSeen: seen, lastSeen: seen + 1 })).toEqual([
      2,
      "Update",
      200402,
      "Detection Finding: Update",
    ]);
    expect(activity({ status: "resolved", resolvedAt: seen + 2 })).toEqual([
      3,
      "Close",
      200403,
      "Detection Finding: Close",
    ]);
    const resolved = detectionFinding(
      { ...finding, status: "resolved", lastSeen: seen + 1, resolvedAt: seen + 7 },
      ACCOUNT,
    ) as OcsfRecord;
    expect(resolved.time).toBe(finding.firstSeen);
    expect(resolved.finding_info.modified_time).toBe(seen + 7);

    // Without a subject there is no resource; an insight is kept as untrusted data.
    const bare = detectionFinding(
      { ...finding, subject: null, insightId: "insight-1" as FindingView["insightId"] },
      ACCOUNT,
    ) as OcsfRecord;
    expect(bare.resources).toBeUndefined();
    expect(bare.unmapped.virga.insight_id).toBe("insight-1");
  });

  it("exports an empty list for an account without findings, and 404 for one not in the index", async () => {
    const json = await download(exportPath(EMPTY_ACCOUNT));
    expect(await bodyText(json)).toBe("[]");
    expect(json.headers.get("virga-export-count")).toBe("0");
    expect(json.headers.get("link")).toBeNull();
    const ndjson = await download(exportPath(EMPTY_ACCOUNT, "format=ndjson"));
    expect(ndjson.status).toBe(200);
    expect(await bodyText(ndjson)).toBe("");

    const unknown = await download(exportPath(UNKNOWN_ACCOUNT));
    expect(unknown.status).toBe(404);
    expect(await unknown.json()).toEqual({ error: "not_found" });
    expect((await download("/api/accounts/not-an-account/findings/export")).status).toBe(404);
  });

  it("serves NDJSON, one record per line", async () => {
    const response = await download(exportPath(ACCOUNT, "format=ndjson"));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/x-ndjson; charset=utf-8");
    expect(response.headers.get("content-disposition")).toBe(
      `attachment; filename="virga-findings-${ACCOUNT}.ocsf.ndjson"`,
    );
    const lines = (await bodyText(response)).split("\n");
    expect(lines.at(-1)).toBe("");
    const parsed = lines.slice(0, -1).map((line) => JSON.parse(line) as OcsfRecord);
    expect(parsed.map((r) => r.finding_info.uid)).toEqual(findings.map((f) => f.fingerprint));
    expect(parsed.every((r) => r.class_uid === 2004)).toBe(true);
  });

  it("keeps hostile strings from the account as data in both formats", async () => {
    for (const format of ["json", "ndjson"]) {
      const response = await download(exportPath(HOSTILE_ACCOUNT, `format=${format}`));
      const text = await bodyText(response);
      // One record; NDJSON ends it with a line feed, the only one in the file.
      const line = format === "json" ? text : text.replace(/\n$/, "");
      expect(line).not.toContain("\n");
      // No markup and no raw control, bidi or separator character in the file.
      expect(text).not.toMatch(/[<>&]/);
      for (const c of INVISIBLE) {
        expect(line.includes(c), `U+${c.codePointAt(0)?.toString(16)}`).toBe(false);
      }
      expect(text).toContain("\\u003c/script\\u003e");
      expect(text).toContain("\\u202e");

      // Parsed back, every value is the string the account wrote.
      const [record] = (format === "json" ? JSON.parse(text) : [JSON.parse(text)]) as OcsfRecord[];
      expect(record?.finding_info.uid).toBe(hostileFinding.fingerprint);
      expect(record?.resources).toEqual([
        { uid: hostileFinding.subject, type: "worker_script", role_id: 1, role: "Target" },
      ]);
      expect(record?.evidences).toEqual([{ data: hostileFinding.evidence }]);
      expect(record?.unmapped.virga.insight_id).toBe(HOSTILE);
      expect(JSON.stringify(record)).toContain(JSON.stringify(HOSTILE));
    }
  });

  it("names the fields that hold strings from the scanned account", async () => {
    const [record] = await records(await download(exportPath(HOSTILE_ACCOUNT)));
    expect(record?.unmapped.virga.untrusted).toEqual([
      "finding_info.uid",
      "resources[].uid",
      "evidences[].data",
      "unmapped.virga.insight_id",
    ]);
    // Every string that carries the hostile text sits under one of those paths.
    const paths: string[] = [];
    const walk = (value: unknown, path: string) => {
      if (typeof value === "string" && value.includes(HOSTILE)) paths.push(path);
      else if (Array.isArray(value)) for (const v of value) walk(v, `${path}[]`);
      else if (value && typeof value === "object") {
        for (const [k, v] of Object.entries(value)) {
          if (k.includes(HOSTILE)) paths.push(`${path}.<key>`);
          walk(v, path === "" ? k : `${path}.${k}`);
        }
      }
    };
    walk(record, "");
    const covered = (path: string) =>
      UNTRUSTED_PATHS.some(
        (p) => path === p || path.startsWith(`${p}.`) || path.startsWith(`${p}[]`),
      );
    expect(paths.length).toBeGreaterThan(3);
    for (const path of paths) expect(covered(path), path).toBe(true);
  });

  it("answers viewers and admins alike, and nobody without Access", async () => {
    const asViewer = await download(exportPath(ACCOUNT), {}, viewer);
    const asAdmin = await download(exportPath(ACCOUNT), {}, admin);
    expect(asViewer.status).toBe(200);
    expect(asAdmin.status).toBe(200);
    expect(await asAdmin.text()).toBe(await asViewer.text());

    const anonymous = await call(exportPath(ACCOUNT));
    expect(anonymous.status).toBe(403);
    expect(await anonymous.json()).toEqual({ error: "forbidden" });
    expect(calls.filter((c) => c.method === "listFindings")).toHaveLength(2);
  });

  it("refuses a request another site sent, and serves the SPA, a typed address and other clients", async () => {
    const status = async (headers: Record<string, string>) =>
      (await download(exportPath(ACCOUNT), headers)).status;
    expect(await status({ "sec-fetch-site": "cross-site" })).toBe(403);
    expect(await status({ "sec-fetch-site": "same-site" })).toBe(403);
    expect(await status({ origin: "https://evil.example.com" })).toBe(403);
    expect(await status({ origin: "null" })).toBe(403);
    expect(calls).toEqual([]);
    const refused = await download(exportPath(ACCOUNT), { "sec-fetch-site": "cross-site" });
    expect(await refused.json()).toEqual({ error: "cross_origin" });

    expect(await status({ "sec-fetch-site": "same-origin", origin: ORIGIN })).toBe(200);
    expect(await status({ "sec-fetch-site": "none" })).toBe(200);
    expect(await status({})).toBe(200);
    const post = await call(exportPath(ACCOUNT), { token: viewer, body: {} });
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET");
  });

  it("holds at most 1,000 findings, and links to the rest", async () => {
    const first = await download(exportPath(MANY_ACCOUNT));
    const page = await records(first);
    expect(page).toHaveLength(EXPORT_MAX);
    expect(first.headers.get("virga-export-count")).toBe(String(EXPORT_MAX));
    expect(nextLink(first)).toBe(exportPath(MANY_ACCOUNT, "format=json&cursor=at%3A1000"));
    // Core is read in chunks, each continuing at the cursor of the one before.
    const reads = calls.filter((c) => c.method === "listFindings").map((c) => c.args[1]);
    expect(reads).toHaveLength(EXPORT_MAX / EXPORT_CHUNK);
    expect(reads[0]).toEqual({ limit: EXPORT_CHUNK });
    expect(reads[1]).toEqual({ limit: EXPORT_CHUNK, cursor: "at:50" });

    const { all } = await exportAll(exportPath(MANY_ACCOUNT));
    const expected = (exportFindings(MANY_ACCOUNT) ?? []).map((f) => f.fingerprint);
    expect(all.map((r) => r.finding_info.uid)).toEqual(expected);
    expect(expected).toHaveLength(1005);

    const ten = await download(exportPath(MANY_ACCOUNT, "limit=10&format=ndjson"));
    expect((await bodyText(ten)).trimEnd().split("\n")).toHaveLength(10);
    expect(nextLink(ten)).toBe(exportPath(MANY_ACCOUNT, "format=ndjson&limit=10&cursor=at%3A10"));
  });

  it("passes the findings filters on, also to the next link", async () => {
    const response = await download(
      exportPath(MANY_ACCOUNT, "status=open&status=suppressed&severity=critical&limit=20"),
    );
    const page = await records(response);
    expect(page).toHaveLength(20);
    for (const r of page) {
      expect(["open", "suppressed"]).toContain(r.status_code);
      expect(r.severity).toBe("Critical");
    }
    expect(calls[0]?.args[1]).toEqual({
      status: ["open", "suppressed"],
      severity: ["critical"],
      limit: 20,
    });
    expect(nextLink(response)).toBe(
      exportPath(
        MANY_ACCOUNT,
        "status=open&status=suppressed&severity=critical&format=json&limit=20&cursor=at%3A20",
      ),
    );
  });

  it("validates the query", async () => {
    const bad = async (query: string) => {
      const response = await download(exportPath(ACCOUNT, query));
      return [response.status, ((await response.json()) as { error: string }).error];
    };
    expect(await bad("format=csv")).toEqual([400, "invalid_format"]);
    expect(await bad("format=")).toEqual([400, "invalid_format"]);
    expect(await bad("limit=0")).toEqual([400, "invalid_limit"]);
    expect(await bad("limit=1001")).toEqual([400, "invalid_limit"]);
    expect(await bad("status=gone")).toEqual([400, "invalid_status"]);
    expect(await bad(`cursor=${"x".repeat(3000)}`)).toEqual([400, "invalid_cursor"]);
    expect(calls).toEqual([]);
  });

  it("stops at about 4 MiB per response, and leaves out evidence over 64 KiB", async () => {
    const { all, sizes } = await exportAll(exportPath(BIG_ACCOUNT));
    const expected = exportFindings(BIG_ACCOUNT) ?? [];
    expect(all.map((r) => r.finding_info.uid)).toEqual(expected.map((f) => f.fingerprint));
    expect(sizes.length).toBeGreaterThan(1);
    // The bound plus at most one chunk of findings, each at most its evidence limit and some.
    const bound = EXPORT_MAX_BYTES + EXPORT_CHUNK * (MAX_EVIDENCE_BYTES + 4096);
    for (const size of sizes) expect(size).toBeLessThanOrEqual(bound);
    expect(sizes[0]).toBeGreaterThanOrEqual(EXPORT_MAX_BYTES);

    const big = all[7] as OcsfRecord;
    expect(big.evidences).toBeUndefined();
    expect(big.metadata).toMatchObject({ is_truncated: true, untruncated_size: 98 });
    expect(big.unmapped.virga.evidence_omitted).toMatch(/read the finding/);
    const normal = all[8] as OcsfRecord;
    expect(normal.metadata.is_truncated).toBeUndefined();
    expect(normal.evidences).toEqual([{ data: expected[8]?.evidence }]);
  });
});
