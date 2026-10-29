import { migrate, recordCoverage } from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { describe, expect, it } from "vitest";
import { evaluateRules } from "../src/evaluate.ts";
import { FIXTURES } from "../src/fixtures.gen.ts";
import { loadFixture, RULES } from "../src/index.ts";

const SEEDED = { severity: "info", evidence: '{"seeded":true}', first_seen: 500, last_seen: 500 };

// The compiler checks fingerprints and severities; this checks the rest of
// the output contract (subject_id, fingerprint prefix, evidence) by running
// every fixture through the findings lifecycle. Each undecided row gets an
// open finding first, which must come out unchanged.
describe("rule fixtures through evaluateRules", () => {
  it.each(FIXTURES.map((f) => [`${f.rule}/${f.name}`, f] as const))("%s", async (_, fixture) => {
    const rule = RULES.find((r) => r.id === fixture.rule);
    if (!rule) throw new Error(`missing rule ${fixture.rule}`);
    const decided = fixture.expect.filter((e) => e.decided !== false).map((e) => e.fingerprint);
    const undecided = fixture.expect.filter((e) => e.decided === false).map((e) => e.fingerprint);
    const db = openNodeDatabase();
    try {
      migrate(db);
      await loadFixture(db, fixture);
      const scanId =
        db.query<{ value: string }>("SELECT value FROM meta WHERE key = 'current_scan'")[0]
          ?.value ?? "";
      for (const input of rule.requires) {
        recordCoverage(db, { scanId, resourceClass: input, status: "complete" });
      }
      for (const fingerprint of undecided) {
        db.run(
          `INSERT INTO findings (fingerprint, rule_id, rule_version, severity, status, title,
             evidence, first_seen, last_seen) VALUES (?, ?, 1, ?, 'open', 'seeded', ?, ?, ?)`,
          fingerprint,
          rule.id,
          SEEDED.severity,
          SEEDED.evidence,
          SEEDED.first_seen,
          SEEDED.last_seen,
        );
      }
      const configured = { ...rule, params: { ...rule.params, ...fixture.params } };
      const [run] = evaluateRules(db, [configured], scanId, 1000);
      expect(run).toEqual({
        ruleId: rule.id,
        status: "evaluated",
        hits: decided.length,
        undecided: undecided.length,
        missing: [],
        opened: decided.length,
        resolved: 0,
      });

      const findings = db.query<{
        fingerprint: string;
        status: string;
        severity: string;
        evidence: string;
        first_seen: number;
        last_seen: number;
        subject: string | null;
      }>(
        `SELECT f.fingerprint, f.status, f.severity, f.evidence, f.first_seen, f.last_seen,
                n.id AS subject
         FROM findings f
         LEFT JOIN finding_nodes fn ON fn.fingerprint = f.fingerprint AND fn.role = 'subject'
         LEFT JOIN nodes n ON n.id = fn.node_id
         ORDER BY f.fingerprint`,
      );
      expect(findings.map((f) => f.fingerprint)).toEqual([...decided, ...undecided].sort());
      for (const finding of findings) {
        if (undecided.includes(finding.fingerprint)) {
          expect(finding, finding.fingerprint).toEqual({
            fingerprint: finding.fingerprint,
            status: "open",
            ...SEEDED,
            subject: null,
          });
        } else {
          expect(finding.subject, finding.fingerprint).not.toBeNull();
        }
      }
    } finally {
      db.close();
    }
  });
});

describe("fixture names", () => {
  it.each(FIXTURES.map((f) => [`${f.rule}/${f.name}`, f] as const))("%s", (_, fixture) => {
    const hits = fixture.expect.filter((e) => e.decided !== false).length;
    const undecided = fixture.expect.length - hits;
    const kind = fixture.name.split("-")[0];
    expect(["positive", "negative", "undecided"]).toContain(kind);
    // positive: at least one hit; negative: no rows; undecided: at least one undecided row
    if (kind === "positive") expect(hits).toBeGreaterThan(0);
    if (kind === "negative") expect(fixture.expect).toEqual([]);
    if (kind === "undecided") expect(undecided).toBeGreaterThan(0);
  });
});

describe("rules that read exposure", () => {
  it.each(RULES.map((r) => [r.id, r] as const))(
    "%s requires exposure and access if it reads exposure",
    (_, rule) => {
      if (/\b(FROM|JOIN)\s+exposure\b/i.test(rule.sql)) {
        expect(rule.requires).toEqual(expect.arrayContaining(["exposure", "access"]));
      }
    },
  );

  it.each(RULES.filter((r) => r.requires.includes("exposure")).map((r) => [r.id]))(
    "%s has a fixture for unknown exposure",
    (id) => {
      const fixtures = FIXTURES.filter((f) => f.rule === id);
      expect(fixtures.some((f) => f.expect.some((e) => e.decided === false))).toBe(true);
    },
  );
});
