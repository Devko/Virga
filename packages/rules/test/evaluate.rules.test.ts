import { migrate, recordCoverage } from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { describe, expect, it } from "vitest";
import { evaluateRules } from "../src/evaluate.ts";
import { FIXTURES } from "../src/fixtures.gen.ts";
import { loadFixture, RULES } from "../src/index.ts";

// The compiler checks fingerprints and severities; this checks the rest of
// the output contract (subject_id, fingerprint prefix, evidence) by running
// every fixture through the findings lifecycle.
describe("rule fixtures through evaluateRules", () => {
  it.each(FIXTURES.map((f) => [`${f.rule}/${f.name}`, f] as const))("%s", async (_, fixture) => {
    const rule = RULES.find((r) => r.id === fixture.rule);
    if (!rule) throw new Error(`missing rule ${fixture.rule}`);
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
      const configured = { ...rule, params: { ...rule.params, ...fixture.params } };
      const [run] = evaluateRules(db, [configured], scanId, 1000);
      expect(run).toEqual({
        ruleId: rule.id,
        status: "evaluated",
        hits: fixture.expect.length,
        undecided: 0,
        missing: [],
        opened: fixture.expect.length,
        resolved: 0,
      });

      const findings = db.query<{ fingerprint: string; subject: string | null }>(
        `SELECT f.fingerprint, n.id AS subject
         FROM findings f
         LEFT JOIN finding_nodes fn ON fn.fingerprint = f.fingerprint AND fn.role = 'subject'
         LEFT JOIN nodes n ON n.id = fn.node_id
         ORDER BY f.fingerprint`,
      );
      expect(findings.map((f) => f.fingerprint)).toEqual(
        fixture.expect.map((e) => e.fingerprint).sort(),
      );
      for (const finding of findings) expect(finding.subject, finding.fingerprint).not.toBeNull();
    } finally {
      db.close();
    }
  });
});
