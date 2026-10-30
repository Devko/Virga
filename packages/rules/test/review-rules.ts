/**
 * The review's rules for R6-02 (docs/reviews/2026-10-30-verification-round-6.md):
 * a zone rule whose bracket alias `[z--]` hid a second statement from the
 * parameter scan.
 */
const zoneRule = (id: string, tail: string) => `-- ---
-- id: ${id}
-- version: 1
-- title: Zone exists
-- severity: low
-- kind: posture
-- requires: [zones]
-- enriches: null
-- ---
SELECT '${id}' AS rule_id, '${id}:' || id AS fingerprint, 'low' AS severity, id AS subject_id
FROM (SELECT id FROM nodes WHERE type = 'zone' AND deleted_at IS NULL) AS [z--]; ${tail}
`;

export const REVIEW_RULES: Record<string, string> = {
  // Writes meta.current_scan in Durable Object SQL, which runs every statement.
  "CF-997": zoneRule("CF-997", "UPDATE meta SET value = 'forged' WHERE key = 'current_scan'"),
  // Reads exposure although requires lacks exposure and access (R4-04).
  "CF-995": zoneRule(
    "CF-995",
    "SELECT 'CF-995' AS rule_id, 'CF-995:' || entry_id AS fingerprint, 'high' AS severity, entry_id AS subject_id FROM exposure WHERE decision = 'public'",
  ),
};

/** The review's fixtures; both pass, because Node SQLite runs only the first statement. */
export const reviewFixtures = (id: string): Record<string, string> => ({
  "negative-none.yaml": "nodes: []\nexpect: []\n",
  "positive-zone.yaml": `nodes:\n  - { type: zone, id: z1, name: example.com }\nexpect:\n  - { fingerprint: "${id}:zone:z1" }\n`,
});
