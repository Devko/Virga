/**
 * Reader for osv-scanner JSON output (`osv-scanner scan --format json`).
 *
 * Format followed: osv-scanner 2 as documented in its output reference
 * (`results[].packages[]` with `package`, `vulnerabilities` and `groups`;
 * osv-scanner 1.x writes the same members), with vulnerability entries in
 * the OSV schema 1.6. Written from the documentation, not yet checked
 * against captured output (S-07).
 *
 * Read: `package.name`, `package.version`, `package.ecosystem`; per
 * vulnerability `id`, `aliases`, `database_specific.severity` and the
 * `fixed` events of `affected[].ranges` for the same package; per group
 * `ids` and `max_severity`. Everything else is ignored, but still counts
 * against the limits.
 */

import { Fields } from "./fields.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { parseJson } from "./json.ts";
import { resolveLimits } from "./limits.ts";
import { type ReaderOptions, ReportBuilder, type ScanReport, type SeverityRank } from "./report.ts";
import { FIELD_LIMITS, LABEL, npmPurl } from "./text.ts";

const TOOL = "osv-scanner";

/** Labels in `database_specific.severity` (GitHub advisories) and in `max_severity`. */
const SEVERITY_LABELS = new Map<string, SeverityRank>([
  ["LOW", 1],
  ["MODERATE", 2],
  ["MEDIUM", 2],
  ["HIGH", 3],
  ["CRITICAL", 4],
]);

/** A CVSS base score, 0.0 to 10.0. */
const SCORE = /^(?:10(?:\.0{1,3})?|[0-9](?:\.[0-9]{1,3})?)$/;

/** CVSS v3 qualitative rating of a base score. */
export function rankScore(score: number): SeverityRank {
  if (score === 0) return 0;
  if (score < 4) return 1;
  if (score < 7) return 2;
  if (score < 9) return 3;
  return 4;
}

/** Per-list caps inside one OSV entry; a longer list rejects the report. */
const MAX_AFFECTED = 1_000;
const MAX_RANGES = 100;
const MAX_EVENTS = 1_000;

/** Range types whose events are versions; GIT ranges carry commits. */
const VERSION_RANGES = new Set(["ECOSYSTEM", "SEMVER"]);

/** "Debian:12" and "Debian" name the same ecosystem. */
const baseEcosystem = (ecosystem: string): string => ecosystem.split(":", 1)[0] ?? ecosystem;

export function readOsvScanner(
  input: string | Uint8Array,
  options: ReaderOptions = {},
): ScanReport {
  const limits = resolveLimits(options.limits);
  const f = new Fields(TOOL);
  const root = f.object(parseJson(input, limits, TOOL), "");
  // An empty object is no report: a clean scan still writes `results`.
  if (!root.has("results")) f.fail("missing_field", "/results");
  const out = new ReportBuilder(TOOL, limits, f);
  f.optionalArray(root, "results", "", limits.maxArrayItems).forEach((result, i) => {
    const at = `/results/${i}`;
    const source = f.object(result, at);
    f.optionalArray(source, "packages", at, limits.maxArrayItems).forEach((entry, j) => {
      readEntry(f, out, entry, `${at}/packages/${j}`);
    });
  });
  return out.build();
}

function readEntry(f: Fields, out: ReportBuilder, value: JsonValue, at: string): void {
  const entry = f.object(value, at);
  const pAt = `${at}/package`;
  const p = f.object(entry.get("package"), pAt);
  const name = f.text(f.string(p, "name", pAt), `${pAt}/name`, FIELD_LIMITS.name);
  const version = f.text(f.string(p, "version", pAt), `${pAt}/version`, FIELD_LIMITS.version, true);
  const ecosystem = f.matching(
    f.string(p, "ecosystem", pAt),
    `${pAt}/ecosystem`,
    LABEL,
    FIELD_LIMITS.label,
  );
  const purl = ecosystem === "npm" ? npmPurl(name, version) : null;
  const pkg = out.addPackage({ purl, ecosystem, name, version: version === "" ? null : version });

  const severities = new Map<string, SeverityRank | null>();
  f.optionalArray(entry, "groups", at, out.limits.maxArrayItems).forEach((g, k) => {
    const gAt = `${at}/groups/${k}`;
    const group = f.object(g, gAt);
    const ids = f.idList(group, "ids", gAt);
    const max = f.optionalString(group, "max_severity", gAt);
    const rank = max === null ? null : parseSeverity(f, max, `${gAt}/max_severity`);
    for (const id of ids) {
      const known = severities.get(id) ?? null;
      severities.set(id, known === null || (rank !== null && rank > known) ? rank : known);
    }
  });

  f.optionalArray(entry, "vulnerabilities", at, out.limits.maxArrayItems).forEach((v, k) => {
    const vAt = `${at}/vulnerabilities/${k}`;
    const vuln = f.object(v, vAt);
    const id = f.id(vuln, "id", vAt);
    const aliases = f.idList(vuln, "aliases", vAt);
    const severity = severities.get(id) ?? databaseSeverity(vuln);
    const fixed = fixedVersions(f, vuln, vAt, name, ecosystem);
    out.addVulnerability(pkg, id, aliases, severity, fixed);
  });
}

/**
 * `max_severity` is a CVSS score as text, or empty. A label is mapped too;
 * any other text is an unknown severity, not a rejection.
 */
function parseSeverity(f: Fields, value: string, at: string): SeverityRank | null {
  f.text(value, at, FIELD_LIMITS.severity, true);
  if (SCORE.test(value)) return rankScore(Number(value));
  return SEVERITY_LABELS.get(value.toUpperCase()) ?? null;
}

/** `database_specific` is free-form in the OSV schema, so a surprise there is not an error. */
function databaseSeverity(vuln: JsonObject): SeverityRank | null {
  const specific = vuln.get("database_specific");
  if (!(specific instanceof Map)) return null;
  const label = specific.get("severity");
  if (typeof label !== "string" || label.length > FIELD_LIMITS.severity) return null;
  return SEVERITY_LABELS.get(label.toUpperCase()) ?? null;
}

function fixedVersions(
  f: Fields,
  vuln: JsonObject,
  at: string,
  name: string,
  ecosystem: string,
): string[] {
  const fixed = new Set<string>();
  const items = f.optionalArray(vuln, "affected", at, MAX_AFFECTED);
  items.forEach((a, i) => {
    const aAt = `${at}/affected/${i}`;
    const affected = f.object(a, aAt);
    const pkg = f.optionalObject(affected, "package", aAt);
    if (!pkg) return;
    const pkgName = f.optionalString(pkg, "name", `${aAt}/package`);
    const pkgEcosystem = f.optionalString(pkg, "ecosystem", `${aAt}/package`);
    if (pkgName !== name || pkgEcosystem === null) return;
    if (baseEcosystem(pkgEcosystem) !== baseEcosystem(ecosystem)) return;
    f.optionalArray(affected, "ranges", aAt, MAX_RANGES).forEach((r, j) => {
      const rAt = `${aAt}/ranges/${j}`;
      const range = f.object(r, rAt);
      const type = f.optionalString(range, "type", rAt);
      if (type === null || !VERSION_RANGES.has(type)) return;
      f.optionalArray(range, "events", rAt, MAX_EVENTS).forEach((e, k) => {
        const eAt = `${rAt}/events/${k}`;
        const value = f.optionalString(f.object(e, eAt), "fixed", eAt);
        if (value !== null) fixed.add(f.text(value, `${eAt}/fixed`, FIELD_LIMITS.version));
      });
    });
  });
  if (fixed.size > FIELD_LIMITS.fixedVersions) f.fail("too_many_items", `${at}/affected`);
  return [...fixed];
}
