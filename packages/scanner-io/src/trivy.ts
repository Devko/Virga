/**
 * Reader for Trivy JSON reports (`trivy image --format json`, also `fs` and
 * `rootfs`), vulnerabilities and secrets.
 *
 * Format followed: the report with `SchemaVersion` 2 as Trivy 0.5x and 0.6x
 * write it (`types.Report` in `pkg/types/report.go`): `Results[]` with
 * `Target`, `Type`, `Packages`, `Vulnerabilities` and `Secrets`; package
 * URLs in `Identifier.PURL` and `PkgIdentifier.PURL`. Any other schema
 * version is rejected. Written from the documentation and the report
 * types, not yet checked against captured output (S-07).
 *
 * Secrets: only `RuleID`, `StartLine` and `EndLine` are read, and the file
 * is the result's `Target`. `Match` and `Code` hold the secret (Trivy masks
 * it by default, but Virga does not rely on that) and are never read.
 */

import { Fields } from "./fields.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { parseJson } from "./json.ts";
import { resolveLimits } from "./limits.ts";
import {
  type ReaderOptions,
  ReportBuilder,
  type ScannedPackage,
  type ScanReport,
  type SeverityRank,
} from "./report.ts";
import { MASK } from "./secrets.ts";
import { FIELD_LIMITS, LABEL, RULE_ID } from "./text.ts";

const TOOL = "trivy";
const SCHEMA_VERSION = 2;

const SEVERITIES = new Map<string, SeverityRank | null>([
  ["UNKNOWN", null],
  ["LOW", 1],
  ["MEDIUM", 2],
  ["HIGH", 3],
  ["CRITICAL", 4],
]);

export function readTrivy(input: string | Uint8Array, options: ReaderOptions = {}): ScanReport {
  const limits = resolveLimits(options.limits);
  const f = new Fields(TOOL);
  const root = f.object(parseJson(input, limits, TOOL), "");
  const schema = f.integer(root, "SchemaVersion", "", 0, 1_000);
  if (schema !== SCHEMA_VERSION) f.fail("unsupported_version", "/SchemaVersion");
  const out = new ReportBuilder(TOOL, limits, f);
  f.optionalArray(root, "Results", "", limits.maxArrayItems).forEach((value, i) => {
    readResult(f, out, value, `/Results/${i}`);
  });
  return out.build();
}

function readResult(f: Fields, out: ReportBuilder, value: JsonValue, at: string): void {
  const result = f.object(value, at);
  const target = f.text(f.string(result, "Target", at), `${at}/Target`, FIELD_LIMITS.path, true);
  const typeText = f.optionalString(result, "Type", at);
  const type =
    typeText === null ? null : f.matching(typeText, `${at}/Type`, LABEL, FIELD_LIMITS.label);
  const packages = f.optionalArray(result, "Packages", at, out.limits.maxArrayItems);
  const vulns = f.optionalArray(result, "Vulnerabilities", at, out.limits.maxArrayItems);
  const secrets = f.optionalArray(result, "Secrets", at, out.limits.maxArrayItems);
  if (type === null && (packages.length > 0 || vulns.length > 0)) {
    f.fail("missing_field", `${at}/Type`);
  }

  // Trivy's package ID ("musl@1.2.4-r2") links a match to its package entry.
  const byId = new Map<string, ScannedPackage>();
  packages.forEach((p, j) => {
    const pAt = `${at}/Packages/${j}`;
    const entry = f.object(p, pAt);
    const name = f.text(f.string(entry, "Name", pAt), `${pAt}/Name`, FIELD_LIMITS.name);
    const version = formatVersion(f, entry, pAt);
    const identifier = f.optionalObject(entry, "Identifier", pAt);
    const purl = identifier ? optionalPurl(f, identifier, `${pAt}/Identifier`) : null;
    const pkg = out.addPackage({ purl, ecosystem: type ?? "", name, version });
    const id = f.optionalString(entry, "ID", pAt);
    if (id !== null) byId.set(f.text(id, `${pAt}/ID`, FIELD_LIMITS.name), pkg);
  });

  vulns.forEach((v, j) => {
    const vAt = `${at}/Vulnerabilities/${j}`;
    const vuln = f.object(v, vAt);
    const id = f.id(vuln, "VulnerabilityID", vAt);
    const name = f.text(f.string(vuln, "PkgName", vAt), `${vAt}/PkgName`, FIELD_LIMITS.name);
    const installed = f.text(
      f.string(vuln, "InstalledVersion", vAt),
      `${vAt}/InstalledVersion`,
      FIELD_LIMITS.version,
      true,
    );
    const identifier = f.optionalObject(vuln, "PkgIdentifier", vAt);
    const purl = identifier ? optionalPurl(f, identifier, `${vAt}/PkgIdentifier`) : null;
    const pkgId = f.optionalString(vuln, "PkgID", vAt);
    const listed = pkgId === null ? undefined : byId.get(pkgId);
    const pkg =
      purl === null && listed
        ? listed
        : { purl, ecosystem: type ?? "", name, version: installed === "" ? null : installed };
    const aliases = f.idList(vuln, "VendorIDs", vAt);
    const fixed = splitFixed(f, f.optionalString(vuln, "FixedVersion", vAt), `${vAt}/FixedVersion`);
    out.addVulnerability(pkg, id, aliases, severity(f, vuln, vAt), fixed);
  });

  secrets.forEach((s, j) => {
    const sAt = `${at}/Secrets/${j}`;
    const secret = f.object(s, sAt);
    const ruleId = f.matching(
      f.string(secret, "RuleID", sAt),
      `${sAt}/RuleID`,
      RULE_ID,
      FIELD_LIMITS.ruleId,
    );
    const line = f.integer(secret, "StartLine", sAt);
    const endLine = f.integer(secret, "EndLine", sAt);
    if (endLine < line) f.fail("out_of_range", `${sAt}/EndLine`);
    // The kind is the rule ID; Trivy keeps no prefix that Virga could read safely.
    out.addSecret({ ruleId, file: target, line, endLine, prefix: null, masked: MASK });
  });
}

function optionalPurl(f: Fields, identifier: JsonObject, at: string): string | null {
  const purl = f.optionalString(identifier, "PURL", at);
  return purl === null || purl === "" ? null : f.purl(purl, `${at}/PURL`);
}

/** `[epoch:]version[-release]`, as Trivy formats the installed version. */
function formatVersion(f: Fields, entry: JsonObject, at: string): string | null {
  let version = f.text(f.string(entry, "Version", at), `${at}/Version`, FIELD_LIMITS.version, true);
  if (version === "") return null;
  const release = f.optionalString(entry, "Release", at);
  const epoch = entry.has("Epoch") ? f.integer(entry, "Epoch", at, 0, 2 ** 31 - 1) : 0;
  if (epoch > 0) version = `${epoch}:${version}`;
  if (release) version = `${version}-${release}`;
  return f.text(version, `${at}/Release`, FIELD_LIMITS.version);
}

function severity(f: Fields, vuln: JsonObject, at: string): SeverityRank | null {
  const label = f.optionalString(vuln, "Severity", at);
  if (label === null) return null;
  const rank = SEVERITIES.get(label);
  if (rank === undefined) f.fail("invalid_format", `${at}/Severity`);
  return rank;
}

/** Trivy lists several fixed versions in one string: "8.17.1, 7.5.10". */
function splitFixed(f: Fields, value: string | null, at: string): string[] {
  if (value === null || value === "") return [];
  f.text(value, at, FIELD_LIMITS.version * 4);
  const parts = value
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part !== "");
  if (parts.length > FIELD_LIMITS.fixedVersions) f.fail("too_many_items", at);
  return parts.map((part) => f.text(part, at, FIELD_LIMITS.version));
}
