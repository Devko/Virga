// An independent check of what a reader returns. It does not reuse the
// readers' validators, so a bug in one of them cannot hide itself.

import type { Limits } from "../src/limits.ts";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9 ._:+-]{0,127}$/;
const PURL = /^pkg:[a-z][a-z0-9.+-]*\/[A-Za-z0-9.\-_~%!$&'()*+,;=:@/?]+$/;
const PREFIXES = new Set(["cfat_", "cfut_", "cfk_"]);
const MASK = "********";

/** No C0 or C1 controls, no lone surrogates, no bidi controls, no line separators. */
function cleanText(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return false;
    if ((c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) return false;
    if (c === 0x2028 || c === 0x2029 || c === 0x200e || c === 0x200f || c === 0x061c) return false;
    if (c >= 0xdc00 && c <= 0xdfff) return false;
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    }
  }
  return true;
}

const text = (value: unknown, max: number, allowEmpty = false): boolean =>
  typeof value === "string" &&
  value.length <= max &&
  (allowEmpty || value.length > 0) &&
  cleanText(value);

const sortedUnique = (values: string[]): boolean =>
  values.every((v, i) => i === 0 || (values[i - 1] as string) < v);

const keyOf = (p: Record<string, unknown>): string =>
  p.purl !== null ? `0${p.purl}` : `1${p.ecosystem}\u0000${p.name}\u0000${p.version ?? ""}`;

/** Problems with a reader result; empty when it meets every invariant. */
export function checkReport(report: unknown, tool: string, limits: Limits): string[] {
  const problems: string[] = [];
  const fail = (what: string) => problems.push(what);
  if (report === null || typeof report !== "object" || Array.isArray(report)) {
    return ["report is not an object"];
  }
  const r = report as Record<string, unknown>;
  if (Object.getPrototypeOf(r) !== Object.prototype) fail("report is not a plain object");
  if (JSON.stringify(Object.keys(r).sort()) !== '["packages","secrets","tool","vulnerabilities"]') {
    fail("report keys");
  }
  if (r.tool !== tool) fail("tool");
  const packages = r.packages;
  const vulns = r.vulnerabilities;
  const secrets = r.secrets;
  if (!Array.isArray(packages) || !Array.isArray(vulns) || !Array.isArray(secrets)) {
    return [...problems, "lists"];
  }
  if (packages.length > limits.maxPackages) fail("too many packages");
  if (vulns.length > limits.maxVulnerabilities) fail("too many vulnerabilities");
  if (secrets.length > limits.maxSecrets) fail("too many secrets");
  if (tool === "gitleaks" && (packages.length > 0 || vulns.length > 0)) fail("gitleaks packages");
  if (tool === "osv-scanner" && secrets.length > 0) fail("osv-scanner secrets");

  const keys: string[] = [];
  for (const p of packages as Record<string, unknown>[]) {
    if (JSON.stringify(Object.keys(p)) !== '["purl","ecosystem","name","version"]')
      fail("package keys");
    if (
      p.purl !== null &&
      !(typeof p.purl === "string" && p.purl.length <= 512 && PURL.test(p.purl))
    ) {
      fail("package purl");
    }
    if (!(typeof p.ecosystem === "string" && LABEL.test(p.ecosystem))) fail("package ecosystem");
    if (!text(p.name, 512)) fail("package name");
    if (p.version !== null && !text(p.version, 256)) fail("package version");
    keys.push(keyOf(p));
  }
  if (!sortedUnique(keys)) fail("packages not sorted and unique");

  const known = new Set(keys);
  const vulnKeys: string[] = [];
  for (const v of vulns as Record<string, unknown>[]) {
    if (
      JSON.stringify(Object.keys(v)) !== '["package","id","aliases","severity","fixedVersions"]'
    ) {
      fail("vulnerability keys");
    }
    const pkg = v.package as Record<string, unknown>;
    if (!known.has(keyOf(pkg))) fail("vulnerability package not listed");
    if (!(typeof v.id === "string" && ID.test(v.id))) fail("vulnerability id");
    const aliases = v.aliases as unknown[];
    if (
      !Array.isArray(aliases) ||
      aliases.length > 100 ||
      !aliases.every((a) => typeof a === "string" && ID.test(a) && a !== v.id) ||
      !sortedUnique(aliases as string[])
    ) {
      fail("vulnerability aliases");
    }
    if (!(v.severity === null || [0, 1, 2, 3, 4].includes(v.severity as number))) fail("severity");
    const fixed = v.fixedVersions as unknown[];
    if (
      !Array.isArray(fixed) ||
      fixed.length > 100 ||
      !fixed.every((f) => text(f, 256)) ||
      !sortedUnique(fixed as string[])
    ) {
      fail("fixed versions");
    }
    vulnKeys.push(`${keys.indexOf(keyOf(pkg)).toString().padStart(8, "0")}\u0000${v.id}`);
  }
  if (!sortedUnique(vulnKeys)) fail("vulnerabilities not sorted and unique");

  const secretKeys: string[] = [];
  let previous: Record<string, unknown> | null = null;
  for (const s of secrets as Record<string, unknown>[]) {
    if (previous !== null && compareSecrets(previous, s) > 0) fail("secrets not sorted");
    previous = s;
    if (JSON.stringify(Object.keys(s)) !== '["ruleId","file","line","endLine","prefix","masked"]') {
      fail("secret keys");
    }
    if (!(typeof s.ruleId === "string" && RULE_ID.test(s.ruleId))) fail("secret rule");
    if (!text(s.file, 1024, true)) fail("secret file");
    const line = s.line as number;
    const end = s.endLine as number;
    if (!(Number.isInteger(line) && Number.isInteger(end) && line >= 0 && end >= line)) {
      fail("secret lines");
    }
    if (!(s.prefix === null || PREFIXES.has(s.prefix as string))) fail("secret prefix");
    if (s.masked !== `${s.prefix ?? ""}${MASK}`) fail("secret mask");
    if (tool === "trivy" && s.prefix !== null) fail("trivy prefix");
    secretKeys.push(JSON.stringify([s.file, line, end, s.ruleId, s.prefix]));
  }
  if (new Set(secretKeys).size !== secretKeys.length) fail("duplicate secrets");
  return problems;
}

const cmp = (a: unknown, b: unknown): number => {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return (a as string | number) < (b as string | number) ? -1 : 1;
};

function compareSecrets(a: Record<string, unknown>, b: Record<string, unknown>): number {
  for (const key of ["file", "line", "endLine", "ruleId", "prefix"]) {
    const order = cmp(a[key], b[key]);
    if (order !== 0) return order;
  }
  return 0;
}
