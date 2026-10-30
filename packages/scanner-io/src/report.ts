import type { Tool } from "./errors.ts";
import { compare, type Fields } from "./fields.ts";
import type { Limits } from "./limits.ts";
import type { SecretPrefix } from "./secrets.ts";
import { FIELD_LIMITS } from "./text.ts";

/** Severity rank as in the graph: 0 none, 1 low, 2 medium, 3 high, 4 critical. */
export type SeverityRank = 0 | 1 | 2 | 3 | 4;

/**
 * A package as a scanner saw it. `name` and `version` come from the scanned
 * workload and are untrusted display strings: checked for length and
 * control characters, never interpreted.
 */
export interface ScannedPackage {
  /** Package URL. Null when the tool gave none and Virga derives none for the ecosystem. */
  purl: string | null;
  /** The tool's ecosystem: an OSV ecosystem for osv-scanner, the result type for Trivy. */
  ecosystem: string;
  name: string;
  /** Null when the tool reported an empty version. */
  version: string | null;
}

export interface VulnerabilityMatch {
  package: ScannedPackage;
  /** Advisory ID as the tool reported it (CVE, GHSA, PYSEC, ...). */
  id: string;
  /** Other IDs of the same advisory, sorted, without `id`. */
  aliases: string[];
  /** Null when the tool stated no severity Virga can map. Unknown, never "none". */
  severity: SeverityRank | null;
  /** Versions that fix it, sorted as text; empty when the tool named none. */
  fixedVersions: string[];
}

/** A secret finding, masked. The raw secret never reaches this object. */
export interface SecretFinding {
  ruleId: string;
  /** Path inside the scanned bundle or image; untrusted. */
  file: string;
  /** First and last line as the tool reported them. */
  line: number;
  endLine: number;
  /** A known Cloudflare token prefix, or null. */
  prefix: SecretPrefix | null;
  /** `prefix` followed by a fixed mask. */
  masked: string;
}

/** The normalized result of one reader, sorted and without duplicates. */
export interface ScanReport {
  tool: Tool;
  packages: ScannedPackage[];
  vulnerabilities: VulnerabilityMatch[];
  secrets: SecretFinding[];
}

export interface ReaderOptions {
  /** Overrides of the default limits. */
  limits?: Partial<Limits>;
}

/** Sort key: packages with a purl first, by purl; then by ecosystem, name and version. */
const packageKey = (p: ScannedPackage): string =>
  p.purl !== null ? `0${p.purl}` : `1${p.ecosystem}\u0000${p.name}\u0000${p.version ?? ""}`;

const maxRank = (a: SeverityRank | null, b: SeverityRank | null): SeverityRank | null =>
  a === null ? b : b === null ? a : a > b ? a : b;

/** A match while it is collected; the sets are made when the first item comes. */
interface Match {
  aliases: Set<string> | null;
  severity: SeverityRank | null;
  fixed: Set<string> | null;
}

/** A stored package: its sort key, kept once, and its matches by advisory ID. */
interface Entry {
  key: string;
  pkg: ScannedPackage;
  matches: Map<string, Match>;
}

/**
 * Collects one report. Duplicates merge: a package is identified by its
 * purl, or by ecosystem, name and version when it has none, and the first
 * entry seen wins. A vulnerability match is identified by package and ID;
 * merged matches take the higher severity and the union of aliases and
 * fixed versions. The result is sorted, so equal input gives equal output.
 *
 * No key repeats a long string per entry: matches hang off their package
 * and secrets off their file. A key built from the package key and the ID
 * copied a 900-character key once per match (R9-06).
 */
export class ReportBuilder {
  readonly tool: Tool;
  readonly limits: Limits;
  readonly fields: Fields;
  private readonly packages = new Map<string, Entry>();
  private readonly entries = new Map<ScannedPackage, Entry>();
  private matchCount = 0;
  /** Secrets by file, then by lines, rule and prefix. */
  private readonly secrets = new Map<string, Map<string, SecretFinding>>();
  private secretCount = 0;

  constructor(tool: Tool, limits: Limits, fields: Fields) {
    this.tool = tool;
    this.limits = limits;
    this.fields = fields;
  }

  /** Adds a package, or returns the one already known under its key. */
  addPackage(pkg: ScannedPackage): ScannedPackage {
    return this.entry(pkg).pkg;
  }

  private entry(pkg: ScannedPackage): Entry {
    const stored = this.entries.get(pkg);
    if (stored) return stored;
    const key = packageKey(pkg);
    const known = this.packages.get(key);
    if (known) return known;
    if (this.packages.size >= this.limits.maxPackages) this.fields.fail("too_many_items", "/");
    const copy = { purl: pkg.purl, ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version };
    const entry: Entry = { key, pkg: copy, matches: new Map() };
    this.packages.set(key, entry);
    this.entries.set(copy, entry);
    return entry;
  }

  addVulnerability(
    pkg: ScannedPackage,
    id: string,
    aliases: readonly string[],
    severity: SeverityRank | null,
    fixed: readonly string[],
  ): void {
    const entry = this.entry(pkg);
    let match = entry.matches.get(id);
    if (!match) {
      if (this.matchCount >= this.limits.maxVulnerabilities) {
        this.fields.fail("too_many_items", "/");
      }
      match = { aliases: null, severity: null, fixed: null };
      entry.matches.set(id, match);
      this.matchCount++;
    }
    for (const alias of aliases) {
      if (alias === id) continue;
      match.aliases ??= new Set();
      match.aliases.add(alias);
    }
    for (const version of fixed) {
      match.fixed ??= new Set();
      match.fixed.add(version);
    }
    if (
      (match.aliases?.size ?? 0) > FIELD_LIMITS.aliases ||
      (match.fixed?.size ?? 0) > FIELD_LIMITS.fixedVersions
    ) {
      this.fields.fail("too_many_items", "/");
    }
    match.severity = maxRank(match.severity, severity);
  }

  addSecret(finding: SecretFinding): void {
    let byFile = this.secrets.get(finding.file);
    const key = JSON.stringify([finding.line, finding.endLine, finding.ruleId, finding.prefix]);
    if (byFile?.has(key)) return;
    if (this.secretCount >= this.limits.maxSecrets) this.fields.fail("too_many_items", "/");
    if (!byFile) {
      byFile = new Map();
      this.secrets.set(finding.file, byFile);
    }
    byFile.set(key, { ...finding });
    this.secretCount++;
  }

  build(): ScanReport {
    const entries = [...this.packages.values()].sort((a, b) => compare(a.key, b.key));
    const packages = entries.map((e) => ({ ...e.pkg }));
    const vulnerabilities: VulnerabilityMatch[] = [];
    entries.forEach((entry, i) => {
      for (const id of [...entry.matches.keys()].sort(compare)) {
        const m = entry.matches.get(id) as Match;
        vulnerabilities.push({
          package: { ...(packages[i] as ScannedPackage) },
          id,
          aliases: m.aliases ? [...m.aliases].sort(compare) : [],
          severity: m.severity,
          fixedVersions: m.fixed ? [...m.fixed].sort(compare) : [],
        });
      }
    });
    const secrets = [...this.secrets.values()]
      .flatMap((byFile) => [...byFile.values()])
      .sort(compareSecrets);
    return { tool: this.tool, packages, vulnerabilities, secrets };
  }
}

/** Known prefixes first, then none. */
const comparePrefix = (a: string | null, b: string | null): number =>
  a === b ? 0 : a === null ? 1 : b === null ? -1 : compare(a, b);

function compareSecrets(a: SecretFinding, b: SecretFinding): number {
  return (
    compare(a.file, b.file) ||
    a.line - b.line ||
    a.endLine - b.endLine ||
    compare(a.ruleId, b.ruleId) ||
    comparePrefix(a.prefix, b.prefix)
  );
}
