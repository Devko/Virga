import {
  asObject,
  Invalid,
  invalid,
  type JsonObject,
  own,
  parseObject,
  readArray,
  readString,
} from "./json.ts";

/**
 * The OSV schema version this reader follows
 * (https://ossf.github.io/osv-schema/). Records that declare another major
 * version are rejected; 1.x records are read as 1.9.2 defines them.
 */
export const OSV_SCHEMA_VERSION = "1.9.2";

/**
 * Limits for one record. Advisory data is untrusted: a record over a limit
 * is rejected, never cut. The `versions` limit leaves room for packages with
 * thousands of releases (canary builds), which osv.dev lists one by one.
 */
export const OSV_LIMITS = {
  recordBytes: 4 * 1024 * 1024,
  idLength: 128,
  aliases: 100,
  timestampLength: 64,
  severity: 16,
  severityTypeLength: 32,
  scoreLength: 256,
  databaseSeverityLength: 32,
  affected: 1000,
  ecosystemLength: 128,
  nameLength: 256,
  ranges: 100,
  events: 500,
  versions: 50_000,
  versionLength: 256,
} as const;

export type OsvEventKind = "introduced" | "fixed" | "last_affected" | "limit";

export interface OsvEvent {
  kind: OsvEventKind;
  /** As written: `0` for introduced and `*` for limit keep their meaning. */
  version: string;
}

export interface OsvRange {
  type: "SEMVER" | "ECOSYSTEM" | "GIT";
  events: OsvEvent[];
}

export interface OsvSeverity {
  type: string;
  score: string;
}

/** One `affected` entry of ecosystem `npm`. */
export interface NpmAffected {
  /** npm package name, `@scope/name` for a scoped package, or `*` for every package. */
  name: string;
  ranges: OsvRange[];
  versions: string[];
  /** Package-level severity; null when the record has none here. */
  severity: OsvSeverity[] | null;
}

/** The parts of an OSV record that matching needs. */
export interface OsvAdvisory {
  id: string;
  modified: string;
  aliases: string[];
  /** Top-level severity; empty when the record has none. */
  severity: OsvSeverity[];
  /** `database_specific.severity`, as GitHub advisories carry it (`LOW` to `CRITICAL`). */
  databaseSeverity: string | null;
  /** Only the npm entries. */
  affected: NpmAffected[];
}

export type OsvRecordResult =
  /** An advisory with at least one npm entry; `skippedEntries` counts the entries of other ecosystems. */
  | { status: "accepted"; advisory: OsvAdvisory; skippedEntries: number }
  /** A valid record with `withdrawn` set. It matches nothing. */
  | { status: "withdrawn"; id: string }
  /** A valid record without npm entries. */
  | { status: "skipped"; id: string; skippedEntries: number }
  /** A record that breaks the schema or a limit. `id` is null when the ID itself could not be read. */
  | { status: "rejected"; id: string | null; reason: string };

/** OSV IDs and aliases: `^[a-zA-Z0-9:_.-]+$`. */
export const OSV_ID = /^[a-zA-Z0-9:_.-]+$/;

const SCHEMA_VERSION = /^1\.\d+\.\d+$/;
const RANGE_TYPES = new Set(["SEMVER", "ECOSYSTEM", "GIT"]);
const EVENT_KINDS: readonly OsvEventKind[] = ["introduced", "fixed", "last_affected", "limit"];
const L = OSV_LIMITS;

const isId = (value: unknown): value is string =>
  typeof value === "string" && value.length <= L.idLength && OSV_ID.test(value);

function readSeverity(object: JsonObject, path: string): OsvSeverity[] | null {
  const list = readArray(object, "severity", `${path}severity`, L.severity);
  return (
    list?.map((item, i) => {
      const at = `${path}severity[${i}]`;
      const entry = asObject(item, at);
      return {
        type: readString(entry, "type", `${at}.type`, L.severityTypeLength, true) as string,
        score: readString(entry, "score", `${at}.score`, L.scoreLength, true) as string,
      };
    }) ?? null
  );
}

function nonEmpty(object: JsonObject, key: string, path: string, max: number): string {
  const value = readString(object, key, path, max, true) as string;
  return value === "" ? invalid(path, "empty") : value;
}

function readRange(item: unknown, path: string): OsvRange {
  const range = asObject(item, path);
  const type = readString(range, "type", `${path}.type`, 16, true);
  if (!RANGE_TYPES.has(type as string)) invalid(`${path}.type`, "unsupported");
  const list = readArray(range, "events", `${path}.events`, L.events);
  if (list === null) return invalid(`${path}.events`, "missing");
  if (list.length === 0) return invalid(`${path}.events`, "empty");
  const events = list.map((value, i): OsvEvent => {
    const at = `${path}.events[${i}]`;
    const event = asObject(value, at);
    const kinds = EVENT_KINDS.filter((kind) => own(event, kind) !== undefined);
    if (kinds.length !== 1) invalid(at, "not exactly one event type");
    const kind = kinds[0] as OsvEventKind;
    return { kind, version: nonEmpty(event, kind, `${at}.${kind}`, L.versionLength) };
  });
  const has = (kind: OsvEventKind) => events.some((e) => e.kind === kind);
  if (!has("introduced")) invalid(`${path}.events`, "no introduced event");
  if (has("fixed") && has("last_affected")) {
    invalid(`${path}.events`, "both fixed and last_affected");
  }
  return { type: type as OsvRange["type"], events };
}

function readNpmEntry(entry: JsonObject, path: string, topSeverity: boolean): NpmAffected {
  const pkg = asObject(own(entry, "package"), `${path}.package`);
  const name = nonEmpty(pkg, "name", `${path}.package.name`, L.nameLength);
  const ranges = readArray(entry, "ranges", `${path}.ranges`, L.ranges) ?? [];
  const versions = readArray(entry, "versions", `${path}.versions`, L.versions) ?? [];
  const severity = readSeverity(entry, `${path}.`);
  if (severity !== null && topSeverity) invalid(`${path}.severity`, "also set at the top level");
  return {
    name,
    ranges: ranges.map((range, r) => readRange(range, `${path}.ranges[${r}]`)),
    versions: versions.map((version, v) => {
      const at = `${path}.versions[${v}]`;
      if (typeof version !== "string") return invalid(at, "not a string");
      if (version.length > L.versionLength) {
        return invalid(at, `longer than ${L.versionLength} characters`);
      }
      return version === "" ? invalid(at, "empty") : version;
    }),
    severity,
  };
}

/**
 * Reads one OSV record (JSON text) strictly. Only the fields matching needs
 * are read, and those are checked against the schema and the limits; any
 * violation rejects the whole record with a reason. Entries of ecosystems
 * other than `npm` are counted, and only their `package.ecosystem` is
 * checked. A key that occurs twice in one object, anywhere in the record,
 * rejects it; the rejection keeps the ID unless the `id` key is the one
 * repeated. Reasons hold paths, offsets and fixed words, never text from
 * the record.
 */
export function readOsvRecord(text: string): OsvRecordResult {
  const parsed = parseObject(text, L.recordBytes);
  if (!parsed.ok) {
    const id = parsed.unique === undefined ? undefined : own(parsed.unique, "id");
    return { status: "rejected", id: isId(id) ? id : null, reason: parsed.reason };
  }
  const record = parsed.value;
  const id = own(record, "id");
  if (id === undefined || id === null) {
    return { status: "rejected", id: null, reason: "id: missing" };
  }
  if (!isId(id)) return { status: "rejected", id: null, reason: "id: invalid" };
  try {
    const schema = own(record, "schema_version");
    if (schema !== undefined && schema !== null) {
      if (typeof schema !== "string" || !SCHEMA_VERSION.test(schema)) {
        invalid("schema_version", "unsupported");
      }
    }
    const modified = readString(record, "modified", "modified", L.timestampLength, true) as string;
    const withdrawn = readString(record, "withdrawn", "withdrawn", L.timestampLength);
    const aliases = (readArray(record, "aliases", "aliases", L.aliases) ?? []).map((alias, i) =>
      isId(alias) ? alias : invalid(`aliases[${i}]`, "invalid"),
    );
    const severity = readSeverity(record, "");
    const dbValue = own(record, "database_specific");
    let databaseSeverity: string | null = null;
    if (dbValue !== undefined && dbValue !== null) {
      const db = asObject(dbValue, "database_specific");
      databaseSeverity = readString(
        db,
        "severity",
        "database_specific.severity",
        L.databaseSeverityLength,
      );
    }
    const affected: NpmAffected[] = [];
    let skippedEntries = 0;
    const entries = readArray(record, "affected", "affected", L.affected) ?? [];
    for (const [i, item] of entries.entries()) {
      const path = `affected[${i}]`;
      const entry = asObject(item, path);
      const pkgValue = own(entry, "package");
      const ecosystem =
        pkgValue === undefined || pkgValue === null
          ? null
          : readString(
              asObject(pkgValue, `${path}.package`),
              "ecosystem",
              `${path}.package.ecosystem`,
              L.ecosystemLength,
              true,
            );
      if (ecosystem === "npm") affected.push(readNpmEntry(entry, path, severity !== null));
      else skippedEntries++;
    }
    if (withdrawn !== null) return { status: "withdrawn", id };
    if (affected.length === 0) return { status: "skipped", id, skippedEntries };
    return {
      status: "accepted",
      skippedEntries,
      advisory: { id, modified, aliases, severity: severity ?? [], databaseSeverity, affected },
    };
  } catch (error) {
    if (error instanceof Invalid) return { status: "rejected", id, reason: error.message };
    throw error;
  }
}

/** The advisories read from a set of OSV records. */
export interface AdvisoryFeed {
  advisories: OsvAdvisory[];
  /** IDs of withdrawn records. */
  withdrawn: string[];
  /** IDs of records without npm entries. */
  skipped: string[];
  /** Entries of other ecosystems in accepted and skipped records. */
  skippedEntries: number;
  /** Rejected records. An ID with a rejected record is not used at all. */
  rejected: { id: string | null; reason: string }[];
}

/**
 * Reads a set of OSV records. An ID that has a rejected record, or more than
 * one record, is rejected as a whole: no record of it is used.
 */
export function readOsvFeed(texts: Iterable<string>): AdvisoryFeed {
  const results = Array.from(texts, readOsvRecord);
  const rejected: AdvisoryFeed["rejected"] = [];
  const rejectedIds = new Set<string>();
  const seen = new Map<string, number>();
  for (const result of results) {
    if (result.status === "rejected") {
      rejected.push({ id: result.id, reason: result.reason });
      if (result.id !== null) rejectedIds.add(result.id);
    } else {
      const id = result.status === "accepted" ? result.advisory.id : result.id;
      seen.set(id, (seen.get(id) ?? 0) + 1);
    }
  }
  for (const [id, count] of seen) {
    if (count > 1 && !rejectedIds.has(id)) {
      rejected.push({ id, reason: "duplicate id" });
      rejectedIds.add(id);
    }
  }
  const feed: AdvisoryFeed = {
    advisories: [],
    withdrawn: [],
    skipped: [],
    skippedEntries: 0,
    rejected,
  };
  for (const result of results) {
    if (result.status === "rejected") continue;
    const id = result.status === "accepted" ? result.advisory.id : result.id;
    if (rejectedIds.has(id)) continue;
    if (result.status === "accepted") {
      feed.advisories.push(result.advisory);
      feed.skippedEntries += result.skippedEntries;
    } else if (result.status === "skipped") {
      feed.skipped.push(id);
      feed.skippedEntries += result.skippedEntries;
    } else {
      feed.withdrawn.push(id);
    }
  }
  return feed;
}
