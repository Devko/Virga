/**
 * CycloneDX 1.6 JSON SBOM for one Worker version.
 *
 * The generator returns a plain JSON value, and `serializeSbom` turns it
 * into the bytes that are stored. Strings from the scanned account (script
 * name, package names and versions) are only ever values in that JSON:
 * `JSON.stringify` escapes them, nothing is concatenated into JSON text.
 *
 * `checkSbom` is a structural self-check of what this module emits; the
 * generator runs it on every document. Validation against the official
 * CycloneDX 1.6 JSON schema (phase 2, gate 2) runs in the tests, on
 * `JSON.parse(serializeSbom(bom))` of every SBOM they build (decision 0010).
 */

import { compare } from "./fields.ts";
import { FIELD_LIMITS, ID, isCleanText, isPurl } from "./text.ts";

export const CYCLONEDX_SPEC_VERSION = "1.6";
export const CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json";

/** Where a package was detected, as on the graph's `CONTAINS` edge. */
export const PACKAGE_SOURCES = ["package_dependencies", "sourcemap", "banner", "sbom"] as const;
export type PackageSource = (typeof PACKAGE_SOURCES)[number];

/** Ordinal confidence as in the graph: 0 low, 1 medium, 2 high. */
export type Confidence = 0 | 1 | 2;
const CONFIDENCE_LABELS = ["low", "medium", "high"] as const;

export const PROPERTY_CONFIDENCE = "virga:confidence";
export const PROPERTY_SOURCE = "virga:source";
const TOOL_NAME = "virga";

export interface SbomPackage {
  purl: string;
  name: string;
  version: string;
  source: PackageSource;
  confidence: Confidence;
}

export interface WorkerSbomInput {
  worker: { scriptName: string; versionId: string };
  packages: readonly SbomPackage[];
  /** Virga's own version. */
  tool: { version: string };
  /** When the packages were collected, in epoch milliseconds. */
  timestamp: number;
  /** A `urn:uuid:` URN; a random one from `crypto.randomUUID()` when omitted. */
  serialNumber?: string;
}

export interface CdxProperty {
  name: string;
  value: string;
}

export interface CdxComponent {
  type: "application" | "library";
  "bom-ref": string;
  name: string;
  version: string;
  purl?: string;
  properties?: CdxProperty[];
}

export interface CdxTool {
  type: "application";
  name: string;
  version: string;
}

export interface CycloneDxBom {
  $schema: typeof CYCLONEDX_SCHEMA;
  bomFormat: "CycloneDX";
  specVersion: typeof CYCLONEDX_SPEC_VERSION;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { components: CdxTool[] };
    component: CdxComponent;
  };
  components: CdxComponent[];
}

/** Bad generator input. The message names the field, never its value. */
export class SbomInputError extends Error {
  override readonly name = "SbomInputError";
  readonly at: string;

  constructor(at: string, problem: string) {
    super(`SBOM input refused: ${at} ${problem}`);
    this.at = at;
  }
}

/** The pattern of the CycloneDX 1.6 schema for `serialNumber`, URN form. */
const SERIAL = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const LAST_TIME = Date.UTC(9999, 11, 31, 23, 59, 59, 999);
const TOOL_VERSION_MAX = 64;

function text(value: unknown, at: string, max: number): string {
  if (typeof value !== "string") throw new SbomInputError(at, "is not text");
  if (value.length === 0 || value.length > max) throw new SbomInputError(at, "has a bad length");
  if (!isCleanText(value)) throw new SbomInputError(at, "has control or invisible characters");
  return value;
}

function checkPackage(pkg: SbomPackage, at: string): SbomPackage {
  if (typeof pkg.purl !== "string" || !isPurl(pkg.purl)) {
    throw new SbomInputError(`${at}/purl`, "is not a purl");
  }
  if (!PACKAGE_SOURCES.includes(pkg.source)) throw new SbomInputError(`${at}/source`, "is unknown");
  if (![0, 1, 2].includes(pkg.confidence)) {
    throw new SbomInputError(`${at}/confidence`, "is not 0, 1 or 2");
  }
  return {
    purl: pkg.purl,
    name: text(pkg.name, `${at}/name`, FIELD_LIMITS.name),
    version: text(pkg.version, `${at}/version`, FIELD_LIMITS.version),
    source: pkg.source,
    confidence: pkg.confidence,
  };
}

/** Higher confidence wins; then the source listed first, then name and version. */
function better(a: SbomPackage, b: SbomPackage): SbomPackage {
  if (a.confidence !== b.confidence) return a.confidence > b.confidence ? a : b;
  const order = PACKAGE_SOURCES.indexOf(a.source) - PACKAGE_SOURCES.indexOf(b.source);
  if (order !== 0) return order < 0 ? a : b;
  return (compare(a.name, b.name) || compare(a.version, b.version)) <= 0 ? a : b;
}

/** A CycloneDX 1.6 SBOM for one Worker version. Throws `SbomInputError` on bad input. */
export function buildWorkerSbom(input: WorkerSbomInput): CycloneDxBom {
  const scriptName = text(input.worker.scriptName, "/worker/scriptName", FIELD_LIMITS.path);
  const versionId = text(input.worker.versionId, "/worker/versionId", FIELD_LIMITS.id);
  if (!ID.test(versionId)) throw new SbomInputError("/worker/versionId", "is not an ID");
  const toolVersion = text(input.tool.version, "/tool/version", TOOL_VERSION_MAX);
  const ts = input.timestamp;
  if (!Number.isSafeInteger(ts) || ts < 0 || ts > LAST_TIME) {
    throw new SbomInputError("/timestamp", "is not a time");
  }
  const serialNumber = input.serialNumber ?? `urn:uuid:${crypto.randomUUID()}`;
  if (!SERIAL.test(serialNumber)) throw new SbomInputError("/serialNumber", "is not a UUID URN");

  const byPurl = new Map<string, SbomPackage>();
  input.packages.forEach((raw, i) => {
    const pkg = checkPackage(raw, `/packages/${i}`);
    const known = byPurl.get(pkg.purl);
    byPurl.set(pkg.purl, known ? better(known, pkg) : pkg);
  });
  const components = [...byPurl.keys()].sort(compare).map((purl): CdxComponent => {
    const pkg = byPurl.get(purl) as SbomPackage;
    return {
      type: "library",
      "bom-ref": purl,
      name: pkg.name,
      version: pkg.version,
      purl,
      properties: [
        { name: PROPERTY_CONFIDENCE, value: CONFIDENCE_LABELS[pkg.confidence] },
        { name: PROPERTY_SOURCE, value: pkg.source },
      ],
    };
  });

  const bom: CycloneDxBom = {
    $schema: CYCLONEDX_SCHEMA,
    bomFormat: "CycloneDX",
    specVersion: CYCLONEDX_SPEC_VERSION,
    serialNumber,
    version: 1,
    metadata: {
      timestamp: new Date(ts).toISOString(),
      tools: { components: [{ type: "application", name: TOOL_NAME, version: toolVersion }] },
      component: {
        type: "application",
        "bom-ref": `worker_version:${versionId}`,
        name: scriptName,
        version: versionId,
      },
    },
    components,
  };
  const problems = checkSbom(bom);
  if (problems.length > 0) throw new Error(`SBOM self-check failed: ${problems.join("; ")}`);
  return bom;
}

/** The stored form: compact JSON, member order as built. */
export const serializeSbom = (bom: CycloneDxBom): string => JSON.stringify(bom);

const BOM_KEYS = [
  "$schema",
  "bomFormat",
  "specVersion",
  "serialNumber",
  "version",
  "metadata",
  "components",
];
const METADATA_KEYS = ["timestamp", "tools", "component"];
const TOOL_KEYS = ["type", "name", "version"];
const COMPONENT_KEYS = ["type", "bom-ref", "name", "version", "purl", "properties"];
/** `component.type` values of the CycloneDX 1.6 schema. */
const COMPONENT_TYPES = new Set([
  "application",
  "framework",
  "library",
  "container",
  "platform",
  "operating-system",
  "device",
  "device-driver",
  "firmware",
  "file",
  "machine-learning-model",
  "data",
  "cryptographic-asset",
]);

type Obj = Record<string, unknown>;
const isObject = (value: unknown): value is Obj =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const isText = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && isCleanText(value);

function validTimestamp(value: unknown): boolean {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString().slice(0, 19) === value.slice(0, 19);
}

/**
 * Problems in an SBOM, as paths and short descriptions without values; empty
 * when the document has the structure this module emits. Stricter than the
 * schema where Virga is: only the members listed above, components sorted by
 * purl, `bom-ref` equal to the purl, and both Virga properties present.
 */
export function checkSbom(doc: unknown): string[] {
  const problems: string[] = [];
  const problem = (at: string, what: string): void => {
    problems.push(`${at} ${what}`);
  };
  const onlyKeys = (value: Obj, allowed: string[], at: string) => {
    for (const key of Object.keys(value)) {
      if (!allowed.includes(key)) problem(at, "has an unexpected member");
    }
  };
  if (!isObject(doc)) return ["/ is not an object"];
  onlyKeys(doc, BOM_KEYS, "/");
  if (doc.$schema !== undefined && doc.$schema !== CYCLONEDX_SCHEMA) {
    problem("/$schema", "is not the 1.6 schema");
  }
  if (doc.bomFormat !== "CycloneDX") problem("/bomFormat", "is not CycloneDX");
  if (doc.specVersion !== CYCLONEDX_SPEC_VERSION) problem("/specVersion", "is not 1.6");
  if (typeof doc.serialNumber !== "string" || !SERIAL.test(doc.serialNumber)) {
    problem("/serialNumber", "is not a UUID URN");
  }
  if (!Number.isInteger(doc.version) || (doc.version as number) < 1) {
    problem("/version", "is not a positive integer");
  }

  const refs = new Set<string>();
  const checkComponent = (value: unknown, at: string, isPackage: boolean) => {
    if (!isObject(value)) return problem(at, "is not an object");
    onlyKeys(value, COMPONENT_KEYS, at);
    if (typeof value.type !== "string" || !COMPONENT_TYPES.has(value.type)) {
      problem(`${at}/type`, "is not a component type");
    } else if (isPackage && value.type !== "library") {
      problem(`${at}/type`, "is not library");
    }
    if (!isText(value.name)) problem(`${at}/name`, "is not text");
    if (!isText(value.version)) problem(`${at}/version`, "is not text");
    const ref = value["bom-ref"];
    if (!isText(ref)) problem(`${at}/bom-ref`, "is not text");
    else if (refs.has(ref)) problem(`${at}/bom-ref`, "is not unique");
    else refs.add(ref);
    if (!isPackage) return;
    if (typeof value.purl !== "string" || !isPurl(value.purl))
      problem(`${at}/purl`, "is not a purl");
    else if (ref !== value.purl) problem(`${at}/bom-ref`, "is not the purl");
    checkProperties(value.properties, `${at}/properties`);
  };
  const checkProperties = (value: unknown, at: string) => {
    if (!Array.isArray(value) || value.length !== 2) return problem(at, "is not two properties");
    value.forEach((p, i) => {
      if (!isObject(p)) {
        problem(`${at}/${i}`, "is not an object");
      } else {
        onlyKeys(p, ["name", "value"], `${at}/${i}`);
        if (typeof p.value !== "string") problem(`${at}/${i}/value`, "is not text");
      }
    });
    const [confidence, source] = value as Obj[];
    if (
      confidence?.name !== PROPERTY_CONFIDENCE ||
      !(CONFIDENCE_LABELS as readonly unknown[]).includes(confidence?.value)
    ) {
      problem(`${at}/0`, "is not a confidence");
    }
    if (
      source?.name !== PROPERTY_SOURCE ||
      !(PACKAGE_SOURCES as readonly unknown[]).includes(source?.value)
    ) {
      problem(`${at}/1`, "is not a source");
    }
  };

  const metadata = doc.metadata;
  if (!isObject(metadata)) {
    problem("/metadata", "is not an object");
  } else {
    onlyKeys(metadata, METADATA_KEYS, "/metadata");
    if (!validTimestamp(metadata.timestamp)) problem("/metadata/timestamp", "is not a UTC time");
    const tools = metadata.tools;
    if (!isObject(tools) || !Array.isArray(tools.components) || tools.components.length === 0) {
      problem("/metadata/tools", "is not an object with components");
    } else {
      onlyKeys(tools, ["components"], "/metadata/tools");
      tools.components.forEach((tool: unknown, i: number) => {
        const at = `/metadata/tools/components/${i}`;
        if (!isObject(tool)) {
          problem(at, "is not an object");
          return;
        }
        onlyKeys(tool, TOOL_KEYS, at);
        if (tool.type !== "application") problem(`${at}/type`, "is not application");
        if (!isText(tool.name) || !isText(tool.version)) problem(at, "lacks name or version");
      });
    }
    if (metadata.component === undefined) problem("/metadata/component", "is missing");
    else checkComponent(metadata.component, "/metadata/component", false);
  }

  if (!Array.isArray(doc.components)) {
    problem("/components", "is not a list");
  } else {
    let previous: string | null = null;
    doc.components.forEach((c: unknown, i: number) => {
      checkComponent(c, `/components/${i}`, true);
      const purl = isObject(c) && typeof c.purl === "string" ? c.purl : null;
      if (purl !== null && previous !== null && compare(previous, purl) >= 0) {
        problem(`/components/${i}`, "is out of order");
      }
      if (purl !== null) previous = purl;
    });
  }
  return problems;
}
