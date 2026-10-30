// Validation against the vendored CycloneDX 1.6 JSON schema (decision 0010),
// with @cfworker/json-schema. Test code only: the guard below changes the
// validator's format table, and nothing in src/ may.
//
// The validator implements `date-time` and `uri`, which the schemas use, but
// not `iri-reference` or `idn-email`, and it passes a format it does not
// know. So both names get a function that records the hit and fails the
// value: a document that reaches either fails its test, and nothing is
// skipped. If the validator ever brings its own entry for either name, the
// guard would stop applying unseen, so that fails a test too.

import { readFileSync } from "node:fs";
import { format, type Schema, Validator } from "@cfworker/json-schema";

export const SCHEMA_DIR = new URL("./schema/cyclonedx-1.6/", import.meta.url);
export const SCHEMA_FILES = ["bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"];

/** Formats the vendored schema uses that the validator does not implement. */
export const UNCHECKED_FORMATS = ["iri-reference", "idn-email"] as const;

const table = format as Record<string, ((value: string) => boolean) | undefined>;

/** Formats the validator implements itself, taken before the guard is added. */
export const VALIDATOR_FORMATS: ReadonlySet<string> = new Set(Object.keys(table));

/** Unchecked formats the validator already had an entry for (must stay empty). */
export const OWN_ENTRIES = UNCHECKED_FORMATS.filter((name) => Object.hasOwn(table, name));

const hits: string[] = [];
for (const name of UNCHECKED_FORMATS) {
  table[name] = () => {
    hits.push(name);
    return false;
  };
}

/** A schema file, parsed fresh: the validator annotates the objects it is given. */
export const loadSchema = (name: string): Schema =>
  JSON.parse(readFileSync(new URL(name, SCHEMA_DIR), "utf8")) as Schema;

const validator = new Validator(loadSchema("bom-1.6.schema.json"), "7", false);
validator.addSchema(loadSchema("spdx.schema.json"));
validator.addSchema(loadSchema("jsf-0.82.schema.json"));

/**
 * Problems with a document under the schema: the validator's errors, plus
 * one for every unchecked format the document reached. Empty when valid.
 * An unresolved `$ref` throws.
 */
export function schemaProblems(doc: unknown): string[] {
  hits.length = 0;
  const result = validator.validate(doc);
  const problems = result.valid
    ? []
    : result.errors.map((e) => `${e.instanceLocation} ${e.keywordLocation}: ${e.error}`);
  for (const name of new Set(hits)) {
    problems.push(`reached format ${name}, which the validator cannot check`);
  }
  return problems;
}
