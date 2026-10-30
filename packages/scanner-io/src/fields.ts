/**
 * Typed access to a parsed report. Every accessor checks one member and
 * throws a `ScannerOutputRejected` with a JSON pointer built from the field
 * names below and array indices, never from keys or values of the report.
 */

import { type RejectionReason, ScannerOutputRejected, type Tool } from "./errors.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { containsCloudflareToken, FIELD_LIMITS, ID, isCleanText, isPurl } from "./text.ts";

/** Upper bound for line numbers. */
const MAX_LINE = 2 ** 31 - 1;

export class Fields {
  readonly tool: Tool;

  constructor(tool: Tool) {
    this.tool = tool;
  }

  fail(reason: RejectionReason, at: string): never {
    throw new ScannerOutputRejected(this.tool, reason, at === "" ? "/" : at);
  }

  object(value: JsonValue | undefined, at: string): JsonObject {
    if (value === undefined) this.fail("missing_field", at);
    if (!(value instanceof Map)) this.fail("wrong_type", at);
    return value;
  }

  array(value: JsonValue | undefined, at: string, maxItems: number): JsonValue[] {
    if (value === undefined) this.fail("missing_field", at);
    if (!Array.isArray(value)) this.fail("wrong_type", at);
    if (value.length > maxItems) this.fail("too_many_items", at);
    return value;
  }

  /** A list that may be missing or `null` (Go writes a nil slice as `null`). */
  optionalArray(obj: JsonObject, key: string, at: string, maxItems: number): JsonValue[] {
    const value = obj.get(key);
    if (value === undefined || value === null) return [];
    return this.array(value, `${at}/${key}`, maxItems);
  }

  optionalObject(obj: JsonObject, key: string, at: string): JsonObject | null {
    const value = obj.get(key);
    if (value === undefined || value === null) return null;
    return this.object(value, `${at}/${key}`);
  }

  string(obj: JsonObject, key: string, at: string): string {
    const value = obj.get(key);
    if (value === undefined) this.fail("missing_field", `${at}/${key}`);
    if (typeof value !== "string") this.fail("wrong_type", `${at}/${key}`);
    return value;
  }

  optionalString(obj: JsonObject, key: string, at: string): string | null {
    const value = obj.get(key);
    if (value === undefined || value === null) return null;
    if (typeof value !== "string") this.fail("wrong_type", `${at}/${key}`);
    return value;
  }

  /** An integer in [min, max]. */
  integer(obj: JsonObject, key: string, at: string, min = 0, max = MAX_LINE): number {
    const value = obj.get(key);
    if (value === undefined) this.fail("missing_field", `${at}/${key}`);
    if (typeof value !== "number" || !Number.isInteger(value))
      this.fail("wrong_type", `${at}/${key}`);
    if (value < min || value > max) this.fail("out_of_range", `${at}/${key}`);
    return value;
  }

  /**
   * A display string that leaves the reader: length, no controls, and no
   * Cloudflare token inside it.
   */
  text(value: string, at: string, max: number, allowEmpty = false): string {
    if (value.length > max) this.fail("string_too_long", at);
    if (!allowEmpty && value.length === 0) this.fail("invalid_format", at);
    if (!isCleanText(value)) this.fail("invalid_text", at);
    if (containsCloudflareToken(value)) this.fail("secret_in_kept_field", at);
    return value;
  }

  /** An identifier that leaves the reader: length and pattern. */
  matching(value: string, at: string, pattern: RegExp, max: number): string {
    if (value.length > max) this.fail("string_too_long", at);
    if (!pattern.test(value)) this.fail("invalid_format", at);
    if (containsCloudflareToken(value)) this.fail("secret_in_kept_field", at);
    return value;
  }

  id(obj: JsonObject, key: string, at: string): string {
    return this.matching(this.string(obj, key, at), `${at}/${key}`, ID, FIELD_LIMITS.id);
  }

  /** A list of advisory IDs, sorted and without duplicates. */
  idList(obj: JsonObject, key: string, at: string): string[] {
    const items = this.optionalArray(obj, key, at, FIELD_LIMITS.aliases);
    const out = new Set<string>();
    items.forEach((item, i) => {
      const itemAt = `${at}/${key}/${i}`;
      if (typeof item !== "string") this.fail("wrong_type", itemAt);
      out.add(this.matching(item, itemAt, ID, FIELD_LIMITS.id));
    });
    return [...out].sort(compare);
  }

  purl(value: string, at: string): string {
    if (value.length > FIELD_LIMITS.purl) this.fail("string_too_long", at);
    if (!isPurl(value)) this.fail("invalid_format", at);
    if (containsCloudflareToken(value)) this.fail("secret_in_kept_field", at);
    return value;
  }
}

/** Code-unit order: locale-independent and the same everywhere. */
export const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
