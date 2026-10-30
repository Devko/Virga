/**
 * A strict JSON parser for scanner reports (RFC 8259, nothing more).
 *
 * `JSON.parse` cannot enforce limits while it parses, silently keeps the
 * last of two duplicate keys and accepts lone surrogates. This parser checks
 * every limit as it goes, so an oversized array is refused before it is
 * built, and it rejects duplicate keys, lone surrogates (raw or escaped),
 * numbers that do not fit a double, a byte order mark and trailing data.
 * Objects become `Map`s, so a key such as `__proto__` is only a string.
 *
 * Memory follows what is built, not the byte count (R9-06): an empty object
 * is two bytes of text and about 100 bytes of heap. So containers and
 * values (object keys included) are counted, and every string is built flat.
 *
 * Errors carry a character offset, never the text around it.
 */

import { type RejectionReason, ScannerOutputRejected, type Tool } from "./errors.ts";
import type { Limits } from "./limits.ts";

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export type JsonObject = Map<string, JsonValue>;

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Longer number literals are refused; a double needs at most about 25 characters. */
const MAX_NUMBER_LENGTH = 64;
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;

const ESCAPES = new Map<number, string>([
  [0x22, '"'],
  [0x5c, "\\"],
  [0x2f, "/"],
  [0x62, "\b"],
  [0x66, "\f"],
  [0x6e, "\n"],
  [0x72, "\r"],
  [0x74, "\t"],
]);

/** Parses one report, enforcing `limits`. Throws only `ScannerOutputRejected`. */
export function parseJson(input: string | Uint8Array, limits: Limits, tool: Tool): JsonValue {
  const text = toText(input, limits, tool);
  return new Parser(text, limits, tool).document();
}

function toText(input: string | Uint8Array, limits: Limits, tool: Tool): string {
  const fail = (reason: RejectionReason, at = "/"): never => {
    throw new ScannerOutputRejected(tool, reason, at);
  };
  if (typeof input === "string") {
    // Every UTF-16 unit takes at least one UTF-8 byte.
    if (input.length > limits.maxBytes) fail("too_large");
    let bytes = 0;
    for (let i = 0; i < input.length; i++) {
      const c = input.charCodeAt(i);
      if (c < 0x80) bytes += 1;
      else if (c < 0x800) bytes += 2;
      else if (c >= 0xd800 && c <= 0xdbff) {
        const next = input.charCodeAt(i + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) fail("invalid_encoding", `offset ${i}`);
        bytes += 4;
        i++;
      } else if (c >= 0xdc00 && c <= 0xdfff) fail("invalid_encoding", `offset ${i}`);
      else bytes += 3;
    }
    if (bytes > limits.maxBytes) fail("too_large");
    return input;
  }
  if (!(input instanceof Uint8Array)) return fail("wrong_type");
  if (input.byteLength > limits.maxBytes) fail("too_large");
  try {
    return decoder.decode(input);
  } catch {
    return fail("invalid_encoding");
  }
}

/** True when every surrogate in `text` is part of a pair. */
export function isWellFormed(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0xd800 || c > 0xdfff) continue;
    if (c > 0xdbff) return false;
    const next = text.charCodeAt(i + 1);
    if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    i++;
  }
  return true;
}

class Parser {
  readonly text: string;
  readonly limits: Limits;
  readonly tool: Tool;
  pos = 0;
  values = 0;
  containers = 0;

  constructor(text: string, limits: Limits, tool: Tool) {
    this.text = text;
    this.limits = limits;
    this.tool = tool;
  }

  fail(reason: RejectionReason, at = this.pos): never {
    throw new ScannerOutputRejected(this.tool, reason, `offset ${at}`);
  }

  document(): JsonValue {
    const value = this.value(0);
    this.space();
    if (this.pos !== this.text.length) this.fail("invalid_json");
    return value;
  }

  space(): void {
    const t = this.text;
    let p = this.pos;
    while (p < t.length) {
      const c = t.charCodeAt(p);
      if (c !== 0x20 && c !== 0x0a && c !== 0x0d && c !== 0x09) break;
      p++;
    }
    this.pos = p;
  }

  /** Counts one value or key; containers count once more, against their own limit. */
  count(container: boolean): void {
    if (++this.values > this.limits.maxValues) this.fail("too_many_values");
    if (container && ++this.containers > this.limits.maxContainers) this.fail("too_many_values");
  }

  value(depth: number): JsonValue {
    this.space();
    const c = this.text.charCodeAt(this.pos);
    this.count(c === 0x7b || c === 0x5b);
    switch (c) {
      case 0x7b:
        return this.object(depth + 1);
      case 0x5b:
        return this.array(depth + 1);
      case 0x22:
        return this.string();
      case 0x74:
        return this.literal("true", true);
      case 0x66:
        return this.literal("false", false);
      case 0x6e:
        return this.literal("null", null);
      default:
        if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return this.number();
        return this.fail("invalid_json");
    }
  }

  literal<T extends JsonValue>(word: string, value: T): T {
    if (!this.text.startsWith(word, this.pos)) this.fail("invalid_json");
    this.pos += word.length;
    return value;
  }

  object(depth: number): JsonObject {
    if (depth > this.limits.maxDepth) this.fail("too_deep");
    this.pos++;
    const out: JsonObject = new Map();
    this.space();
    if (this.text.charCodeAt(this.pos) === 0x7d) {
      this.pos++;
      return out;
    }
    for (;;) {
      this.space();
      const keyAt = this.pos;
      if (this.text.charCodeAt(keyAt) !== 0x22) this.fail("invalid_json");
      // A key costs a string and an entry, like a value.
      this.count(false);
      const key = this.string();
      if (out.has(key)) this.fail("duplicate_key", keyAt);
      if (out.size >= this.limits.maxObjectKeys) this.fail("too_many_keys", keyAt);
      this.space();
      if (this.text.charCodeAt(this.pos) !== 0x3a) this.fail("invalid_json");
      this.pos++;
      out.set(key, this.value(depth));
      this.space();
      const c = this.text.charCodeAt(this.pos);
      this.pos++;
      if (c === 0x7d) return out;
      if (c !== 0x2c) this.fail("invalid_json", this.pos - 1);
    }
  }

  array(depth: number): JsonValue[] {
    if (depth > this.limits.maxDepth) this.fail("too_deep");
    this.pos++;
    const out: JsonValue[] = [];
    this.space();
    if (this.text.charCodeAt(this.pos) === 0x5d) {
      this.pos++;
      return out;
    }
    for (;;) {
      if (out.length >= this.limits.maxArrayItems) this.fail("too_many_items");
      out.push(this.value(depth));
      this.space();
      const c = this.text.charCodeAt(this.pos);
      this.pos++;
      if (c === 0x5d) return out;
      if (c !== 0x2c) this.fail("invalid_json", this.pos - 1);
    }
  }

  string(): string {
    const t = this.text;
    const max = this.limits.maxStringLength;
    const begin = this.pos;
    let p = begin + 1;
    let start = p;
    // The pieces of a string with escapes, joined once at the end. `out +=`
    // per escape builds a rope of one node per escape, which V8 keeps as it
    // is: 16 MiB of `\n` escapes kept 260 MB in Node (R9-06).
    let parts: string[] | null = null;
    let length = 0;
    let unicodeEscape = false;
    for (;;) {
      if (p >= t.length) this.fail("invalid_json", p);
      const c = t.charCodeAt(p);
      if (c === 0x22) break;
      if (c < 0x20) this.fail("invalid_json", p);
      if (c !== 0x5c) {
        p++;
        if (length + (p - start) > max) this.fail("string_too_long", begin);
        continue;
      }
      parts ??= [];
      if (p > start) parts.push(t.slice(start, p));
      length += p - start;
      const e = t.charCodeAt(p + 1);
      if (e === 0x75) {
        const hex = t.slice(p + 2, p + 6);
        if (!HEX4.test(hex)) this.fail("invalid_json", p);
        parts.push(String.fromCharCode(Number.parseInt(hex, 16)));
        unicodeEscape = true;
        p += 6;
      } else {
        const ch = ESCAPES.get(e);
        if (ch === undefined) this.fail("invalid_json", p);
        parts.push(ch);
        p += 2;
      }
      length += 1;
      start = p;
      if (length > max) this.fail("string_too_long", begin);
    }
    if (parts !== null && p > start) parts.push(t.slice(start, p));
    const out = parts === null ? t.slice(start, p) : parts.join("");
    this.pos = p + 1;
    // Raw lone surrogates were refused with the encoding; escapes can still make one.
    if (unicodeEscape && !isWellFormed(out)) this.fail("invalid_text", begin);
    return out;
  }

  number(): number {
    NUMBER.lastIndex = this.pos;
    const match = NUMBER.exec(this.text);
    if (!match) return this.fail("invalid_json");
    const literal = match[0];
    if (literal.length > MAX_NUMBER_LENGTH) this.fail("number_out_of_range");
    const value = Number(literal);
    if (!Number.isFinite(value)) this.fail("number_out_of_range");
    this.pos += literal.length;
    return value;
  }
}
