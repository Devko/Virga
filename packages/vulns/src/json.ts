/** Helpers for reading untrusted JSON strictly. */

export type JsonObject = Record<string, unknown>;

export const isObject = (value: unknown): value is JsonObject =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** An own property only: `constructor` or `__proto__` never read through the prototype. */
export const own = (object: JsonObject, key: string): unknown =>
  Object.hasOwn(object, key) ? object[key] : undefined;

/** UTF-8 length of `text`, counted until it exceeds `stopAbove`. */
export function utf8Length(text: string, stopAbove: number): number {
  let bytes = 0;
  for (let i = 0; i < text.length && bytes <= stopAbove; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      bytes += 4;
      i++;
    } else bytes += 3;
  }
  return bytes;
}

export interface RepeatedKeys {
  /** Offset of the first repeated key, in UTF-16 code units. */
  offset: number;
  /** Every top-level key that occurs more than once. */
  topLevel: Set<string>;
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;

/**
 * Finds keys that occur more than once in one object of `text`, which must
 * be valid JSON: `JSON.parse` has accepted it. `JSON.parse` keeps the last
 * value of a repeated key, so another reader of the same text may see
 * another record. Keys compare as JSON decodes them, so `"id"` and
 * `"id"` are the same key. The whole text is scanned, so `topLevel`
 * names every repeated top-level key. Null when no key repeats.
 */
export function repeatedKeys(text: string): RepeatedKeys | null {
  // The keys of each open object; null for an open array.
  const open: (Set<string> | null)[] = [];
  const topLevel = new Set<string>();
  let offset = -1;
  let keyNext = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === QUOTE) {
      const start = i;
      let escaped = false;
      for (i++; i < text.length && text.charCodeAt(i) !== QUOTE; i++) {
        if (text.charCodeAt(i) === BACKSLASH) {
          escaped = true;
          i++;
        }
      }
      if (!keyNext) continue;
      keyNext = false;
      const keys = open[open.length - 1] as Set<string>;
      const key = escaped
        ? (JSON.parse(text.slice(start, i + 1)) as string)
        : text.slice(start + 1, i);
      if (!keys.has(key)) keys.add(key);
      else {
        if (offset === -1) offset = start;
        if (open.length === 1) topLevel.add(key);
      }
    } else if (c === 0x7b) {
      open.push(new Set());
      keyNext = true;
    } else if (c === 0x5b) {
      open.push(null);
      keyNext = false;
    } else if (c === 0x7d || c === 0x5d) {
      open.pop();
      keyNext = false;
    } else if (c === 0x2c) {
      keyNext = open[open.length - 1] instanceof Set;
    }
  }
  return offset === -1 ? null : { offset, topLevel };
}

export type Parsed =
  | { ok: true; value: JsonObject }
  | {
      ok: false;
      reason: string;
      /**
       * Only after a repeated key: the top-level members whose key occurs
       * once, so a reader can name what it rejects (an ID). Never read as
       * the input.
       */
      unique?: JsonObject;
    };

/**
 * Parses text of at most `maxBytes` UTF-8 bytes that must hold a JSON
 * object. A key that occurs twice in one object rejects the text: what
 * `JSON.parse` makes of it (the last value) need not be what the source
 * meant.
 */
export function parseObject(text: unknown, maxBytes: number): Parsed {
  if (typeof text !== "string") return { ok: false, reason: "not text" };
  if (text.length > maxBytes || utf8Length(text, maxBytes) > maxBytes) {
    return { ok: false, reason: `larger than ${maxBytes} bytes` };
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, reason: "not valid JSON" };
  }
  if (!isObject(value)) return { ok: false, reason: "not a JSON object" };
  const repeated = repeatedKeys(text);
  if (repeated) {
    // fromEntries defines own properties, so a key `__proto__` stays data.
    const unique = Object.fromEntries(
      Object.entries(value).filter(([key]) => !repeated.topLevel.has(key)),
    );
    return { ok: false, reason: `duplicate key at offset ${repeated.offset}`, unique };
  }
  return { ok: true, value };
}

/** A reason to refuse a whole input. Its message holds a path and a problem, never input text. */
export class Invalid extends Error {}

export const invalid = (path: string, problem: string): never => {
  throw new Invalid(`${path}: ${problem}`);
};

/** A string property; null when missing or null, unless it is required. */
export function readString(
  object: JsonObject,
  key: string,
  path: string,
  max: number,
  required = false,
): string | null {
  const value = own(object, key);
  if (value === undefined || value === null) return required ? invalid(path, "missing") : null;
  if (typeof value !== "string") return invalid(path, "not a string");
  if (value.length > max) return invalid(path, `longer than ${max} characters`);
  return value;
}

/** An array property of at most `max` entries; null when missing or null. */
export function readArray(
  object: JsonObject,
  key: string,
  path: string,
  max: number,
): unknown[] | null {
  const value = own(object, key);
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value)) return invalid(path, "not an array");
  if (value.length > max) return invalid(path, `more than ${max} entries`);
  return value;
}

export function asObject(value: unknown, path: string): JsonObject {
  return isObject(value) ? value : invalid(path, "not an object");
}
