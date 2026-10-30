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

export type Parsed = { ok: true; value: JsonObject } | { ok: false; reason: string };

/** Parses text of at most `maxBytes` UTF-8 bytes that must hold a JSON object. */
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
