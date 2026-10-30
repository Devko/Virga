// A deterministic mutation fuzzer for scanner reports. No dependency: a seeded
// PRNG picks mutations of a valid sample, on the parsed value and on the text.

import type { Limits } from "../src/limits.ts";
import {
  BYTE_ORDER_MARK,
  LEFT_TO_RIGHT_ISOLATE,
  LINE_SEPARATOR,
  NONCHARACTER,
  PARAGRAPH_SEPARATOR,
  RIGHT_TO_LEFT_OVERRIDE,
} from "./chars.ts";

/** mulberry32: small, fast and good enough to pick mutations. */
export function prng(seed: number) {
  let state = seed >>> 0;
  const next = (): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number): number => Math.floor(next() * n);
  const pick = <T>(items: readonly T[]): T => items[int(items.length)] as T;
  return { next, int, pick, chance: (p: number) => next() < p };
}

export type Rng = ReturnType<typeof prng>;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Slot = { get: () => Json; set: (value: Json) => void; remove?: () => void };

/** Every place in the document that holds a value, the root included. */
function slots(root: { value: Json }): Slot[] {
  const out: Slot[] = [{ get: () => root.value, set: (v) => (root.value = v) }];
  const walk = (value: Json) => {
    if (Array.isArray(value)) {
      value.forEach((item, i) => {
        out.push({
          get: () => value[i] as Json,
          set: (v) => (value[i] = v),
          remove: () => value.splice(i, 1),
        });
        walk(item);
      });
    } else if (value !== null && typeof value === "object") {
      for (const key of Object.keys(value)) {
        out.push({
          get: () => value[key] as Json,
          set: (v) => define(value, key, v),
          remove: () => delete value[key],
        });
        walk(value[key] as Json);
      }
    }
  };
  walk(root.value);
  return out;
}

/** Sets a member without invoking the `__proto__` setter. */
function define(target: { [key: string]: Json }, key: string, value: Json) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

const FIELD_NAMES = [
  "results",
  "packages",
  "package",
  "name",
  "version",
  "ecosystem",
  "vulnerabilities",
  "id",
  "aliases",
  "groups",
  "ids",
  "max_severity",
  "affected",
  "ranges",
  "events",
  "fixed",
  "database_specific",
  "severity",
  "SchemaVersion",
  "Results",
  "Target",
  "Type",
  "Packages",
  "Vulnerabilities",
  "Secrets",
  "VulnerabilityID",
  "PkgName",
  "PkgID",
  "PkgIdentifier",
  "PURL",
  "InstalledVersion",
  "FixedVersion",
  "Severity",
  "VendorIDs",
  "Identifier",
  "Release",
  "Epoch",
  "RuleID",
  "StartLine",
  "EndLine",
  "File",
  "Secret",
  "Match",
  "__proto__",
  "constructor",
];

const ODD_CHARS = [
  "\u0000",
  "\u0001",
  "\u001f",
  "\u007f",
  "\u0085",
  LINE_SEPARATOR,
  PARAGRAPH_SEPARATOR,
  RIGHT_TO_LEFT_OVERRIDE,
  LEFT_TO_RIGHT_ISOLATE,
  "\ud800",
  "\udfff",
  BYTE_ORDER_MARK,
  NONCHARACTER,
  "😀",
  "\\",
  '"',
  "<",
  "%",
  "/",
  " ",
  "é",
];

function randomScalar(rng: Rng, limits: Limits): Json {
  switch (rng.int(9)) {
    case 0:
      return null;
    case 1:
      return rng.chance(0.5);
    case 2:
      return rng.pick([0, -1, 1.5, 2 ** 31, 2 ** 53 + 2, -0, 1e308, 3]);
    case 3:
      return "";
    case 4:
      return rng.pick(["CVE-2021-0001", "pkg:npm/x@1", "UNKNOWN", "HIGH", "npm", "cfk_x"]);
    case 5:
      return "x".repeat(rng.pick([129, 257, 513, 1025, limits.maxStringLength + 1]));
    case 6:
      return `a${rng.pick(ODD_CHARS)}b`;
    case 7:
      return [];
    default:
      return {};
  }
}

function randomValue(rng: Rng, limits: Limits, depth = 0): Json {
  if (depth > 2 || rng.chance(0.6)) return randomScalar(rng, limits);
  if (rng.chance(0.5)) {
    return Array.from({ length: rng.int(4) }, () => randomValue(rng, limits, depth + 1));
  }
  const out: { [key: string]: Json } = {};
  for (let i = rng.int(4); i > 0; i--)
    define(out, rng.pick(FIELD_NAMES), randomValue(rng, limits, depth + 1));
  return out;
}

const typeOf = (v: Json): string => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);

/** One mutation of the parsed document. */
function mutateValue(root: { value: Json }, rng: Rng, limits: Limits): void {
  const all = slots(root);
  const slot = rng.pick(all);
  const current = slot.get();
  switch (rng.int(10)) {
    case 0: {
      // Wrong type.
      let next = randomValue(rng, limits);
      for (let i = 0; i < 4 && typeOf(next) === typeOf(current); i++)
        next = randomValue(rng, limits);
      slot.set(next);
      return;
    }
    case 1:
      // Missing field or item.
      if (slot.remove) slot.remove();
      return;
    case 2:
      // Extra field.
      if (current !== null && typeof current === "object" && !Array.isArray(current)) {
        define(current, rng.pick(FIELD_NAMES), randomValue(rng, limits));
      }
      return;
    case 3:
      // Huge string.
      if (typeof current === "string") {
        const size = rng.pick([129, 257, 513, 1025, limits.maxStringLength + 1]);
        slot.set(current + "y".repeat(Math.max(0, size - current.length)));
      }
      return;
    case 4: {
      // Huge array: more items than the parser or a reader allows.
      if (!Array.isArray(current)) return;
      const first = current[0] ?? 0;
      const size = rng.pick([
        limits.maxArrayItems + 1,
        limits.maxPackages + 1,
        limits.maxSecrets + 1,
        101,
      ]);
      // Keep the text below a few megabytes, whatever the limits.
      const item = (JSON.stringify(first) ?? "").length * size > 4_000_000 ? 0 : first;
      slot.set(Array.from({ length: size }, () => structuredClone(item)));
      return;
    }
    case 5: {
      // Deep nesting.
      let value = current;
      for (let i = limits.maxDepth + rng.int(4) - 2; i > 0; i--) {
        value = rng.chance(0.5) ? [value] : { a: value };
      }
      slot.set(value);
      return;
    }
    case 6:
      // Odd characters: invalid UTF-16, NUL and other controls, bidi, markup.
      if (typeof current === "string") {
        const at = rng.int(current.length + 1);
        slot.set(current.slice(0, at) + rng.pick(ODD_CHARS) + current.slice(at));
      }
      return;
    case 7:
      // Edge numbers.
      if (typeof current === "number") {
        slot.set(rng.pick([-1, 0, 1.5, 2 ** 31, 2 ** 53, -0, current + 1, current - 1]));
      }
      return;
    case 8: {
      // Duplicated item, to exercise merging.
      if (Array.isArray(current) && current.length > 0) {
        current.push(structuredClone(rng.pick(current)));
      }
      return;
    }
    default:
      // Empty container.
      if (Array.isArray(current)) slot.set([]);
      else if (current !== null && typeof current === "object") slot.set({});
  }
}

const QUOTED_KEY = /"([A-Za-z_]+)":/g;

/** One mutation of the JSON text. */
function mutateText(text: string, rng: Rng, limits: Limits): string {
  switch (rng.int(9)) {
    case 0: {
      // Duplicate key: repeat a member in front of itself.
      const keys = [...text.matchAll(QUOTED_KEY)];
      if (keys.length === 0) return text;
      const match = rng.pick(keys);
      const value = rng.pick(["null", "0", '"x"', "[]", "{}"]);
      return `${text.slice(0, match.index)}"${match[1]}":${value},${text.slice(match.index)}`;
    }
    case 1:
      return text.slice(0, rng.int(text.length));
    case 2: {
      const at = rng.int(text.length);
      return text.slice(0, at) + rng.pick(ODD_CHARS) + text.slice(at);
    }
    case 3: {
      const at = rng.int(text.length);
      return text.slice(0, at) + text.slice(at + 1 + rng.int(8));
    }
    case 4:
      return rng.pick([BYTE_ORDER_MARK, " ", "\n", "x", "[", "]"]) + text;
    case 5:
      return text + rng.pick([" ", "\n", "{}", "x", ",", "\u0000"]);
    case 6:
      return text.replace(
        /\d+/,
        rng.pick(["1e400", "-1e400", `1${"0".repeat(400)}`, "01", "1.", "-"]),
      );
    case 7: {
      const n = limits.maxDepth + 1 + rng.int(limits.maxDepth * 4);
      return `${"[".repeat(n)}${text}${"]".repeat(n)}`;
    }
    default:
      return text.replace(/"/, "'");
  }
}

/** Bytes with invalid UTF-8 spliced in, or the text encoded as UTF-8. */
function toBytes(text: string, rng: Rng): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  if (rng.chance(0.5)) return bytes;
  const bad = rng.pick([
    [0xff],
    [0xc0, 0x80],
    [0xed, 0xa0, 0x80],
    [0xe2, 0x82],
    [0xf8, 0x88, 0x80, 0x80, 0x80],
  ]);
  const at = rng.int(bytes.length + 1);
  const out = new Uint8Array(bytes.length + bad.length);
  out.set(bytes.subarray(0, at), 0);
  out.set(bad, at);
  out.set(bytes.subarray(at), at + bad.length);
  return out;
}

/** A mutated report: one to three value mutations, sometimes a text mutation, as text or bytes. */
export function mutate(sample: unknown, rng: Rng, limits: Limits): string | Uint8Array {
  const root = { value: structuredClone(sample) as Json };
  for (let i = 1 + rng.int(3); i > 0; i--) mutateValue(root, rng, limits);
  let text = JSON.stringify(root.value) ?? "";
  if (rng.chance(0.3)) text = mutateText(text, rng, limits);
  return rng.chance(0.2) ? toBytes(text, rng) : text;
}
