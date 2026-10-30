// The most expensive reports found for the default limits (R9-06). Each one
// stays within every limit, so the parser accepts it. Used by
// memory.test.ts and memory-worker.ts; Node runs this file directly too.

import { DEFAULT_LIMITS as L } from "../src/limits.ts";

const BACKSLASH = String.fromCharCode(0x5c);
export const CJK = String.fromCharCode(0x4e00);
const C = L.maxContainers - 20;
const V = L.maxValues - 20;

/** Nested arrays of at most `maxArrayItems - 2` items, `count` items in all. */
function arrays(count: number, item: (i: number) => string): string {
  const per = L.maxArrayItems - 2;
  const outer: string[] = [];
  for (let i = 0; i < count; i += per) {
    const n = Math.min(per, count - i);
    outer.push(`[${Array.from({ length: n }, (_, j) => item(i + j)).join(",")}]`);
  }
  return `[${outer.join(",")}]`;
}

/** Copies of one string literal, up to `maxBytes`. */
function fill(literal: string): string {
  const n = Math.floor((L.maxBytes - 2) / (literal.length + 1));
  return `[${new Array(n).fill(literal).join(",")}]`;
}

/** Objects of `maxObjectKeys` members with 13-character keys and values. */
function members(count: number): string {
  const k = L.maxObjectKeys;
  const object = (o: number) =>
    `{${Array.from({ length: k }, (_, j) => {
      const n = String(o * k + j);
      return `"${n.padStart(13, "k")}":"${n.padStart(13, "v")}"`;
    }).join(",")}}`;
  return `[${Array.from({ length: Math.floor(count / k) }, (_, o) => object(o)).join(",")}]`;
}

/** Empty objects up to the container limit, then object members up to the value limit. */
function worstTree(): string {
  const objects = C - 1_000;
  const memberCount = Math.floor((V - objects) / 2) - 2 * L.maxObjectKeys;
  return `[${arrays(objects, () => "{}")},${members(memberCount)}]`;
}

/** The worst tree, with one two-byte character and padded to `maxBytes`. */
export function worstReport(): string {
  const body = `["${CJK}",${worstTree().slice(1)}`;
  const size = new TextEncoder().encode(body).length;
  return body + " ".repeat(L.maxBytes - size);
}

export const HOSTILE_SHAPES: [string, () => string][] = [
  // The review's input: five arrays of 99,998 `{}` (before: 94 MB in Node).
  ["empty objects up to the container limit", () => arrays(C, () => "{}")],
  ["one-item arrays up to the container limit", () => arrays(C, () => "[0]")],
  [
    "12-character strings up to the value limit",
    () => arrays(V, (i) => `"${String(i).padStart(12, "x")}"`),
  ],
  [
    "strings that start with an escape",
    () => arrays(V, (i) => `"${BACKSLASH}n${String(i).padStart(12, "x")}"`),
  ],
  // Before: a rope of one node per escape, 260 MB in Node.
  [
    "strings of escapes up to the byte limit",
    () => fill(`"${`${BACKSLASH}n`.repeat(L.maxStringLength)}"`),
  ],
  [
    "two-byte strings of escapes",
    () => fill(`"${CJK}${`${BACKSLASH}n`.repeat(L.maxStringLength - 1)}"`),
  ],
  ["object members with long keys and values", () => members(Math.floor(V / 2) - L.maxObjectKeys)],
  ["empty objects and object members together", worstTree],
  ["the worst tree in two-byte text padded to the byte limit", worstReport],
];
