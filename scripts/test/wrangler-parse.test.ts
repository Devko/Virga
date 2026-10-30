import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseJsonc } from "../lib/jsonc.ts";
import { REPO_ROOT } from "./helpers.ts";

/**
 * Compares parseJsonc with the parser of the Wrangler the apps pin, through
 * its config API. Whatever parseJsonc accepts, Wrangler must read the same
 * way (R5-01). Nothing here reaches the network.
 */
interface Wrangler {
  experimental_readRawConfig(args: { config: string }): { rawConfig: unknown };
}

type Outcome = { ok: true; value: unknown } | { ok: false; error: string };

const attempt = (fn: () => unknown): Outcome => {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
};

/** A comparable form that includes inherited keys: what Wrangler reads through `config.key`. */
function visible(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(visible);
  if (typeof value !== "object" || value === null) return value;
  const entries: [string, unknown][] = [];
  for (const key in value) entries.push([key, visible((value as Record<string, unknown>)[key])]);
  return { entries };
}

/** Deterministic PRNG (mulberry32), so a failure can be replayed. */
function random(seed: number) {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const KEYS = [
  `"name"`,
  `"routes"`,
  `"d1_databases"`,
  `"a"`,
  `"__proto__"`,
  `"\\u005f_proto__"`,
  `"constructor"`,
  `"prototype"`,
  `"x\\"y"`,
];
const STRINGS = [
  `"virga-web"`,
  `""`,
  `"// not a comment"`,
  `"/* nor this */"`,
  `"a,]}"`,
  `"esc \\n\\t\\"\\\\\\/\\b\\f\\r"`,
  `"\\u0041\\ud83d\\ude00"`,
  `"  "`,
  `"\\x"`,
  `"\\u12"`,
  `"tab\there"`,
];
const NUMBERS = ["0", "-0", "12", "1.5", "-2e3", "1E+2", "1e-2", "01", "1.", "-", ".5"];
const LITERALS = ["true", "false", "null", "nul", "True"];
const TRIVIA = [
  "",
  "",
  " ",
  "\t",
  "\n",
  "\r",
  "\r\n",
  "// c\n",
  "// c\r",
  "/* c */",
  "/* \n */",
  "\v",
  " ",
  "﻿",
];
const NOISE = [",", "/", "*", '"', "\\", "\r", "{", "}", "[", "]", ":", "0", "e", "-", " "];

function generate(next: () => number): string {
  const pick = <T>(list: readonly T[]): T => list[Math.floor(next() * list.length)] as T;
  const gap = () => (next() < 0.7 ? pick(TRIVIA.slice(0, 3)) : pick(TRIVIA));
  const comma = () => (next() < 0.15 ? `,${gap()}` : "");
  const value = (depth: number): string => {
    const kind = next();
    if (depth < 3 && kind < 0.35) {
      const props = Array.from(
        { length: Math.floor(next() * 4) },
        () => `${gap()}${pick(KEYS)}${gap()}:${gap()}${value(depth + 1)}${gap()}`,
      );
      return `{${props.join(",")}${props.length > 0 ? comma() : ""}${gap()}}`;
    }
    if (depth < 3 && kind < 0.55) {
      const items = Array.from(
        { length: Math.floor(next() * 4) },
        () => `${gap()}${value(depth + 1)}${gap()}`,
      );
      return `[${items.join(",")}${items.length > 0 ? comma() : ""}${gap()}]`;
    }
    if (kind < 0.75) return pick(STRINGS);
    if (kind < 0.9) return pick(NUMBERS);
    return pick(LITERALS);
  };
  let text = `${next() < 0.1 ? "﻿" : ""}${gap()}${value(0)}${gap()}`;
  if (next() < 0.3) {
    const at = Math.floor(next() * (text.length + 1));
    text =
      next() < 0.5
        ? `${text.slice(0, at)}${text.slice(at + 1)}`
        : `${text.slice(0, at)}${pick(NOISE)}${text.slice(at)}`;
  }
  return text;
}

describe("parseJsonc against Wrangler's parser", () => {
  let dir = "";
  let wrangler: Wrangler;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "virga-jsonc-"));
    wrangler = createRequire(join(REPO_ROOT, "apps", "broker", "package.json"))(
      "wrangler",
    ) as Wrangler;
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  /** Both readings of one file, each as its reader gets the file. */
  const read = (text: string) => {
    const path = join(dir, "wrangler.jsonc");
    writeFileSync(path, text);
    return {
      theirs: attempt(() => wrangler.experimental_readRawConfig({ config: path }).rawConfig),
      ours: attempt(() => parseJsonc(readFileSync(path, "utf8"))),
    };
  };

  it("R5-01: refuses the review's __proto__ member, whose bindings Wrangler reads as the config's own", () => {
    const { theirs, ours } = read(`{
      "name": "virga-web",
      "__proto__": {
        "d1_databases": [{ "binding": "VAULT", "database_name": "virga-vault" }],
        "secrets_store_secrets": [{ "binding": "MASTER_KEY_STORE", "store_id": "s", "secret_name": "virga-master-key" }]
      }
    }`);
    expect(theirs.ok).toBe(true);
    const config = (theirs as { value: Record<string, unknown> }).value;
    expect(Object.keys(config)).toEqual(["name"]);
    expect(config.d1_databases).toEqual([{ binding: "VAULT", database_name: "virga-vault" }]);
    expect(config.secrets_store_secrets).toHaveLength(1);
    expect(ours).toEqual({ ok: false, error: expect.stringMatching(/"__proto__" is refused/) });
  });

  it("R5-01: reads the committed configs as Wrangler does", () => {
    for (const app of ["broker", "core", "web"]) {
      const { theirs, ours } = read(
        readFileSync(join(REPO_ROOT, "apps", app, "wrangler.jsonc"), "utf8"),
      );
      expect(ours.ok).toBe(true);
      expect(visible((ours as { value: unknown }).value)).toEqual(
        visible((theirs as { value: unknown }).value),
      );
    }
  });

  it("R5-01: reads any text the same as Wrangler, or refuses it", () => {
    const next = random(0x5eed);
    let accepted = 0;
    let refusedOnPurpose = 0;
    for (let i = 0; i < 1500; i++) {
      const text = generate(next);
      const { theirs, ours } = read(text);
      const label = `case ${i}: ${JSON.stringify(text)}`;
      if (ours.ok) {
        accepted++;
        expect(theirs.ok, label).toBe(true);
        expect(visible(ours.value), label).toEqual(visible((theirs as { value: unknown }).value));
      } else if (theirs.ok) {
        // Stricter than Wrangler only where Wrangler's reading is a trap.
        expect(ours.error, label).toMatch(/is refused|duplicate key/);
        refusedOnPurpose++;
      }
    }
    expect(accepted).toBeGreaterThan(300);
    expect(refusedOnPurpose).toBeGreaterThan(30);
  });
});
