import { describe, expect, it } from "vitest";
import { parseJsonc, stripComments } from "../lib/jsonc.ts";

describe("parseJsonc", () => {
  it("accepts line and block comments and trailing commas", () => {
    const text = `{
      // a comment
      "name": "virga-core", /* inline */
      "list": [1, 2,],
      "nested": { "a": true, },
    }`;
    expect(parseJsonc(text)).toEqual({ name: "virga-core", list: [1, 2], nested: { a: true } });
  });

  it("keeps comment markers and commas inside strings", () => {
    const text = `{ "url": "https://example.com/*x*/", "s": "a,]", "q": "say \\"hi\\" // not a comment" }`;
    expect(parseJsonc(text)).toEqual({
      url: "https://example.com/*x*/",
      s: "a,]",
      q: 'say "hi" // not a comment',
    });
  });

  it("parses the $schema line of a real config", () => {
    const text = `{ "$schema": "node_modules/wrangler/config-schema.json", "name": "x" }`;
    expect(parseJsonc(text)).toMatchObject({ name: "x" });
  });

  it("reports where the syntax error is", () => {
    expect(() => parseJsonc(`{\n  "a": 1\n  "b": 2\n}`)).toThrow(/line 3/);
  });

  it("rejects unterminated comments and strings", () => {
    expect(() => parseJsonc(`{ /* open`)).toThrow(/unterminated comment/);
    expect(() => parseJsonc(`{ "open`)).toThrow(/unterminated string/);
  });

  it("R5-01: refuses __proto__, constructor and prototype keys at any depth", () => {
    for (const key of ["__proto__", "constructor", "prototype", "\\u005f_proto__"]) {
      expect(() => parseJsonc(`{ "${key}": { "d1_databases": [] } }`)).toThrow(/key .* is refused/);
      expect(() => parseJsonc(`{ "a": [{ "b": { "${key}": 1 } }] }`)).toThrow(/key .* is refused/);
    }
  });

  it("R5-01: refuses duplicate keys", () => {
    expect(() => parseJsonc(`{ "routes": [], "name": "x", "routes": [] }`)).toThrow(
      /duplicate key "routes" at line 1/,
    );
    expect(() => parseJsonc(`{ "a": { "b": 1, "b": 2 } }`)).toThrow(/duplicate key "b"/);
  });

  it("R5-01: returns objects without a prototype", () => {
    const parsed = parseJsonc(`{ "a": { "b": [{}] } }`) as { a: { b: object[] } };
    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(Object.getPrototypeOf(parsed.a.b[0])).toBeNull();
    expect((parsed as Record<string, unknown>).toString).toBeUndefined();
  });

  it("R5-01: ends a line comment at a carriage return, as Wrangler does", () => {
    const text = `{ "name": "virga-web", // comment\r "routes": ["x.example.com"]\n}`;
    expect(parseJsonc(text)).toEqual({ name: "virga-web", routes: ["x.example.com"] });
  });

  it("R5-01: accepts what Wrangler accepts around commas and a byte order mark", () => {
    expect(parseJsonc(`﻿{ "a": 1 }`)).toEqual({ a: 1 });
    expect(() => parseJsonc(`[,]`)).toThrow(SyntaxError);
    expect(() => parseJsonc(`{ , }`)).toThrow(SyntaxError);
    expect(() => parseJsonc(`[1,,]`)).toThrow(SyntaxError);
    expect(() => parseJsonc(``)).toThrow(SyntaxError);
  });

  it("R5-01: refuses whitespace and literals outside JSON", () => {
    for (const text of [`{\v}`, `{ }`, `{ }`, `[NaN]`, `[0x1]`, `['a']`, `[01]`, `[1.]`]) {
      expect(() => parseJsonc(text), JSON.stringify(text)).toThrow(SyntaxError);
    }
  });

  it("refuses nesting deeper than any config needs", () => {
    expect(() => parseJsonc(`${"[".repeat(200)}${"]".repeat(200)}`)).toThrow(/nested too deeply/);
  });
});

describe("stripComments", () => {
  it("keeps line numbers", () => {
    const text = "a /* one\ntwo */ b // three\nc";
    const out = stripComments(text);
    expect(out.split("\n")).toHaveLength(3);
    expect(out.replace(/\s+/g, " ").trim()).toBe("a b c");
  });

  it("treats single quotes and backticks as strings when asked", () => {
    expect(stripComments("x = '//'; y = `/*`;", { quotes: `"'\`` })).toBe("x = '//'; y = `/*`;");
  });

  it("can blank string contents", () => {
    expect(stripComments(`a "bc" 'd'`, { quotes: `"'`, blankStrings: true })).toBe(`a "  " ' '`);
  });
});
