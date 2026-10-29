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
