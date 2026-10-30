import { describe, expect, it } from "vitest";
import { ScannerOutputRejected } from "../src/errors.ts";
import { type JsonValue, parseJson } from "../src/json.ts";
import { DEFAULT_LIMITS, type Limits, resolveLimits } from "../src/limits.ts";
import { BYTE_ORDER_MARK } from "./chars.ts";

const parse = (input: string | Uint8Array, limits: Partial<Limits> = {}): JsonValue =>
  parseJson(input, resolveLimits(limits), "trivy");

const rejection = (input: string | Uint8Array, limits: Partial<Limits> = {}) => {
  try {
    parse(input, limits);
  } catch (error) {
    expect(error).toBeInstanceOf(ScannerOutputRejected);
    return error as ScannerOutputRejected;
  }
  throw new Error("expected a rejection");
};

/** Converts the parser's Map-based objects into plain values for comparison. */
const plain = (value: JsonValue): unknown => {
  if (Array.isArray(value)) return value.map(plain);
  if (value instanceof Map) return Object.fromEntries([...value].map(([k, v]) => [k, plain(v)]));
  return value;
};

describe("parseJson", () => {
  it.each([
    ['{"a":[1,-2.5,3e2,true,false,null],"b":{"c":"d"}}'],
    ['  [ "x" , { } , [ ] ]  '],
    ['"\\u00e9\\n\\t\\"\\\\\\/"'],
    ['"\\ud83d\\ude00"'],
    ["0"],
    ["-0.0e-0"],
  ])("parses %s like JSON.parse", (text) => {
    expect(plain(parse(text))).toEqual(JSON.parse(text));
  });

  it("returns objects as maps, so keys never touch a prototype", () => {
    const value = parse('{"__proto__":{"polluted":true},"constructor":1}');
    expect(value).toBeInstanceOf(Map);
    const map = value as Map<string, JsonValue>;
    expect([...map.keys()]).toEqual(["__proto__", "constructor"]);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("accepts UTF-8 bytes", () => {
    const bytes = new TextEncoder().encode('{"name":"café"}');
    expect(plain(parse(bytes))).toEqual({ name: "café" });
  });

  it.each([
    ["empty input", ""],
    ["truncated object", '{"a":1'],
    ["trailing comma", "[1,]"],
    ["trailing data", "{} {}"],
    ["single quotes", "{'a':1}"],
    ["leading zero", "01"],
    ["bare word", "nul"],
    ["comment", "[1/*x*/]"],
    ["raw newline in a string", '"a\nb"'],
    ["raw NUL in a string", '"a\u0000b"'],
    ["bad escape", '"\\x41"'],
    ["short unicode escape", '"\\u12"'],
    ["byte order mark", `${BYTE_ORDER_MARK}{"a":1}`],
    ["NaN", "NaN"],
    ["plus sign", "+1"],
  ])("rejects %s as invalid JSON", (_, text) => {
    expect(rejection(text).reason).toBe("invalid_json");
  });

  it("rejects duplicate keys anywhere in the document", () => {
    const error = rejection('{"a":{"b":1,"b":2}}');
    expect(error.reason).toBe("duplicate_key");
    expect(error.message).not.toContain('"b"');
  });

  it("rejects numbers that do not fit a double", () => {
    expect(rejection("1e400").reason).toBe("number_out_of_range");
    expect(rejection(`1${"0".repeat(80)}`).reason).toBe("number_out_of_range");
  });

  it("rejects lone surrogates, escaped or raw", () => {
    expect(rejection('"\\ud800"').reason).toBe("invalid_text");
    expect(rejection('"\\udc00\\ud800"').reason).toBe("invalid_text");
    expect(rejection('{"\\ud800":1}').reason).toBe("invalid_text");
    expect(rejection('"a\ud800b"').reason).toBe("invalid_encoding");
  });

  it("rejects invalid UTF-8 bytes", () => {
    for (const bad of [[0xff], [0xc0, 0x80], [0xed, 0xa0, 0x80], [0xc3]]) {
      const bytes = new Uint8Array([0x22, ...bad, 0x22]);
      expect(rejection(bytes).reason).toBe("invalid_encoding");
    }
  });

  it("rejects a byte order mark in bytes too", () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, 0x5b, 0x5d]);
    expect(rejection(bytes).reason).toBe("invalid_json");
  });

  it("enforces the size limit in UTF-8 bytes before parsing", () => {
    expect(rejection("[1, 2]", { maxBytes: 5 }).reason).toBe("too_large");
    expect(rejection(new Uint8Array(6), { maxBytes: 5 }).reason).toBe("too_large");
    // Three bytes per character in UTF-8, one UTF-16 unit each.
    expect(rejection('"€€"', { maxBytes: 7 }).reason).toBe("too_large");
    expect(plain(parse('"€€"', { maxBytes: 8 }))).toBe("€€");
  });

  it("enforces the depth limit", () => {
    const deep = (n: number) => `${"[".repeat(n)}${"]".repeat(n)}`;
    expect(() => parse(deep(4), { maxDepth: 4 })).not.toThrow();
    expect(rejection(deep(5), { maxDepth: 4 }).reason).toBe("too_deep");
    expect(rejection('{"a":{"b":{"c":{"d":{}}}}}', { maxDepth: 4 }).reason).toBe("too_deep");
  });

  it("survives nesting far beyond the call stack at the default limits", () => {
    const n = 1_000_000;
    expect(rejection(`${"[".repeat(n)}${"]".repeat(n)}`).reason).toBe("too_deep");
  });

  it("enforces array, object, string and value count limits", () => {
    expect(rejection("[1,2,3,4]", { maxArrayItems: 3 }).reason).toBe("too_many_items");
    expect(rejection('{"a":1,"b":2,"c":3}', { maxObjectKeys: 2 }).reason).toBe("too_many_keys");
    expect(rejection('"abcdef"', { maxStringLength: 5 }).reason).toBe("string_too_long");
    expect(rejection('{"abcdef":1}', { maxStringLength: 5 }).reason).toBe("string_too_long");
    expect(rejection('"\\u0041\\u0041\\u0041"', { maxStringLength: 2 }).reason).toBe(
      "string_too_long",
    );
    expect(rejection("[[1,2],[3]]", { maxValues: 5 }).reason).toBe("too_many_values");
    expect(() => parse("[[1,2],[3]]", { maxValues: 6 })).not.toThrow();
  });

  it("reports an offset, never the offending text", () => {
    const error = rejection('{"secret":"abc\u0001def"}');
    expect(error.at).toMatch(/^offset \d+$/);
    expect(error.message).not.toContain("abc");
  });

  it("refuses limits that are not positive integers", () => {
    expect(() => resolveLimits({ maxBytes: 0 })).toThrow(RangeError);
    expect(() => resolveLimits({ maxDepth: 1.5 })).toThrow(RangeError);
    expect(() => resolveLimits({ maxDepth: 10_000 })).toThrow(RangeError);
    expect(resolveLimits()).toEqual(DEFAULT_LIMITS);
  });
});
