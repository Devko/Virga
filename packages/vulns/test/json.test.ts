import { describe, expect, it } from "vitest";
import { parseObject, repeatedKeys } from "../src/json.ts";

describe("repeatedKeys (R9 hardening, duplicate keys)", () => {
  it.each([
    ["no object", "[1, 2]"],
    ["distinct keys", '{"a": 1, "b": {"a": 2, "b": [{"a": 3}, {"a": 4}]}}'],
    ["the same key in sibling objects", '{"x": [{"id": 1}, {"id": 2}], "y": {"id": 3}}'],
    ["keys that differ only in case", '{"id": 1, "ID": 2, "Id": 3}'],
    ["key-like text in strings", '{"a": "\\"a\\": 1, {\\"a\\"", "b": ["a", "a"], "c": "}{"}'],
    ["a key equal to a value", '{"a": "a", "b": "a"}'],
    ["empty objects and arrays", '{"a": {}, "b": [], "c": [{}, {}], "d": [[], {}]}'],
    ["an escaped backslash before a quote", '{"a\\\\": 1, "a": 2}'],
  ])("finds nothing with %s", (_, text) => {
    JSON.parse(text);
    expect(repeatedKeys(text)).toBeNull();
  });

  it.each([
    ["at the top level", '{"a": 1, "a": 2}', 9, ["a"]],
    ["in a nested object", '{"x": {"a": 1, "b": 2, "a": 3}}', 23, []],
    ["in an object in an array", '{"x": [{"a": 1}, {"a": 1, "a": 2}]}', 26, []],
    ["after an empty object", '{"a": {}, "a": []}', 10, ["a"]],
    ["written with an escape", '{"id": 1, "\\u0069d": 2}', 10, ["id"]],
    ["named __proto__", '{"__proto__": {}, "__proto__": {}}', 18, ["__proto__"]],
  ])("finds a repeated key %s", (_, text, offset, topLevel) => {
    JSON.parse(text);
    expect(repeatedKeys(text)).toEqual({ offset, topLevel: new Set(topLevel) });
  });

  it("names every repeated top-level key, after a nested one", () => {
    const text = '{"x": {"b": 1, "b": 2}, "id": "A", "y": 1, "id": "B", "y": 2}';
    expect(repeatedKeys(text)).toEqual({ offset: 15, topLevel: new Set(["id", "y"]) });
  });
});

describe("parseObject (R9 hardening, duplicate keys)", () => {
  it("rejects a repeated key and keeps the top-level keys that occur once", () => {
    const text = '{"id": "A", "x": [1], "x": [], "__proto__": 1}';
    const parsed = parseObject(text, 1000);
    expect(parsed).toEqual({
      ok: false,
      reason: "duplicate key at offset 22",
      unique: { id: "A", ["__proto__"]: 1 },
    });
    if (parsed.ok || !parsed.unique) return;
    expect(Object.hasOwn(parsed.unique, "__proto__")).toBe(true);
    expect(Object.hasOwn(parsed.unique, "x")).toBe(false);
  });

  it("gives no unique keys for other failures", () => {
    expect(parseObject("{", 1000)).toEqual({ ok: false, reason: "not valid JSON" });
  });
});
