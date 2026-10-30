export interface StripOptions {
  /** Characters that delimit strings. */
  quotes?: string;
  /** Replace the contents of strings by spaces too. */
  blankStrings?: boolean;
}

/**
 * Removes `//` and `/* *\/` comments outside string literals. Comment text is
 * replaced by spaces and newlines are kept, so positions stay meaningful.
 */
export function stripComments(text: string, options: StripOptions = {}): string {
  const { quotes = `"`, blankStrings = false } = options;
  let out = "";
  let i = 0;
  while (i < text.length) {
    const c = text[i] as string;
    if (quotes.includes(c)) {
      const end = stringEnd(text, i);
      const literal = text.slice(i, end);
      out += blankStrings ? `${c}${literal.slice(1, -1).replace(/[^\n]/g, " ")}${c}` : literal;
      i = end;
    } else if (c === "/" && text[i + 1] === "/") {
      const end = text.indexOf("\n", i);
      const stop = end === -1 ? text.length : end;
      out += " ".repeat(stop - i);
      i = stop;
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      if (end === -1) throw new SyntaxError(`unterminated comment at ${position(text, i)}`);
      out += text.slice(i, end + 2).replace(/[^\n]/g, " ");
      i = end + 2;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/** Index just past the string literal that starts at `start`. */
function stringEnd(text: string, start: number): number {
  const quote = text[start];
  let i = start + 1;
  while (i < text.length) {
    const c = text[i];
    if (c === "\\") i += 2;
    else if (c === quote) return i + 1;
    else i++;
  }
  throw new SyntaxError(`unterminated string at ${position(text, start)}`);
}

/** Line and column of `index`; CR LF, CR and LF each end a line. */
export function position(text: string, index: number): string {
  const lines = text.slice(0, index).split(/\r\n|\r|\n/);
  return `line ${lines.length}, column ${(lines.at(-1) ?? "").length + 1}`;
}

/**
 * Keys refused at any depth. Wrangler's parser stores a member with
 * `object[key] = value`, so a `__proto__` member becomes the prototype and
 * Wrangler deploys every key under it as the config's own (R5-01).
 */
const REFUSED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** Far deeper than any Wrangler config. */
const MAX_DEPTH = 64;

const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
/** Characters that end a bare word such as `true`, as in jsonc-parser's scanner. */
const WORD_END = new Set([...' \t\r\n{}[]":,/']);
const ESCAPES = new Map([
  ['"', '"'],
  ["\\", "\\"],
  ["/", "/"],
  ["b", "\b"],
  ["f", "\f"],
  ["n", "\n"],
  ["r", "\r"],
  ["t", "\t"],
]);

/**
 * Parses wrangler.jsonc the way Wrangler 4.151.0 does (jsonc-parser 3.2.0,
 * comments and trailing commas allowed), and refuses what the two could read
 * differently (R5-01): `__proto__`, `constructor` and `prototype` keys, and
 * duplicate keys. Objects have no prototype. As in Wrangler, a leading UTF-8
 * byte order mark is skipped, whitespace is only space, tab, CR and LF, and a
 * line comment ends at CR or LF. test/wrangler-parse.test.ts compares the two.
 */
export function parseJsonc(input: string): unknown {
  const text = input.startsWith("﻿") ? input.slice(1) : input;
  let i = 0;
  const fail = (message: string, at = i): never => {
    throw new SyntaxError(`${message} at ${position(text, at)}`);
  };

  const skip = () => {
    for (;;) {
      const c = text[i];
      if (c === " " || c === "\t" || c === "\r" || c === "\n") i++;
      else if (c === "/" && text[i + 1] === "/") {
        while (i < text.length && text[i] !== "\r" && text[i] !== "\n") i++;
      } else if (c === "/" && text[i + 1] === "*") {
        const end = text.indexOf("*/", i + 2);
        if (end === -1) fail("unterminated comment");
        i = end + 2;
      } else return;
    }
  };

  const string = (): string => {
    const start = i++;
    let out = "";
    for (;;) {
      const c = text[i];
      if (c === undefined || c === "\r" || c === "\n") return fail("unterminated string", start);
      if (c === '"') {
        i++;
        return out;
      }
      if (c === "\\") {
        const code = text[i + 1] ?? "";
        const hex = text.slice(i + 2, i + 6);
        const decoded = ESCAPES.get(code);
        if (code === "u" && /^[0-9a-fA-F]{4}$/.test(hex)) {
          out += String.fromCharCode(Number.parseInt(hex, 16));
          i += 6;
        } else if (decoded !== undefined) {
          out += decoded;
          i += 2;
        } else {
          fail("invalid escape in string");
        }
        continue;
      }
      if (c < " ") fail("control character in string");
      out += c;
      i++;
    }
  };

  /** Reads the members of an object or array, from its opening bracket to its closing one. */
  const members = (close: "}" | "]", member: () => void) => {
    i++;
    skip();
    if (text[i] === close) {
      i++;
      return;
    }
    for (;;) {
      member();
      skip();
      if (text[i] === ",") {
        i++;
        skip();
        if (text[i] !== close) continue;
      } else if (text[i] !== close) {
        fail(`expected , or ${close}`);
      }
      i++;
      return;
    }
  };

  const value = (depth: number): unknown => {
    if (depth > MAX_DEPTH) fail("nested too deeply");
    skip();
    const c = text[i];
    if (c === "{") {
      const object: Record<string, unknown> = Object.create(null);
      members("}", () => {
        skip();
        const at = i;
        if (text[i] !== '"') fail("expected a property name");
        const key = string();
        if (REFUSED_KEYS.has(key)) {
          fail(
            `key ${JSON.stringify(key)} is refused: Wrangler deploys the keys of a __proto__ member unchecked, and no config needs __proto__, constructor or prototype`,
            at,
          );
        }
        if (Object.hasOwn(object, key)) fail(`duplicate key ${JSON.stringify(key)}`, at);
        skip();
        if (text[i] !== ":") fail("expected :");
        i++;
        object[key] = value(depth + 1);
      });
      return object;
    }
    if (c === "[") {
      const array: unknown[] = [];
      members("]", () => array.push(value(depth + 1)));
      return array;
    }
    if (c === '"') return string();
    NUMBER.lastIndex = i;
    const number = NUMBER.exec(text);
    if (number) {
      i += number[0].length;
      return Number(number[0]);
    }
    const start = i;
    while (i < text.length && !WORD_END.has(text[i] as string)) i++;
    const word = text.slice(start, i);
    if (word === "true") return true;
    if (word === "false") return false;
    if (word === "null") return null;
    return fail(word === "" ? "expected a value" : `unexpected ${JSON.stringify(word)}`, start);
  };

  const result = value(0);
  skip();
  if (i < text.length) fail("unexpected text after the value");
  return result;
}
