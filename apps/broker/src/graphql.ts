/**
 * Decides whether a GraphQL document only reads. The lexer follows the
 * GraphQL spec closely enough to skip strings, block strings and comments;
 * anything it does not understand is refused (fail closed).
 */

export const MAX_DOCUMENT_LENGTH = 64 * 1024;

type Token = { kind: "name"; value: string } | { kind: "punct"; value: string } | { kind: "value" };

const PUNCT = new Set(["!", "$", "&", "(", ")", ":", "=", "@", "[", "]", "{", "|", "}"]);
const NAME = /[_A-Za-z][_0-9A-Za-z]*/y;
const NUMBER = /-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;

function lex(source: string): Token[] | null {
  const tokens: Token[] = [];
  let i = 0;
  while (i < source.length) {
    const c = source[i] as string;
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "," || c === "﻿") {
      i++;
    } else if (c === "#") {
      while (i < source.length && source[i] !== "\n" && source[i] !== "\r") i++;
    } else if (source.startsWith('"""', i)) {
      let j = i + 3;
      for (;;) {
        if (j >= source.length) return null;
        if (source.startsWith('\\"""', j)) j += 4;
        else if (source.startsWith('"""', j)) break;
        else j++;
      }
      tokens.push({ kind: "value" });
      i = j + 3;
    } else if (c === '"') {
      let j = i + 1;
      for (;;) {
        const d = source[j];
        if (d === undefined || d === "\n" || d === "\r") return null;
        if (d === "\\") j += 2;
        else if (d === '"') break;
        else j++;
      }
      tokens.push({ kind: "value" });
      i = j + 1;
    } else if (source.startsWith("...", i)) {
      tokens.push({ kind: "punct", value: "..." });
      i += 3;
    } else if (PUNCT.has(c)) {
      tokens.push({ kind: "punct", value: c });
      i++;
    } else {
      NAME.lastIndex = i;
      const name = NAME.exec(source);
      if (name) {
        tokens.push({ kind: "name", value: name[0] });
        i = NAME.lastIndex;
        continue;
      }
      NUMBER.lastIndex = i;
      const number = NUMBER.exec(source);
      if (!number || number[0] === "") return null;
      tokens.push({ kind: "value" });
      i = NUMBER.lastIndex;
    }
  }
  return tokens;
}

export type GraphqlCheck = { ok: true } | { ok: false; reason: string };

/** Accepts documents made of query operations and fragments only. */
export function checkReadOnlyDocument(document: unknown): GraphqlCheck {
  if (typeof document !== "string" || document.length === 0) {
    return { ok: false, reason: "query must be a non-empty string" };
  }
  if (document.length > MAX_DOCUMENT_LENGTH) return { ok: false, reason: "query is too long" };
  const tokens = lex(document);
  if (!tokens) return { ok: false, reason: "query does not parse" };
  let operations = 0;
  let i = 0;
  while (i < tokens.length) {
    const first = tokens[i] as Token;
    if (first.kind === "name") {
      if (first.value === "mutation" || first.value === "subscription") {
        return { ok: false, reason: `${first.value} operations are not allowed` };
      }
      if (first.value !== "query" && first.value !== "fragment") {
        return { ok: false, reason: `unexpected definition ${first.value.slice(0, 40)}` };
      }
      if (first.value === "query") operations++;
      // Skip the header (name, variables, directives) up to the selection set.
      // Braces inside parentheses are object values, not the selection set.
      let parens = 0;
      i++;
      while (i < tokens.length) {
        const t = tokens[i] as Token;
        if (t.kind === "punct" && t.value === "(") parens++;
        else if (t.kind === "punct" && t.value === ")") parens--;
        else if (t.kind === "punct" && t.value === "{" && parens === 0) break;
        i++;
      }
      if (i >= tokens.length) return { ok: false, reason: "definition has no selection set" };
    } else if (first.kind === "punct" && first.value === "{") {
      operations++;
    } else {
      return { ok: false, reason: "query does not parse" };
    }
    // tokens[i] is the opening brace of the selection set.
    let depth = 0;
    do {
      const t = tokens[i] as Token;
      if (t.kind === "punct" && t.value === "{") depth++;
      else if (t.kind === "punct" && t.value === "}") depth--;
      i++;
    } while (depth > 0 && i < tokens.length);
    if (depth !== 0) return { ok: false, reason: "unbalanced braces" };
  }
  if (operations === 0) return { ok: false, reason: "query has no operation" };
  return { ok: true };
}
