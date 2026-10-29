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

/** Drops commas that are followed only by whitespace and a closing bracket. */
function stripTrailingCommas(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const c = text[i] as string;
    if (c === `"`) {
      const end = stringEnd(text, i);
      out += text.slice(i, end);
      i = end;
      continue;
    }
    if (c === ",") {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j] as string)) j++;
      if (text[j] === "}" || text[j] === "]") {
        out += " ";
        i++;
        continue;
      }
    }
    out += c;
    i++;
  }
  return out;
}

export function position(text: string, index: number): string {
  const before = text.slice(0, index);
  const line = before.split("\n").length;
  const column = index - before.lastIndexOf("\n");
  return `line ${line}, column ${column}`;
}

/** Parses JSON with comments and trailing commas, the format of wrangler.jsonc. */
export function parseJsonc(text: string): unknown {
  const json = stripTrailingCommas(stripComments(text));
  try {
    return JSON.parse(json);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const at = /position (\d+)/.exec(message);
    const located = at && !/line \d+/.test(message);
    throw new SyntaxError(located ? `${message} (${position(json, Number(at[1]))})` : message);
  }
}
