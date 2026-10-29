export interface CompiledSql {
  sql: string;
  /** Parameter names in the order of their `?` placeholders. */
  order: string[];
}

const NAME = /[A-Za-z_][A-Za-z0-9_]*/y;

/**
 * Replaces `:name` parameters with positional `?` placeholders, because
 * Durable Object SQL only documents positional parameters. Skips string
 * literals, quoted identifiers and comments. Rejects positional placeholders
 * and more than one statement.
 */
export function compileParams(source: string): CompiledSql {
  let out = "";
  const order: string[] = [];
  let i = 0;
  let statementEnded = false;

  while (i < source.length) {
    const c = source[i] as string;
    const next = source[i + 1];

    if (c === "'" || c === '"' || c === "`") {
      const end = findQuoteEnd(source, i, c);
      out += source.slice(i, end);
      i = end;
      continue;
    }
    if (c === "-" && next === "-") {
      const end = source.indexOf("\n", i);
      const stop = end === -1 ? source.length : end;
      out += source.slice(i, stop);
      i = stop;
      continue;
    }
    if (c === "/" && next === "*") {
      const end = source.indexOf("*/", i + 2);
      if (end === -1) throw new SyntaxError("unterminated block comment");
      out += source.slice(i, end + 2);
      i = end + 2;
      continue;
    }
    if (statementEnded && !/\s/.test(c)) {
      throw new SyntaxError("a rule must contain exactly one statement");
    }
    if (c === ";") {
      statementEnded = true;
      i++;
      continue;
    }
    if (c === "?") throw new SyntaxError("use named :parameters, not positional ?");
    if (c === ":" && next !== ":" && source[i - 1] !== ":") {
      NAME.lastIndex = i + 1;
      const match = NAME.exec(source);
      if (match) {
        order.push(match[0]);
        out += "?";
        i += 1 + match[0].length;
        continue;
      }
    }
    out += c;
    i++;
  }
  return { sql: out.trim(), order };
}

function findQuoteEnd(source: string, start: number, quote: string): number {
  let i = start + 1;
  while (i < source.length) {
    if (source[i] === quote) {
      if (source[i + 1] === quote) {
        i += 2;
        continue;
      }
      return i + 1;
    }
    i++;
  }
  throw new SyntaxError(`unterminated ${quote} literal`);
}
