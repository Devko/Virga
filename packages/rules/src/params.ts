export interface CompiledSql {
  sql: string;
  /** Parameter names in the order of their `?` placeholders. */
  order: string[];
}

/** A parameter name the compiler rewrites. */
const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const WORD = /[A-Za-z0-9_]*/y;
/** What SQLite still reads as part of a variable after its name: identifier characters, `(...)` and `::`. */
const RUNS_ON = /^(?:[$\u0080-\uffff(]|::)/;

/** The variable at `start` as far as SQLite could read it, enough to name it. */
function placeholder(source: string, start: number): string {
  WORD.lastIndex = start + 1;
  const end = start + 1 + (WORD.exec(source)?.[0].length ?? 0);
  return source.slice(start, end) + (RUNS_ON.exec(source.slice(end, end + 2))?.[0] ?? "");
}

/**
 * Replaces `:name` parameters with positional `?` placeholders, because
 * Durable Object SQL only documents positional parameters. Skips string
 * literals, quoted identifiers ("", ``, []) and comments. Rejects positional
 * placeholders, every other variable form (`@name`, `$name`, `#name`, and
 * a `:` that SQLite would read as more or other than `:name`), and more
 * than one statement. Node SQLite binds such a variable NULL, so a rule
 * with one would pass its fixtures; Durable Object SQL refuses the bindings
 * on every run (R8 hardening).
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
    // SQLite ends a [identifier] at the first ], with no escape. A `--` or `;`
    // inside one is neither a comment nor a separator (R6-02).
    if (c === "[") {
      const end = source.indexOf("]", i + 1);
      if (end === -1) throw new SyntaxError("unterminated [ identifier");
      out += source.slice(i, end + 1);
      i = end + 1;
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
    if (c === ":" || c === "$" || c === "@" || c === "#") {
      const token = placeholder(source, i);
      const name = token.slice(1);
      if (c !== ":" || !NAME.test(name)) {
        throw new SyntaxError(`unsupported placeholder ${token}; use named :parameters`);
      }
      order.push(name);
      out += "?";
      i += token.length;
      continue;
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
