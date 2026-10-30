import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { WorkerConfig } from "./config.ts";
import { stripComments } from "./jsonc.ts";

export interface ModuleExports {
  names: Set<string>;
  /** `export * from`: names the text alone cannot tell. */
  star: boolean;
}

const IDENT = "[A-Za-z_$][\\w$]*";

/**
 * Value exports of an ES module, read from its source text. Enough for a
 * Worker's main module, which re-exports its entrypoints and classes.
 */
export function moduleExports(source: string): ModuleExports {
  const code = stripComments(source, { quotes: `"'\``, blankStrings: true });
  const names = new Set<string>();
  let star = false;

  for (const m of code.matchAll(/export\s+(type\s+)?\{([^}]*)\}/g)) {
    if (m[1]) continue;
    for (const part of (m[2] ?? "").split(",")) {
      const spec = part.trim();
      if (spec === "" || spec.startsWith("type ")) continue;
      const alias = new RegExp(`^(?:${IDENT}|default)\\s+as\\s+(${IDENT})$`).exec(spec);
      names.add(alias ? (alias[1] as string) : spec);
    }
  }
  const declarations = [
    new RegExp(`export\\s+(?:abstract\\s+)?class\\s+(${IDENT})`, "g"),
    new RegExp(`export\\s+(?:async\\s+)?function\\s*\\*?\\s*(${IDENT})`, "g"),
    new RegExp(`export\\s+(?:const|let|var)\\s+(${IDENT})`, "g"),
    new RegExp(`export\\s+\\*\\s+as\\s+(${IDENT})`, "g"),
  ];
  for (const pattern of declarations) {
    for (const m of code.matchAll(pattern)) names.add(m[1] as string);
  }
  if (/export\s+default\b/.test(code)) names.add("default");
  if (/export\s+\*\s+from\b/.test(code)) star = true;
  return { names, star };
}

/** Exports of a Worker's main module, or null when it has none or it cannot be read. */
export function loadExports(worker: WorkerConfig): ModuleExports | null {
  if (worker.main === null) return null;
  try {
    return moduleExports(readFileSync(resolve(worker.dir, worker.main), "utf8"));
  } catch {
    return null;
  }
}
