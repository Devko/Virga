import { join, relative, sep } from "node:path";
import type { GenerateDirs, GeneratedCheck } from "../../packages/rules/src/generate.ts";
import { sha256 } from "./run.ts";
import { type Context, DeployError } from "./steps.ts";
import type { WorkspaceRecord } from "./workspace.ts";

/** checkGenerated of packages/rules/src/generate.ts. */
export type CheckGenerated = (dirs: GenerateDirs) => Promise<GeneratedCheck>;

/** The warning Node's SQLite gives when it loads. */
const isSqliteWarning = (warning: unknown, type: unknown) =>
  type === "ExperimentalWarning" &&
  typeof warning === "string" &&
  warning.startsWith("SQLite is an experimental feature");

/**
 * Loads the rule compiler. The deploy loads it before the builds, so that the
 * code that checks the generated rules after them is the checkout's, not code
 * a build wrote (R6-01, R8-05). Node's SQLite, on which the compiler runs the
 * fixtures, warns on load that it is experimental; only that warning is left
 * out of the deploy's output.
 */
export async function loadRuleCompiler(): Promise<CheckGenerated> {
  const emitWarning = process.emitWarning;
  process.emitWarning = ((warning: string | Error, ...rest: unknown[]) => {
    const [options] = rest;
    const type =
      typeof options === "object" && options !== null
        ? (options as { type?: unknown }).type
        : options;
    if (isSqliteWarning(warning, type)) return;
    Reflect.apply(emitWarning, process, [warning, ...rest]);
  }) as typeof process.emitWarning;
  try {
    return (await import("../../packages/rules/src/generate.ts")).checkGenerated;
  } finally {
    process.emitWarning = emitWarning;
  }
}

/**
 * The directory of the generated rule modules that virga-core bundles: src/
 * of the package that apps/core/node_modules/@virga/rules leads to, by its
 * real path. The workspace record holds the link only while it leads to
 * packages/rules, and the runner compares the record before every Wrangler
 * call, so the modules checked are the ones Wrangler bundles (L-2).
 */
export function bundledRulesDir(core: WorkspaceRecord | undefined): string {
  const at = join("apps", "core", "node_modules", "@virga", "rules");
  const target = core?.links.get(join(core.appDir, "node_modules", "@virga", "rules"));
  if (target === undefined) {
    throw new DeployError(
      `${at} is missing; virga-core bundles the generated rules through it. Run pnpm install first`,
    );
  }
  return join(target, "src");
}

/**
 * Compiles rules/, runs every fixture, and compares the output with the
 * generated modules in `outDir`, the ones virga-core bundles
 * (bundledRulesDir). Only CI's rules:check compared them before, and a
 * statement added by hand after a rule's SQL in rules.gen.ts would run on
 * Durable Object SQL (R8-05). The deploy runs this after the builds, on what
 * they left (R6-01). Returns the sha256 of each module by absolute path,
 * which the runner compares before every Wrangler call.
 */
export async function checkRules(
  ctx: Context,
  root: string,
  check: CheckGenerated,
  outDir: string,
): Promise<Map<string, string>> {
  const result = await check({ rulesDir: join(root, "rules"), outDir });
  if (result.errors.length > 0) {
    throw new DeployError(
      `the rules in rules/ fail the rule compiler, so virga-core would bundle rules that no fixture checked (pnpm rules:check shows the same):\n${result.errors.map((error) => `  ${error}`).join("\n")}`,
    );
  }
  const shown = (path: string) => relative(root, path).split(sep).join("/");
  const stale = result.files.filter((file) => file.stale);
  if (stale.length > 0) {
    throw new DeployError(
      stale
        .map(
          (file) =>
            `${shown(file.path)} is not what the rule compiler makes of rules/; virga-core would bundle it as it is, and Durable Object SQL runs every statement of a rule. Run pnpm rules:build, review the diff and commit it, then deploy again`,
        )
        .join("\n"),
    );
  }
  ctx.log(
    `Rules: ${result.rules} rule(s) and ${result.fixtures} fixture(s) pass the compiler; ${result.files.map((file) => shown(file.path)).join(" and ")} are its output`,
  );
  return new Map(result.files.map((file) => [file.path, sha256(file.content)]));
}
