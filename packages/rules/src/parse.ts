import { parse as parseYaml } from "yaml";
import { compileParams } from "./params.ts";
import {
  type CompiledRule,
  type FixtureExpectation,
  RULE_KINDS,
  RULE_SEVERITIES,
  type RuleFixture,
  type RuleMeta,
  type RuleSeverity,
} from "./types.ts";

const FENCE = /^--\s*---\s*$/;

/** Splits a rule file into its front matter and its SQL body. */
export function splitRuleSource(source: string): { frontMatter: string; body: string } {
  const lines = source.split("\n");
  if (!FENCE.test(lines[0] ?? "")) throw new SyntaxError("rule must start with '-- ---'");
  const end = lines.findIndex((line, i) => i > 0 && FENCE.test(line));
  if (end === -1) throw new SyntaxError("front matter is not closed with '-- ---'");
  const frontMatter = lines
    .slice(1, end)
    .map((line) => {
      if (!line.startsWith("--")) throw new SyntaxError(`front matter line without '--': ${line}`);
      return line.replace(/^-- ?/, "");
    })
    .join("\n");
  return { frontMatter, body: lines.slice(end + 1).join("\n") };
}

function fail(file: string, message: string): never {
  throw new Error(`${file}: ${message}`);
}

export function validateMeta(value: unknown, file: string): RuleMeta {
  if (value === null || typeof value !== "object") fail(file, "front matter must be a mapping");
  const m = value as Record<string, unknown>;
  const known = ["id", "version", "title", "severity", "kind", "requires", "params", "enriches"];
  for (const key of Object.keys(m)) {
    if (!known.includes(key)) fail(file, `unknown front matter key '${key}'`);
  }
  if (typeof m.id !== "string" || !/^CF-\d{3}[a-z]?$/.test(m.id)) fail(file, "id must be CF-nnn");
  if (!Number.isInteger(m.version) || (m.version as number) < 1) {
    fail(file, "version must be a positive integer");
  }
  if (typeof m.title !== "string" || m.title.length === 0) fail(file, "title is required");
  if (!RULE_SEVERITIES.includes(m.severity as never)) fail(file, "invalid severity");
  if (!RULE_KINDS.includes(m.kind as never)) fail(file, "invalid kind");
  const requires = m.requires ?? [];
  if (!Array.isArray(requires) || requires.some((r) => typeof r !== "string")) {
    fail(file, "requires must be a list of strings");
  }
  const params = m.params ?? {};
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    fail(file, "params must be a mapping");
  }
  for (const [name, v] of Object.entries(params)) {
    if (typeof v !== "number" && typeof v !== "string")
      fail(file, `param ${name}: invalid default`);
  }
  if (m.enriches != null && typeof m.enriches !== "string") fail(file, "enriches must be a string");
  return {
    id: m.id,
    version: m.version as number,
    title: m.title,
    severity: m.severity as RuleMeta["severity"],
    kind: m.kind as RuleMeta["kind"],
    requires: requires as string[],
    params: params as Record<string, number | string>,
    enriches: (m.enriches as string | null | undefined) ?? null,
  };
}

/** Parses and compiles one rule file. */
export function parseRule(source: string, file: string): CompiledRule {
  const { frontMatter, body } = splitRuleSource(source);
  const meta = validateMeta(parseYaml(frontMatter), file);
  let compiled: ReturnType<typeof compileParams>;
  try {
    compiled = compileParams(body);
  } catch (error) {
    fail(file, (error as Error).message);
  }
  const statement = compiled.sql.replace(/^(\s|--[^\n]*\n|\/\*[\s\S]*?\*\/)*/, "");
  if (!/^(SELECT|WITH)\b/i.test(statement)) fail(file, "statement must start with SELECT or WITH");
  const declared = Object.keys(meta.params);
  for (const name of compiled.order) {
    if (!declared.includes(name)) fail(file, `parameter :${name} has no default in params`);
  }
  for (const name of declared) {
    if (!compiled.order.includes(name)) fail(file, `parameter ${name} is declared but unused`);
  }
  return { ...meta, sql: compiled.sql, paramOrder: compiled.order };
}

function parseExpectation(value: unknown, where: string): FixtureExpectation {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(where, "must be a mapping");
  }
  const e = value as Record<string, unknown>;
  for (const key of Object.keys(e)) {
    if (!["fingerprint", "severity", "decided"].includes(key)) fail(where, `unknown key '${key}'`);
  }
  if (typeof e.fingerprint !== "string" || e.fingerprint.length === 0) {
    fail(where, "fingerprint is required");
  }
  if (e.severity !== undefined && !RULE_SEVERITIES.includes(e.severity as never)) {
    fail(where, "invalid severity");
  }
  if (e.decided !== undefined && typeof e.decided !== "boolean") {
    fail(where, "decided must be true or false");
  }
  // An undecided row changes no finding, so its severity means nothing.
  if (e.decided === false && e.severity !== undefined) {
    fail(where, "an undecided row has no severity to expect");
  }
  return {
    fingerprint: e.fingerprint,
    ...(e.severity !== undefined ? { severity: e.severity as RuleSeverity } : {}),
    ...(e.decided === false ? { decided: false as const } : {}),
  };
}

export function parseFixture(source: string, rule: string, name: string): RuleFixture {
  const data = parseYaml(source) as Partial<RuleFixture> | null;
  const file = `${rule}/fixtures/${name}`;
  if (!data || typeof data !== "object") fail(file, "fixture must be a mapping");
  if (!Array.isArray(data.expect)) fail(file, "fixture needs an expect list (may be empty)");
  const expect = (data.expect as unknown[]).map((entry, i) =>
    parseExpectation(entry, `${file}: expect entry ${i + 1}`),
  );
  if (new Set(expect.map((e) => e.fingerprint)).size < expect.length) {
    fail(file, "expect lists a fingerprint twice");
  }
  return {
    rule,
    name,
    ...(data.description ? { description: data.description } : {}),
    ...(data.params ? { params: data.params } : {}),
    nodes: data.nodes ?? [],
    edges: data.edges ?? [],
    exposure: data.exposure ?? [],
    vulns: data.vulns ?? [],
    signals: data.signals ?? [],
    expect,
  };
}
