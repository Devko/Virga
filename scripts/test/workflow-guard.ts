/**
 * The workflow guard (R8-04, H-1, R10-03): what lets a GitHub workflow
 * install packages or deploy before the release-age check, or after the check
 * failed. The tests apply it to every file in .github/workflows and to the
 * example deploy workflow in the operator guide.
 *
 * It reads a workflow with a YAML parser and checks the parsed jobs and steps,
 * so neither indentation nor quoting nor escapes can hide a key or a status
 * function from it (R10-03). It refuses what another parser, such as
 * GitHub's, could read differently, or what lets one line stand for another:
 * anchors, aliases, merge keys, tags, directives, duplicate keys, keys that are
 * not strings and more than one document.
 *
 * The parser is `yaml`, which pnpm-lock.yaml locks for packages/rules. The
 * scripts declare no dependencies of their own, so it is imported from there.
 */
import {
  isAlias,
  isMap,
  isScalar,
  isSeq,
  LineCounter,
  Parser,
  parseDocument,
  visit,
} from "../../packages/rules/node_modules/yaml/dist/index.js";

/** A parsed YAML value, with the line it starts on for messages. */
export type Value = YamlMap | YamlSeq | YamlScalar;

export interface YamlMap {
  kind: "map";
  line: number;
  entries: Map<string, Value>;
}

export interface YamlSeq {
  kind: "seq";
  line: number;
  items: Value[];
}

export interface YamlScalar {
  kind: "scalar";
  line: number;
  value: string | number | boolean | null;
}

export interface Job {
  name: string;
  /** The job's own keys, steps among them. */
  keys: YamlMap;
  steps: YamlMap[];
}

export interface Workflow {
  top: YamlMap;
  jobs: Map<string, Job>;
}

/** The commands the release-age job may run: the check, on a fresh checkout or not. */
export const CHECK_RUNS: ReadonlySet<string> = new Set([
  "node scripts/check-release-age.ts",
  "node scripts/check-release-age.ts --fresh-checkout",
]);

const HIDES =
  "the guard refuses anchors, aliases, merge keys, tags and directives, which another parser may read differently and which could hide an if: or continue-on-error";

const preview = (text: string) => JSON.stringify(text.length > 60 ? `${text.slice(0, 60)}…` : text);

/**
 * A workflow as the guard reads it, or the problems that keep it from reading
 * one. With a workflow, the problems are parts it could not read, such as a
 * job that is not a mapping.
 */
export function readWorkflow(text: string): { workflow?: Workflow; problems: string[] } {
  const lines = new LineCounter();
  const lineOf = (offset: number | undefined) => lines.linePos(offset ?? 0).line;
  const doc = parseDocument(text, {
    lineCounter: lines,
    merge: false,
    prettyErrors: false,
    uniqueKeys: true,
    version: "1.2",
  });
  const problems: string[] = [];
  for (const error of [...doc.errors, ...doc.warnings]) {
    problems.push(`line ${lineOf(error.pos[0])}: ${error.message.split("\n")[0]}`);
  }
  for (const token of new Parser().parse(text)) {
    if (token.type === "directive")
      problems.push(`line ${lineOf(token.offset)}: a directive; ${HIDES}`);
  }
  visit(doc, {
    Alias(_, node) {
      problems.push(`line ${lineOf(node.range?.[0])}: an alias; ${HIDES}`);
    },
    Node(_, node) {
      if (node.anchor) problems.push(`line ${lineOf(node.range?.[0])}: an anchor; ${HIDES}`);
      if (node.tag) problems.push(`line ${lineOf(node.range?.[0])}: a tag; ${HIDES}`);
    },
    Pair(_, pair) {
      if (isScalar(pair.key) && pair.key.value === "<<") {
        problems.push(`line ${lineOf(pair.key.range?.[0])}: a merge key; ${HIDES}`);
      }
    },
  });
  if (problems.length > 0) return { problems };

  const toValue = (node: unknown): Value => {
    const line = lineOf(
      isMap(node) || isSeq(node) || isScalar(node) || isAlias(node) ? node.range?.[0] : 0,
    );
    if (isMap(node)) {
      const entries = new Map<string, Value>();
      for (const pair of node.items) {
        if (!isScalar(pair.key) || typeof pair.key.value !== "string") {
          problems.push(
            `line ${isScalar(pair.key) ? lineOf(pair.key.range?.[0]) : line}: a key that is not a string, which another parser may read differently`,
          );
          continue;
        }
        entries.set(pair.key.value, toValue(pair.value));
      }
      return { kind: "map", line, entries };
    }
    if (isSeq(node)) return { kind: "seq", line, items: node.items.map(toValue) };
    const value = isScalar(node) ? node.value : null;
    if (value === null || ["string", "number", "boolean"].includes(typeof value)) {
      return { kind: "scalar", line, value: value as YamlScalar["value"] };
    }
    problems.push(`line ${line}: a value the guard cannot read`);
    return { kind: "scalar", line, value: null };
  };

  const top = toValue(doc.contents);
  if (top.kind !== "map") return { problems: [...problems, "the workflow is not a mapping"] };
  const jobs = new Map<string, Job>();
  const all = top.entries.get("jobs");
  if (all?.kind !== "map") problems.push("the workflow has no jobs: mapping");
  for (const [name, job] of all?.kind === "map" ? all.entries : []) {
    if (job.kind !== "map") {
      problems.push(`line ${job.line}: job ${name} is not a mapping`);
      continue;
    }
    const steps: YamlMap[] = [];
    const list = job.entries.get("steps");
    if (list !== undefined && list.kind !== "seq") {
      problems.push(`line ${list.line}: the steps of job ${name} are not a list`);
    }
    for (const step of list?.kind === "seq" ? list.items : []) {
      if (step.kind === "map") steps.push(step);
      else problems.push(`line ${step.line}: a step of job ${name} is not a mapping`);
    }
    jobs.set(name, { name, keys: job, steps });
  }
  return { workflow: { top, jobs }, problems };
}

/** A workflow the test expects the guard to read without a problem. */
export function parseWorkflow(text: string): Workflow {
  const { workflow, problems } = readWorkflow(text);
  if (workflow === undefined || problems.length > 0) {
    throw new Error(`the guard cannot read the workflow: ${problems.join("; ")}`);
  }
  return workflow;
}

/** A scalar's string, or undefined. */
export const stringOf = (value: Value | undefined): string | undefined =>
  value?.kind === "scalar" && typeof value.value === "string" ? value.value : undefined;

/** Every key and every scalar in a value, as strings. */
export function strings(value: Value | undefined, found: string[] = []): string[] {
  if (value?.kind === "map") {
    for (const [key, item] of value.entries) {
      found.push(key);
      strings(item, found);
    }
  } else if (value?.kind === "seq") {
    for (const item of value.items) strings(item, found);
  } else if (value !== undefined && value.value !== null) {
    found.push(String(value.value));
  }
  return found;
}

/** Every key in a value, at any depth. */
export function keysIn(value: Value | undefined, found: string[] = []): string[] {
  if (value?.kind === "map") {
    for (const [key, item] of value.entries) {
      found.push(key);
      keysIn(item, found);
    }
  } else if (value?.kind === "seq") {
    for (const item of value.items) keysIn(item, found);
  }
  return found;
}

/** A value as plain data, for comparisons in tests. */
export function plain(value: Value | undefined): unknown {
  if (value?.kind === "map") {
    return Object.fromEntries([...value.entries].map(([key, item]) => [key, plain(item)]));
  }
  if (value?.kind === "seq") return value.items.map(plain);
  return value?.value;
}

/** The jobs a job needs, from `needs: a` or `needs: [a, b]`. */
export function needs(job: Job): string[] {
  const value = job.keys.entries.get("needs");
  if (value?.kind === "seq") return value.items.flatMap((item) => stringOf(item) ?? []);
  const one = stringOf(value);
  return one === undefined ? [] : [one];
}

/** The commands of a job's steps. */
export const runs = (job: Job): string[] =>
  job.steps.flatMap((step) => stringOf(step.entries.get("run")) ?? []);

/** Every action and reusable workflow a workflow uses, job-level `uses:` included. */
export function actions(workflow: Workflow): string[] {
  return [...workflow.jobs.values()].flatMap((job) =>
    [job.keys, ...job.steps].flatMap((map) => {
      const uses = map.entries.get("uses");
      return uses === undefined ? [] : [stringOf(uses) ?? JSON.stringify(plain(uses))];
    }),
  );
}

/** The action a step uses, without its ref and in lowercase, as GitHub matches it. */
const actionOf = (step: YamlMap) =>
  stringOf(step.entries.get("uses"))?.replace(/@.*$/, "").toLowerCase();

/** A step's `with:` inputs by name in lowercase, since GitHub reads input names without case. */
function inputs(step: YamlMap): [string, Value][] {
  const given = step.entries.get("with");
  if (given?.kind !== "map") return [];
  return [...given.entries].map(([key, value]) => [key.toLowerCase(), value]);
}

const PACKAGE_MANAGER = /\b(?:pnpm|pnpx|npm|npx|yarn|corepack)\b/i;
const DEPLOY = /\bscripts\/deploy\.ts\b/;

/**
 * A job that installs packages or runs a package manager: pnpm/action-setup
 * (which installs pnpm itself), a package cache (setup-node's cache input or
 * actions/cache), any pnpm, npm, npx, yarn or corepack command, or a reusable
 * workflow (job-level `uses:`), whose steps the guard cannot see. The words
 * are matched in every key and value of the job, without case.
 */
export function installs(job: Job): boolean {
  return (
    job.keys.entries.has("uses") ||
    keysIn(job.keys).some((key) => key.toLowerCase() === "cache") ||
    job.steps.some((step) => actionOf(step) === "actions/cache") ||
    strings(job.keys).some((value) => PACKAGE_MANAGER.test(value))
  );
}

/** A job that runs the deploy, which runs the builds and Wrangler from node_modules. */
export const deploys = (job: Job): boolean => strings(job.keys).some((value) => DEPLOY.test(value));

/** A job that must wait for the release-age job: it installs or deploys. */
export const gated = (job: Job): boolean => installs(job) || deploys(job);

/** Jobs other than release-age that install or deploy without needing it. */
export const ungated = (workflow: Workflow): string[] =>
  [...workflow.jobs.values()]
    .filter((job) => job.name !== "release-age" && gated(job))
    .filter((job) => !needs(job).includes("release-age"))
    .map((job) => job.name);

/** Whether a job runs the release-age check in one of its steps. */
export const runsCheck = (job: Job): boolean => runs(job).some((run) => CHECK_RUNS.has(run));

/** GitHub's status check functions, whose names are not case-sensitive. */
const STATUS_FUNCTION = /\b(?:success|always|failure|cancelled)\s*\(/i;

/**
 * Whether a job-level if: runs the job when a job it needs failed (H-1).
 * Without a status check function GitHub adds `success() &&`; with one it adds
 * nothing, so `always()`, `!cancelled()` or `success() || true` run the job
 * after a failed check. The guard accepts a condition without one, and
 * `success()` alone or followed by `&&` and a condition without another status
 * function or `||`.
 */
export function runsAfterFailure(condition: string): boolean {
  if (!STATUS_FUNCTION.test(condition)) return false;
  const body = /^\s*\$\{\{([\s\S]*)\}\}\s*$/.exec(condition)?.[1] ?? condition;
  const match = /^\s*success\s*\(\s*\)\s*(?:&&([\s\S]*))?$/i.exec(body);
  if (match === null) return true;
  const rest = match[1] ?? "";
  return STATUS_FUNCTION.test(rest) || rest.includes("||");
}

/** The keys the release-age job, and each of its steps, may have (H-1). */
const CHECK_JOB_KEYS = new Set(["name", "runs-on", "timeout-minutes", "steps"]);
const CHECK_STEP_KEYS = new Set(["name", "uses", "with", "run"]);

/**
 * What could let the check in the release-age job fail without failing the
 * job, or change what it runs or reads (H-1): continue-on-error on the job or
 * a step, any key the guard does not know (shell, working-directory, env, if,
 * defaults, container), a command other than the check, which could change
 * the check's environment through $GITHUB_ENV or $GITHUB_PATH, an action
 * other than checkout and setup-node, and a setup-node input other than
 * node-version-file (mirror, for one). gateProblems checks the inputs of
 * checkout in every job.
 */
function checkJobProblems(job: Job): string[] {
  const problems: string[] = [];
  const keyProblems = (map: YamlMap, allowed: ReadonlySet<string>) => {
    for (const key of map.entries.keys()) {
      if (key === "continue-on-error") {
        problems.push(
          "release-age has continue-on-error, so the jobs that need it run when the check fails",
        );
      } else if (!allowed.has(key)) {
        problems.push(
          `release-age has ${JSON.stringify(key)}, a key the guard does not know; keys such as shell, working-directory, env and if change what the check runs, or whether it runs`,
        );
      }
    }
  };
  keyProblems(job.keys, CHECK_JOB_KEYS);
  for (const step of job.steps) {
    keyProblems(step, CHECK_STEP_KEYS);
    const run = step.entries.get("run");
    if (run !== undefined && !CHECK_RUNS.has(stringOf(run) ?? "")) {
      problems.push(
        `line ${run.line}: release-age runs ${preview(strings(run).join(" "))}, not the check; a command there could change the check's environment through $GITHUB_ENV or $GITHUB_PATH`,
      );
    }
    const action = actionOf(step);
    if (action === undefined || action === "actions/checkout") continue;
    if (action !== "actions/setup-node") {
      problems.push(
        `release-age uses ${action}; only actions/checkout and actions/setup-node run before the check, since an action could change what it runs`,
      );
      continue;
    }
    for (const [input] of inputs(step)) {
      if (input !== "node-version-file") {
        problems.push(
          `release-age gives actions/setup-node the input ${input}, which the guard does not know; inputs such as mirror change which Node.js runs the check`,
        );
      }
    }
  }
  return problems;
}

/**
 * actions/setup-node steps that do not take the Node.js version from .nvmrc
 * (TM-32): each must give node-version-file: .nvmrc and no node-version,
 * which setup-node prefers.
 */
function setupNodeProblems(workflow: Workflow): string[] {
  const problems: string[] = [];
  for (const job of workflow.jobs.values()) {
    for (const step of job.steps) {
      if (actionOf(step) !== "actions/setup-node") continue;
      const given = inputs(step);
      const file = given.filter(([input]) => input === "node-version-file");
      if (
        file.length !== 1 ||
        stringOf(file[0]?.[1]) !== ".nvmrc" ||
        given.some(([input]) => input === "node-version")
      ) {
        problems.push(
          `line ${step.entries.get("uses")?.line}: actions/setup-node does not take the version from .nvmrc`,
        );
      }
    }
  }
  return problems;
}

/** setup-node problems of a workflow's text, after the problems reading it. */
export function nodeProblems(source: string): string[] {
  const { workflow, problems } = readWorkflow(source);
  return workflow === undefined ? problems : [...problems, ...setupNodeProblems(workflow)];
}

/**
 * What lets a workflow install or deploy before the check (R8-04), or after a
 * failed check (H-1): what the guard cannot read, a job that installs or
 * deploys without needing release-age, a release-age job that does not run
 * the check alone or whose check can fail without failing it, workflow-level
 * env or defaults, an installing job whose if: runs it when release-age
 * failed, a pnpm/action-setup version input, a checkout of other files than
 * the release-age job checked, a setup-node that does not read .nvmrc, or an
 * action not pinned by commit SHA.
 */
export function gateProblems(source: string): string[] {
  const { workflow, problems } = readWorkflow(source);
  if (workflow === undefined) return problems;
  const jobs = [...workflow.jobs.values()];
  for (const name of ungated(workflow)) {
    problems.push(`job ${name} installs or deploys before release-age`);
  }
  const check = workflow.jobs.get("release-age");
  if (
    jobs.some(gated) &&
    (check === undefined || !runsCheck(check) || gated(check) || needs(check).length > 0)
  ) {
    problems.push("no release-age job that runs the check before anything else");
  }
  if (check !== undefined) problems.push(...checkJobProblems(check));
  for (const key of workflow.top.entries.keys()) {
    if (key.toLowerCase() === "env" || key.toLowerCase() === "defaults") {
      problems.push(
        `workflow-level ${key}: applies to the release-age job too; set it on the jobs that need it`,
      );
    }
  }
  for (const job of jobs) {
    if (job.name === "release-age" || !gated(job)) continue;
    for (const [key, condition] of job.keys.entries) {
      if (key.toLowerCase() === "if" && runsAfterFailure(strings(condition).join("\n"))) {
        problems.push(`job ${job.name} has an if: that runs it when release-age failed`);
      }
    }
  }
  for (const job of jobs) {
    for (const step of job.steps) {
      const action = actionOf(step);
      // It installs the pnpm that the root package.json names, which the check dates.
      for (const [input] of action === "pnpm/action-setup" ? inputs(step) : []) {
        problems.push(
          input === "version"
            ? "pnpm/action-setup has a version input"
            : `pnpm/action-setup has the input ${input}, which the guard does not know; inputs such as version and package_json_file change which pnpm it installs`,
        );
      }
      if (action !== "actions/checkout") continue;
      for (const [input] of inputs(step)) {
        if (input !== "persist-credentials") {
          problems.push(
            `job ${job.name} gives actions/checkout the input ${input}; inputs such as ref, repository or path check out other files than the release-age job checked`,
          );
        }
      }
    }
  }
  problems.push(...setupNodeProblems(workflow));
  for (const action of actions(workflow)) {
    if (!/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/.test(action)) {
      problems.push(`${action} is not pinned by commit SHA`);
    }
  }
  return problems;
}
