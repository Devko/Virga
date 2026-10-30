import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT } from "./helpers.ts";
import {
  actions,
  CHECK_RUNS,
  deploys,
  gated,
  gateProblems,
  type Job,
  keysIn,
  needs,
  parseWorkflow,
  plain,
  runs,
  ungated,
  type Workflow,
} from "./workflow-guard.ts";

const guide = readFileSync(join(REPO_ROOT, "docs", "operator", "guide.md"), "utf8");
const ci = parseWorkflow(readFileSync(join(REPO_ROOT, ".github", "workflows", "ci.yml"), "utf8"));

/** The text of a section of the guide, from its heading to the next heading of any level. */
function section(heading: string): string {
  const start = guide.indexOf(`\n${heading}\n`);
  expect(start, heading).toBeGreaterThan(-1);
  const rest = guide.slice(start + heading.length + 2);
  // Headings outside code blocks; a `#` comment inside a block is not one.
  let inBlock = false;
  let end = 0;
  for (const line of rest.split("\n")) {
    if (line.startsWith("```")) inBlock = !inBlock;
    else if (!inBlock && /^#{1,6} /.test(line)) break;
    end += line.length + 1;
  }
  return rest.slice(0, end);
}

/** The code blocks of `text` in a language. */
const blocks = (text: string, language: string) =>
  [...text.matchAll(new RegExp(`^\`\`\`${language}\\n([^]*?)^\`\`\`$`, "gm"))].map(
    (match) => match[1] ?? "",
  );

/** A job of a parsed workflow. */
function jobOf(workflow: Workflow, name: string): Job {
  const found = workflow.jobs.get(name);
  expect(found, name).toBeDefined();
  return found as Job;
}

describe('operator guide, "Deploy from CI"', () => {
  const workflow = blocks(section("### Deploy from CI"), "yaml")[0] ?? "";
  const example = parseWorkflow(workflow);
  const IGNORED =
    "release-age has continue-on-error, so the jobs that need it run when the check fails";
  const RUNS = "job deploy has an if: that runs it when release-age failed";

  it("R8-04: holds one example workflow", () => {
    expect(blocks(section("### Deploy from CI"), "yaml")).toHaveLength(1);
    expect(workflow).toContain("\njobs:\n");
    expect([...example.jobs.keys()]).toContain("deploy");
  });

  it("R8-04: runs the release-age check in its own job, which installs nothing", () => {
    const check = jobOf(example, "release-age");
    expect(runs(check)).toHaveLength(1);
    expect(CHECK_RUNS.has(runs(check)[0] ?? "")).toBe(true);
    expect(gated(check)).toBe(false);
    expect(needs(check)).toEqual([]);
  });

  it("R8-04: every job that installs or deploys needs the release-age job", () => {
    const gatedJobs = [...example.jobs.values()].filter(
      (job) => job.name !== "release-age" && gated(job),
    );
    expect(gatedJobs.map(({ name }) => name)).toContain("deploy");
    expect(ungated(example)).toEqual([]);
  });

  it("R8-04: finds a job that installs or deploys before the check", () => {
    const unneeded = workflow.replace(/^ {4}needs: release-age\n/m, "");
    expect(unneeded).not.toBe(workflow);
    expect(ungated(parseWorkflow(unneeded))).toEqual(["deploy"]);
    const synthetic = [
      "jobs:",
      "  release-age:",
      "    steps:",
      "      - run: node scripts/check-release-age.ts",
      "  deploy-only:",
      "    steps:",
      "      - run: node scripts/deploy.ts",
      "  cached:",
      "    needs: [build]",
      "    steps:",
      "      - with:",
      "          cache: pnpm",
      "  gated:",
      "    needs: [build, release-age]",
      "    steps:",
      "      - run: pnpm install --frozen-lockfile && node scripts/deploy.ts",
      "",
    ].join("\n");
    expect(ungated(parseWorkflow(synthetic))).toEqual(["deploy-only", "cached"]);
  });

  it("H-1: neither lets the check fail nor runs the deploy job when it failed", () => {
    expect(gateProblems(workflow)).toEqual([]);
    const deploy = jobOf(example, "deploy");
    expect(deploys(deploy)).toBe(true);
    expect([...deploy.keys.entries.keys()].map((key) => key.toLowerCase())).not.toContain("if");
    expect(keysIn(jobOf(example, "release-age").keys)).not.toContain("continue-on-error");
  });

  it("H-1: finds continue-on-error in the check and a status function in a gated job's if", () => {
    const withCheck = (job: string) =>
      workflow.replace("      - run: node scripts/check-release-age.ts\n", job);
    expect(
      gateProblems(
        withCheck(
          "      - run: node scripts/check-release-age.ts\n        continue-on-error: true\n",
        ),
      ),
    ).toEqual([IGNORED]);
    expect(
      gateProblems(
        workflow.replace("  release-age:\n", "  release-age:\n    continue-on-error: true\n"),
      ),
    ).toEqual([IGNORED]);
    /** A GitHub expression, `${{ body }}`. */
    const expression = (body: string) => `$\{{ ${body} }}`;
    for (const condition of [
      "always()",
      expression("always()"),
      expression("ALWAYS() && true"),
      "Failure()",
      expression("cancelled ()"),
      "|\n      success() ||\n      failure()",
      "success() || true",
    ]) {
      const changed = workflow.replace(
        "    needs: release-age\n",
        `    needs: release-age\n    if: ${condition}\n`,
      );
      expect(gateProblems(changed), condition).toEqual([RUNS]);
    }
    // success() and other conditions run the job only when the check passed.
    const passing = workflow.replace(
      "    needs: release-age\n",
      `    needs: release-age\n    if: ${expression("success() && github.ref == 'refs/heads/main'")}\n`,
    );
    expect(gateProblems(passing)).toEqual([]);
  });

  it("R10-03: finds the review's variants in the example: a 5-space release-age job, an escaped always()", () => {
    // (a) The release-age job's keys at 5 spaces, with continue-on-error: true.
    const fiveSpaces = workflow.replace(
      "    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n",
      "     runs-on: ubuntu-24.04\n     timeout-minutes: 10\n     continue-on-error: true\n     steps:\n",
    );
    expect(fiveSpaces).not.toBe(workflow);
    expect(gateProblems(fiveSpaces)).toEqual([IGNORED]);
    // (b) The deploy job's if: is "\x61lways()", which YAML reads as always().
    const escaped = workflow.replace(
      "    needs: release-age\n",
      '    needs: release-age\n    if: "\\x61lways()"\n',
    );
    expect(escaped).not.toBe(workflow);
    expect(gateProblems(escaped)).toEqual([RUNS]);
  });

  it("R8-04: the deploy job restores no package cache", () => {
    const deploy = jobOf(example, "deploy");
    expect(deploys(deploy)).toBe(true);
    const keys = keysIn(deploy.keys).map((key) => key.toLowerCase());
    expect(keys).not.toContain("cache");
    expect(keys).not.toContain("cache-dependency-path");
    expect(actions(example).filter((action) => /^actions\/cache@/i.test(action))).toEqual([]);
  });

  it("R8-04: pins every action by the commit SHA that CI uses", () => {
    const uses = actions(example);
    const pinned = new Set(actions(ci));
    expect(uses.length).toBeGreaterThan(0);
    for (const action of uses) {
      expect(action).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
      expect(pinned.has(action), action).toBe(true);
    }
    expect(plain(example.top.entries.get("permissions"))).toEqual({ contents: "read" });
  });
});

describe('operator guide, "Run the deploy"', () => {
  /** Bare module names imported by the sources of packages/<name>, tests left out. */
  const imports = (name: string) => {
    const src = join(REPO_ROOT, "packages", name, "src");
    const found = new Set<string>();
    for (const file of readdirSync(src, { recursive: true, encoding: "utf8" })) {
      if (!file.endsWith(".ts") || file.endsWith(".test.ts")) continue;
      const text = readFileSync(join(src, file), "utf8");
      for (const [, spec] of text.matchAll(/\b(?:from|import)\s*\(?\s*"([^".][^"]*)"/g)) {
        if (spec !== undefined && !spec.startsWith("node:")) found.add(spec);
      }
    }
    return found;
  };

  it("H-2: names every package the rule compiler loads into the process that holds the token", () => {
    // The workspace packages rules/ reaches, and the third-party packages they import.
    const workspace = new Set(["rules"]);
    const thirdParty = new Set<string>();
    for (const name of workspace) {
      for (const spec of imports(name)) {
        const scoped = /^@virga\/([^/]+)/.exec(spec);
        if (scoped?.[1] !== undefined) workspace.add(scoped[1]);
        else thirdParty.add(spec);
      }
    }
    expect([...thirdParty]).toEqual(["yaml"]);
    const run = section("### Run the deploy");
    for (const name of [...workspace].filter((name) => name !== "rules")) {
      expect(run, name).toContain(`\`@virga/${name}\``);
    }
    for (const name of thirdParty) expect(run).toContain(`the YAML parser \`${name}\``);
    expect(run).toContain("`yaml` is the only third-party package in that process");
    expect(run).toContain("the release-age check dates it");
  });
});

describe("operator guide, workstation steps", () => {
  it("R8-04: runs the release-age check with Node before pnpm installs anything", () => {
    const commands = blocks(guide, "sh");
    const installing = commands.filter((block) => /\bpnpm install\b/.test(block));
    expect(installing.length).toBeGreaterThan(0);
    for (const block of installing) {
      const check = block.indexOf("node scripts/check-release-age.ts");
      expect(check, block).toBeGreaterThan(-1);
      expect(check, block).toBeLessThan(block.search(/\b(?:corepack|pnpm) /));
    }
    // Through pnpm, the commit's pnpm would run before the check.
    for (const block of commands) expect(block).not.toMatch(/\bpnpm (?:run )?check:release-age/);
  });

  it("R8-04: names the check before pnpm install in Updates", () => {
    const updates = section("### Updates");
    const check = updates.indexOf("node scripts/check-release-age.ts");
    expect(check).toBeGreaterThan(-1);
    expect(check).toBeLessThan(updates.indexOf("pnpm install"));
  });
});
