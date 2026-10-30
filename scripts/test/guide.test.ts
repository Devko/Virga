import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT } from "./helpers.ts";

const guide = readFileSync(join(REPO_ROOT, "docs", "operator", "guide.md"), "utf8");
const ci = readFileSync(join(REPO_ROOT, ".github", "workflows", "ci.yml"), "utf8");

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

/** The text of each job under `jobs:`, by job name. */
function jobs(workflow: string): Map<string, string> {
  const result = new Map<string, string>();
  let name: string | undefined;
  const at = workflow.indexOf("\njobs:\n");
  expect(at).toBeGreaterThan(-1);
  for (const line of workflow.slice(at).split("\n").slice(2)) {
    const header = /^ {2}([\w-]+):$/.exec(line);
    if (header?.[1] !== undefined) {
      name = header[1];
      result.set(name, "");
    } else if (name !== undefined && line.startsWith("    ")) {
      result.set(name, `${result.get(name)}${line}\n`);
    }
  }
  return result;
}

/** The jobs a job needs, from `needs: a` or `needs: [a, b]`. */
function needs(job: string): string[] {
  const [, one, list] = /^ {4}needs: (?:([\w-]+)|\[([^\]]*)\])$/m.exec(job) ?? [];
  if (one !== undefined) return [one];
  return list === undefined ? [] : list.split(",").map((name) => name.trim());
}

/**
 * A job that installs packages or runs a package manager: pnpm/action-setup
 * (which installs the pnpm that package.json names), a setup-node package
 * cache, or any pnpm, npm, npx, yarn or corepack command.
 */
const INSTALLS = /uses: pnpm\/action-setup@|^\s+cache:|\b(?:pnpm|pnpx|npm|npx|yarn|corepack)\b/m;
/** A job that runs the deploy, which runs the builds and Wrangler from node_modules. */
const DEPLOYS = /\bscripts\/deploy\.ts\b/;

/** Jobs other than release-age that install or deploy without waiting for it. */
const ungated = (workflow: string) =>
  [...jobs(workflow)]
    .filter(([name, job]) => name !== "release-age" && (INSTALLS.test(job) || DEPLOYS.test(job)))
    .filter(([, job]) => !needs(job).includes("release-age"))
    .map(([name]) => name);

describe('operator guide, "Deploy from CI"', () => {
  const workflow = blocks(section("### Deploy from CI"), "yaml")[0] ?? "";

  it("R8-04: holds one example workflow", () => {
    expect(blocks(section("### Deploy from CI"), "yaml")).toHaveLength(1);
    expect(workflow).toContain("\njobs:\n");
    expect([...jobs(workflow).keys()]).toContain("deploy");
  });

  it("R8-04: runs the release-age check in its own job, which installs nothing", () => {
    const check = jobs(workflow).get("release-age") ?? "";
    expect(check).toContain("- run: node scripts/check-release-age.ts\n");
    expect(check).not.toMatch(INSTALLS);
    expect(check).not.toMatch(DEPLOYS);
    expect(needs(check)).toEqual([]);
  });

  it("R8-04: every job that installs or deploys needs the release-age job", () => {
    const gated = [...jobs(workflow)].filter(
      ([name, job]) => name !== "release-age" && (INSTALLS.test(job) || DEPLOYS.test(job)),
    );
    expect(gated.map(([name]) => name)).toContain("deploy");
    expect(ungated(workflow)).toEqual([]);
  });

  it("R8-04: finds a job that installs or deploys before the check", () => {
    expect(ungated(workflow.replace(/^ {4}needs: release-age\n/m, ""))).toEqual(["deploy"]);
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
    expect(ungated(`\n${synthetic}`)).toEqual(["deploy-only", "cached"]);
  });

  it("R8-04: the deploy job restores no package cache", () => {
    const deploy = jobs(workflow).get("deploy") ?? "";
    expect(deploy).toMatch(DEPLOYS);
    expect(deploy).not.toMatch(/^\s+cache(?:-dependency-path)?:/m);
    expect(deploy).not.toMatch(/uses: actions\/cache/);
  });

  it("R8-04: pins every action by the commit SHA that CI uses", () => {
    const uses = [...workflow.matchAll(/uses: (\S+)/g)].map((match) => match[1] ?? "");
    const pinned = new Set([...ci.matchAll(/uses: (\S+)/g)].map((match) => match[1]));
    expect(uses.length).toBeGreaterThan(0);
    for (const action of uses) {
      expect(action).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
      expect(pinned.has(action), action).toBe(true);
    }
    expect(workflow).toContain("\npermissions:\n  contents: read\n");
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
