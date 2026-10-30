import { createHash } from "node:crypto";
import {
  appendFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { checkAppDir } from "../lib/config.ts";
import { recordWorkspace, WorkspaceError, workspaceChanges } from "../lib/workspace.ts";
import { put, REPO_ROOT } from "./helpers.ts";

/** packages/<name> with its package.json and a source file. */
function workspacePackage(root: string, name: string) {
  put(join(root, "packages", name, "package.json"), JSON.stringify({ name: `@virga/${name}` }));
  put(join(root, "packages", name, "src", "index.ts"), `export const NAME = "${name}";\n`);
}

/** `from`/node_modules/@virga/<name>, a relative link to `target`, as pnpm links it. */
function pnpmLink(from: string, name: string, target: string) {
  const at = join(from, "node_modules", "@virga", name);
  mkdirSync(dirname(at), { recursive: true });
  rmSync(at, { force: true });
  symlinkSync(relative(dirname(at), target), at);
  return at;
}

describe("recordWorkspace (L-2)", () => {
  let root = "";
  const core = (...parts: string[]) => join(root, "apps", "core", ...parts);
  const packages = (...parts: string[]) => join(root, "packages", ...parts);
  /** apps/core linking rules and graph; rules links collectors and graph; collectors links graph. */
  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "virga-workspace-")));
    for (const name of ["graph", "collectors", "rules"]) workspacePackage(root, name);
    put(packages("rules", "src", "rules.gen.ts"), "export const RULES = [];\n");
    put(core("wrangler.jsonc"), `{ "name": "virga-core" }`);
    put(core("src", "index.ts"), "export default {};\n");
    for (const name of ["rules", "graph"]) pnpmLink(core(), name, packages(name));
    for (const name of ["collectors", "graph"]) pnpmLink(packages("rules"), name, packages(name));
    pnpmLink(packages("collectors"), "graph", packages("graph"));
    mkdirSync(join(root, "outside"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const problem = () => {
    try {
      recordWorkspace(root, "core");
      return null;
    } catch (error) {
      expect(error).toBeInstanceOf(WorkspaceError);
      return (error as Error).message;
    }
  };

  it("L-2: records the @virga links of an app and of the workspace packages they lead to", () => {
    const record = recordWorkspace(root, "core");
    expect(record.appDir).toBe(core());
    expect(
      [...record.links].map(
        ([link, target]) => `${relative(root, link)} ${relative(root, target)}`,
      ),
    ).toEqual([
      "apps/core/node_modules/@virga/graph packages/graph",
      "apps/core/node_modules/@virga/rules packages/rules",
      "packages/rules/node_modules/@virga/collectors packages/collectors",
      "packages/rules/node_modules/@virga/graph packages/graph",
      "packages/collectors/node_modules/@virga/graph packages/graph",
    ]);
    expect(checkAppDir(root, "core")).toBe(core("wrangler.jsonc"));
    // An app without workspace packages records none.
    put(join(root, "apps", "web", "wrangler.jsonc"), `{ "name": "virga-web" }`);
    expect(recordWorkspace(root, "web").links.size).toBe(0);
  });

  it("L-2: refuses a link retargeted to another copy of the package, which Wrangler would bundle", () => {
    // A copy of packages/rules with another rules.gen.ts.
    cpSync(packages("rules"), join(root, "outside", "rules"), { recursive: true });
    appendFileSync(join(root, "outside", "rules", "src", "rules.gen.ts"), "// planted\n");
    pnpmLink(core(), "rules", join(root, "outside", "rules"));
    expect(problem()).toBe(
      `apps/core/node_modules/@virga/rules leads to ${join(root, "outside", "rules")}, not to packages/rules, the workspace package @virga/rules; Wrangler would bundle what it leads to. Unless you changed the link yourself, find what wrote it, starting with the build scripts, and deploy from a fresh clone (operator guide, Troubleshooting)`,
    );
    // checkAppDir runs the same check.
    expect(() => checkAppDir(root, "core")).toThrow("apps/core/node_modules/@virga/rules leads to");
    // Another workspace package under the name.
    pnpmLink(core(), "rules", packages("graph"));
    expect(problem()).toContain(
      `apps/core/node_modules/@virga/rules leads to ${packages("graph")}, not to packages/rules`,
    );
  });

  it("L-2: refuses a retargeted link in the node_modules of a workspace package", () => {
    cpSync(packages("graph"), join(root, "outside", "graph"), { recursive: true });
    pnpmLink(packages("collectors"), "graph", join(root, "outside", "graph"));
    expect(problem()).toContain(
      `packages/collectors/node_modules/@virga/graph leads to ${join(root, "outside", "graph")}, not to packages/graph`,
    );
  });

  it("L-2: refuses a symlink inside packages/graph/src, and a package directory that is one", () => {
    writeFileSync(join(root, "outside", "index.ts"), 'export const NAME = "planted";\n');
    rmSync(packages("graph", "src", "index.ts"));
    symlinkSync(join(root, "outside", "index.ts"), packages("graph", "src", "index.ts"));
    expect(problem()).toBe(
      "packages/graph, which apps/core bundles through apps/core/node_modules/@virga/graph, holds symlinks outside node_modules: packages/graph/src/index.ts. Wrangler bundles what a link points to, wherever that is. Replace each link with the file",
    );
    rmSync(packages("graph", "src", "index.ts"));
    writeFileSync(packages("graph", "src", "index.ts"), 'export const NAME = "graph";\n');
    expect(problem()).toBeNull();

    renameSync(packages("graph"), join(root, "outside", "graph"));
    symlinkSync(join(root, "outside", "graph"), packages("graph"));
    expect(problem()).toBe(
      "packages/graph, which apps/core bundles through apps/core/node_modules/@virga/graph, holds symlinks outside node_modules: packages/graph. Wrangler bundles what a link points to, wherever that is. Replace each link with the file",
    );
  });

  it("L-2: refuses a node_modules directory in a package's or an app's sources, which Wrangler would search first", () => {
    // A plain copy, no link: found before the checked package from anything in src/.
    cpSync(packages("graph"), packages("rules", "src", "node_modules", "@virga", "graph"), {
      recursive: true,
    });
    expect(problem()).toBe(
      "packages/rules, which apps/core bundles through apps/core/node_modules/@virga/rules, holds node_modules directories other than its own: packages/rules/src/node_modules. Wrangler takes a package from the nearest node_modules directory, so one there would replace the package pnpm installed. Remove them",
    );
    rmSync(packages("rules", "src", "node_modules"), { recursive: true });

    // A plain copy of the package's files, without its links.
    cpSync(packages("rules", "src"), core("src", "node_modules", "@virga", "rules", "src"), {
      recursive: true,
    });
    expect(() => checkAppDir(root, "core")).toThrow(
      "apps/core holds node_modules directories other than its own: apps/core/src/node_modules. Wrangler and Vite take a package from the nearest node_modules directory, so one there would replace the package pnpm installed. Remove them",
    );
  });

  it("L-2: refuses a link that leads nowhere, and an entry that is not a workspace package", () => {
    pnpmLink(core(), "missing", packages("missing"));
    cpSync(packages("graph"), join(root, "outside", "evil"), { recursive: true });
    writeFileSync(join(root, "outside", "evil", "package.json"), '{ "name": "@virga/evil" }');
    pnpmLink(core(), "evil", join(root, "outside", "evil"));
    expect(problem()?.split("\n")).toEqual([
      `apps/core/node_modules/@virga/evil: packages/evil is not the workspace package @virga/evil, so Wrangler would bundle what the link leads to (${join(root, "outside", "evil")}) unchecked. Remove it and run pnpm install`,
      "apps/core/node_modules/@virga/missing leads to a path that does not exist; it should lead to packages/missing. Run pnpm install",
    ]);
    rmSync(core("node_modules", "@virga", "missing"));
    rmSync(core("node_modules", "@virga", "evil"));
    // packages/<name> must be the package of that name.
    writeFileSync(packages("graph", "package.json"), '{ "name": "@virga/other" }');
    expect(problem()).toContain(
      "apps/core/node_modules/@virga/graph: packages/graph is not the workspace package @virga/graph",
    );
  });

  it("L-2: refuses a node_modules/@virga that is not a directory", () => {
    rmSync(core("node_modules", "@virga"), { recursive: true });
    mkdirSync(join(root, "outside", "scope"));
    symlinkSync(join(root, "outside", "scope"), core("node_modules", "@virga"));
    expect(problem()).toBe(
      "apps/core/node_modules/@virga is not a directory; pnpm links each workspace package into a directory of that name. Run pnpm install",
    );
  });

  it("L-2: names a link that was removed or retargeted after the record", () => {
    const before = recordWorkspace(root, "core");
    expect(workspaceChanges(before)).toBeNull();
    // Without the link, Wrangler would look further up, for example in apps/node_modules.
    rmSync(core("node_modules", "@virga", "graph"));
    expect(workspaceChanges(before)).toBe(
      "the workspace links of apps/core changed after the deploy recorded them before the builds: apps/core/node_modules/@virga/graph. Wrangler takes the workspace packages through them. Unless you changed them yourself, find what wrote them, starting with the build scripts, and deploy from a fresh clone (operator guide, Troubleshooting)",
    );
    pnpmLink(core(), "graph", packages("graph"));
    expect(workspaceChanges(before)).toBeNull();
    pnpmLink(core(), "graph", join(root, "outside"));
    expect(workspaceChanges(before)).toContain("apps/core/node_modules/@virga/graph leads to");
  });
});

/** A tsconfig.json as the repository's apps and packages have it, comment and trailing comma included. */
const EXTENDS_BASE = `{
  // As in the repository.
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "types": [] },
}
`;

/** compilerOptions that map @virga/rules to another module, as the review's build wrote them. */
const mapping = (to: string) =>
  JSON.stringify({
    extends: "../../tsconfig.base.json",
    compilerOptions: { baseUrl: ".", paths: { "@virga/rules": [to] } },
  });

const MAPPING_REASON =
  "Wrangler's bundler (esbuild) resolves imports through paths and baseUrl before node_modules, and TypeScript through rootDirs too, so a mapping could make apps/core bundle another module in place of a workspace package, past the checks of the workspace links and the generated rules. Virga sets none of them; remove it";

const CHANGED_REASON =
  "esbuild takes paths and baseUrl from tsconfig.json and jsconfig.json and the files they extend, and exports, main, imports and browser from package.json, so a change there can make Wrangler bundle another module than the one the deploy checked. Unless you changed them yourself, find what wrote them, starting with the build scripts, and deploy from a fresh clone (operator guide, Troubleshooting)";

describe("recordWorkspace and module resolution (R10-04)", () => {
  let root = "";
  const core = (...parts: string[]) => join(root, "apps", "core", ...parts);
  const packages = (...parts: string[]) => join(root, "packages", ...parts);
  /** The repository's layout: a base config that every app and package extends. */
  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "virga-resolution-")));
    put(join(root, "package.json"), '{ "name": "virga", "private": true }');
    put(join(root, "tsconfig.base.json"), '{ "compilerOptions": { "strict": true } }');
    for (const name of ["graph", "rules"]) {
      workspacePackage(root, name);
      put(packages(name, "tsconfig.json"), EXTENDS_BASE);
    }
    put(
      packages("rules", "package.json"),
      JSON.stringify({ name: "@virga/rules", exports: { ".": "./src/index.ts" } }),
    );
    put(core("package.json"), '{ "name": "@virga/core" }');
    put(core("tsconfig.json"), EXTENDS_BASE);
    put(core("test", "tsconfig.json"), '{ "extends": "../tsconfig.json" }');
    put(core("wrangler.jsonc"), `{ "name": "virga-core" }`);
    put(core("src", "index.ts"), "export default {};\n");
    for (const name of ["rules", "graph"]) pnpmLink(core(), name, packages(name));
    pnpmLink(packages("rules"), "graph", packages("graph"));
    put(join(root, "outside", "rules", "index.ts"), 'export const RULES = "planted";\n');
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const problem = () => {
    try {
      recordWorkspace(root, "core");
      return null;
    } catch (error) {
      expect(error).toBeInstanceOf(WorkspaceError);
      return (error as Error).message;
    }
  };
  /** The recorded files inside the checkout, by relative path. */
  const recorded = (record: ReturnType<typeof recordWorkspace>) =>
    [...record.resolution.keys()]
      .map((path) => relative(root, path))
      .filter((path) => !path.startsWith(".."))
      .sort();

  it("R10-04: records the tsconfig chain and the package.json files esbuild reads for an app", () => {
    const record = recordWorkspace(root, "core");
    expect(recorded(record)).toEqual([
      "apps/core/package.json",
      "apps/core/test/tsconfig.json",
      "apps/core/tsconfig.json",
      "package.json",
      "packages/graph/package.json",
      "packages/graph/tsconfig.json",
      "packages/rules/package.json",
      "packages/rules/tsconfig.json",
      "tsconfig.base.json",
    ]);
    const sha256 = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
    for (const path of [core("tsconfig.json"), join(root, "tsconfig.base.json")]) {
      expect(record.resolution.get(path), path).toBe(sha256(path));
    }
    expect(workspaceChanges(record)).toBeNull();
  });

  it("R10-04: refuses paths for @virga/rules that a build wrote into apps/core/tsconfig.json or tsconfig.base.json", () => {
    const before = recordWorkspace(root, "core");
    writeFileSync(core("tsconfig.json"), mapping("../../outside/rules/index.ts"));
    const app = `apps/core/tsconfig.json sets compilerOptions.paths and compilerOptions.baseUrl: ${MAPPING_REASON}`;
    expect(workspaceChanges(before)).toBe(app);
    expect(problem()).toBe(app);
    expect(() => checkAppDir(root, "core")).toThrow(app);
    writeFileSync(core("tsconfig.json"), EXTENDS_BASE);
    expect(workspaceChanges(before)).toBeNull();

    writeFileSync(
      join(root, "tsconfig.base.json"),
      JSON.stringify({
        compilerOptions: { paths: { "@virga/rules": ["./outside/rules/index.ts"] } },
      }),
    );
    expect(workspaceChanges(before)).toBe(
      `tsconfig.base.json, which apps/core/tsconfig.json extends, sets compilerOptions.paths: ${MAPPING_REASON}`,
    );
  });

  it("R10-04: refuses paths, baseUrl and rootDirs wherever esbuild or TypeScript would read them", () => {
    // A workspace package's own config.
    writeFileSync(
      packages("rules", "tsconfig.json"),
      '{ "compilerOptions": { "rootDirs": ["src"] } }',
    );
    expect(problem()).toBe(
      `packages/rules/tsconfig.json sets compilerOptions.rootDirs: ${MAPPING_REASON}`,
    );
    writeFileSync(packages("rules", "tsconfig.json"), EXTENDS_BASE);
    // A config nearer to the sources, which esbuild takes in place of the app's.
    for (const name of ["tsconfig.json", "jsconfig.json", "TSConfig.json"]) {
      put(core("src", name), '{ "compilerOptions": { "baseUrl": "." } }');
      expect(problem(), name).toBe(
        `apps/core/src/${name} sets compilerOptions.baseUrl: ${MAPPING_REASON}`,
      );
      rmSync(core("src", name));
    }
    // A config the app's extends through a second file.
    writeFileSync(core("tsconfig.json"), '{ "extends": ["../../tsconfig.base.json", "./more"] }');
    put(core("more.json"), '{ "extends": "./paths.json" }');
    put(core("paths.json"), mapping("../../outside/rules/index.ts"));
    expect(problem()).toBe(
      `apps/core/paths.json, which apps/core/more.json extends, sets compilerOptions.paths and compilerOptions.baseUrl: ${MAPPING_REASON}`,
    );
    // Without the app's own config, esbuild takes the nearest one above it.
    rmSync(core("tsconfig.json"));
    rmSync(core("test"), { recursive: true });
    put(
      join(root, "apps", "tsconfig.json"),
      JSON.stringify({ compilerOptions: { paths: { "@virga/rules": ["../outside/rules"] } } }),
    );
    expect(problem()).toBe(`apps/tsconfig.json sets compilerOptions.paths: ${MAPPING_REASON}`);
  });

  it("R10-04: refuses an extends esbuild would take from node_modules, one that leads nowhere, and a config that is not JSON with comments", () => {
    writeFileSync(core("tsconfig.json"), '{ "extends": "@tsconfig/strictest/tsconfig.json" }');
    expect(problem()).toBe(
      'apps/core/tsconfig.json extends "@tsconfig/strictest/tsconfig.json", a package: esbuild and TypeScript would look for it in node_modules, where the deploy does not check it. Extend a file by its path, starting with ./ or ../, as Virga\'s tsconfig files extend ../../tsconfig.base.json',
    );
    writeFileSync(core("tsconfig.json"), '{ "extends": "../../missing" }');
    expect(problem()).toBe(
      'apps/core/tsconfig.json extends "../../missing", which is not a file (missing, also with .json). Fix or remove the extends',
    );
    writeFileSync(core("tsconfig.json"), '{ "extends": 1 }');
    expect(problem()).toBe(
      "apps/core/tsconfig.json: extends is neither a path nor a list of paths. Fix it",
    );
    writeFileSync(core("tsconfig.json"), '{ "compilerOptions": { "paths": {}, "paths": {} } }');
    expect(problem()).toMatch(
      /^apps\/core\/tsconfig\.json cannot be read as JSON with comments: duplicate key "paths" at line 1, column \d+\. Wrangler's bundler \(esbuild\) reads it to resolve imports, so the deploy checks it too\. Fix it$/,
    );
    // Without .json, as esbuild and TypeScript take it; a file created at the name itself would replace it.
    writeFileSync(core("tsconfig.json"), '{ "extends": "../../tsconfig.base" }');
    const record = recordWorkspace(root, "core");
    expect(record.resolution.get(join(root, "tsconfig.base"))).toBe("absent");
    put(join(root, "tsconfig.base"), "{}");
    expect(workspaceChanges(record)).toBe(
      `the files that tell Wrangler's bundler how to resolve the modules of apps/core changed after the deploy recorded them before the builds: tsconfig.base (added). ${CHANGED_REASON}`,
    );
  });

  it("R10-04: names a tsconfig or package.json that was changed, added or removed after the record", () => {
    const before = recordWorkspace(root, "core");
    // The review's second case: exports that point the bundle at another file.
    writeFileSync(
      packages("rules", "package.json"),
      JSON.stringify({ name: "@virga/rules", exports: { ".": "./src/planted.ts" } }),
    );
    expect(workspaceChanges(before)).toBe(
      `the files that tell Wrangler's bundler how to resolve the modules of apps/core changed after the deploy recorded them before the builds: packages/rules/package.json (changed). ${CHANGED_REASON}`,
    );
    // A config added next to the sources, one removed, and a browser map in a package.json above.
    put(core("src", "jsconfig.json"), "{}");
    rmSync(packages("graph", "tsconfig.json"));
    put(join(root, "apps", "package.json"), '{ "browser": { "./x.ts": "./y.ts" } }');
    expect(workspaceChanges(before)).toBe(
      `the files that tell Wrangler's bundler how to resolve the modules of apps/core changed after the deploy recorded them before the builds: apps/core/src/jsconfig.json (added), apps/package.json (added), packages/graph/tsconfig.json (removed), packages/rules/package.json (changed). ${CHANGED_REASON}`,
    );
  });
});

describe("the workspace links of the repository (L-2)", () => {
  it("L-2: the real tree passes, and core bundles packages/rules", () => {
    for (const app of ["broker", "core", "web"]) {
      expect(checkAppDir(REPO_ROOT, app), app).toBe(join(REPO_ROOT, "apps", app, "wrangler.jsonc"));
    }
    const core = recordWorkspace(REPO_ROOT, "core");
    const links = new Map(
      [...core.links].map(([link, target]) => [relative(REPO_ROOT, link), target]),
    );
    for (const name of ["cf-api", "collectors", "exposure", "graph", "rules"]) {
      expect(links.get(`apps/core/node_modules/@virga/${name}`), name).toBe(
        realpathSync(join(REPO_ROOT, "packages", name)),
      );
    }
    expect(links.get("packages/rules/node_modules/@virga/graph")).toBe(
      realpathSync(join(REPO_ROOT, "packages", "graph")),
    );
    expect([...recordWorkspace(REPO_ROOT, "broker").links.keys()]).toEqual([
      join(REPO_ROOT, "apps", "broker", "node_modules", "@virga", "cf-api"),
    ]);
  });

  it("R10-04: the real tree passes, and each app's record holds its tsconfig chain and the package.json files esbuild reads", () => {
    /** The recorded files inside the checkout, by relative path. */
    const recorded = (app: string) =>
      new Set(
        [...recordWorkspace(REPO_ROOT, app).resolution.keys()]
          .map((path) => relative(REPO_ROOT, path))
          .filter((path) => !path.startsWith("..")),
      );
    const chain = (app: string) => [
      "package.json",
      "tsconfig.base.json",
      `apps/${app}/package.json`,
      `apps/${app}/tsconfig.json`,
      `apps/${app}/test/tsconfig.json`,
    ];
    const bundled = (name: string) => [
      `packages/${name}/package.json`,
      `packages/${name}/tsconfig.json`,
    ];
    const core = recorded("core");
    for (const path of [
      ...chain("core"),
      ...["cf-api", "collectors", "exposure", "graph", "rules", "vulns"].flatMap(bundled),
    ]) {
      expect(core.has(path), path).toBe(true);
    }
    expect([...recorded("broker")].sort()).toEqual(
      [...chain("broker"), ...bundled("cf-api")].sort(),
    );
    expect([...recorded("web")].sort()).toEqual(
      [...chain("web"), "apps/web/spa/tsconfig.json"].sort(),
    );
  });
});
