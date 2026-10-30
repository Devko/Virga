import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  type CheckOptions,
  checkReleaseAge,
  EXCEPTIONS,
  type Exception,
  LockfileError,
  type MainOptions,
  main,
  PackageJsonError,
  parseLockfile,
  parseNpmrc,
  parsePackageManager,
  parseWorkspace,
} from "../check-release-age.ts";
import { put, REPO_ROOT } from "./helpers.ts";
import {
  actions,
  gated,
  gateProblems,
  type Job,
  needs,
  nodeProblems,
  parseWorkflow,
  plain,
  runs,
  stringOf,
  ungated,
} from "./workflow-guard.ts";

const NOW = new Date("2026-10-30T12:00:00Z");
const DAY = 86_400_000;
const ago = (days: number) => new Date(NOW.getTime() - days * DAY).toISOString();

/** A lockfile in the layout pnpm writes, with one snapshot per packages entry. */
function lockfile(entries: string[]): string {
  const keys = entries.map((entry) => entry.slice(2, entry.indexOf(":\n")));
  return [
    "lockfileVersion: '9.0'",
    "",
    "settings:",
    "  autoInstallPeers: true",
    "",
    "importers:",
    "",
    "  .: {}",
    "",
    "packages:",
    "",
    ...entries.flatMap((entry) => [entry, ""]),
    "snapshots:",
    "",
    ...keys.flatMap((key) => [`  ${key}: {}`, ""]),
  ].join("\n");
}

const TYPES_NODE_INTEGRITY =
  "sha512-MzQj+8Kx3XI40OmUAE6Qoh58ZMNstNNMwn2nfd3qWsfe7nDNSqJNzes4njhz6AHwrSHOffSLwXU6yb474Q4aog==";
const UNDICI_TYPES_INTEGRITY =
  "sha512-KTDyRTYX8sWmKXAikPHHSyc63CRPETMctyjKFupcC6OBLXT3xsN0e9aF7m+mIXutFWpUXuedtowG7iLOzp0kQg==";

/**
 * The review's lockfile (R6-03), as pnpm 10.28.0 writes it: @types/node
 * 26.6.6, published 2026-10-28, and its dependency. Line 17 is the packages
 * key of @types/node.
 */
const REVIEW_LOCKFILE = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      '@types/node':
        specifier: 26.6.6
        version: 26.6.6

packages:

  '@types/node@26.6.6':
    resolution: {integrity: ${TYPES_NODE_INTEGRITY}}

  undici-types@8.9.0:
    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}

snapshots:

  '@types/node@26.6.6':
    dependencies:
      undici-types: 8.9.0

  undici-types@8.9.0: {}
`;

/** The review's three layouts: valid YAML that pnpm installs from, with the same entries. */
function reviewLayout(layout: "flow" | "comment" | "indent"): string {
  const [head = "", rest = ""] = REVIEW_LOCKFILE.split("packages:\n");
  const [packages = "", snapshots = ""] = rest.split("snapshots:\n");
  let changed = packages;
  if (layout === "flow") {
    changed = packages.replace(
      `  '@types/node@26.6.6':\n    resolution: {integrity: ${TYPES_NODE_INTEGRITY}}`,
      `  '@types/node@26.6.6': {resolution: {integrity: ${TYPES_NODE_INTEGRITY}}}`,
    );
  } else if (layout === "comment") {
    changed = packages.replace("  '@types/node@26.6.6':\n", "  '@types/node@26.6.6': # types\n");
  } else {
    changed = packages.replaceAll(/^(?= +\S)/gm, " ");
  }
  expect(changed).not.toBe(packages);
  return `${head}packages:\n${changed}snapshots:\n${snapshots}`;
}

/** The registry as the review saw it, publishing the review lockfile's integrity. */
const REVIEW_REGISTRY: Registry = {
  "@types/node": () =>
    Response.json(
      registryDocument(
        "@types/node",
        { "26.6.6": "2026-10-28T18:36:00.000Z" },
        { "26.6.6": { integrity: TYPES_NODE_INTEGRITY } },
      ),
    ),
  "undici-types": () =>
    Response.json(
      registryDocument(
        "undici-types",
        { "8.9.0": "2026-06-01T00:00:00.000Z" },
        { "8.9.0": { integrity: UNDICI_TYPES_INTEGRITY } },
      ),
    ),
};

const registryEntry = (key: string) =>
  `  ${key}:\n    resolution: {integrity: sha512-AAAA}\n    engines: {node: '>=14.17'}`;

/**
 * A registry document as the npm registry serves it: publish times and each
 * version's dist, with the integrity registryEntry locks unless `dists` says otherwise.
 */
function registryDocument(
  name: string,
  times: Record<string, string>,
  dists: Record<string, unknown> = {},
) {
  const versions = Object.fromEntries(
    Object.keys(times).map((version) => [
      version,
      {
        name,
        version,
        dist: dists[version] ?? { integrity: "sha512-AAAA" },
      },
    ]),
  );
  return { name, time: { created: ago(1000), modified: ago(1), ...times }, versions };
}

/** Registry documents by package name; a function builds the response itself. */
type Registry = Record<string, Record<string, string> | (() => Response | Promise<Response>)>;

function mockFetch(registry: Registry) {
  const urls: string[] = [];
  const fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    urls.push(url);
    const name = decodeURIComponent(url.slice("https://registry.npmjs.org/".length));
    const doc = registry[name];
    if (doc === undefined) return new Response('{"error":"Not found"}', { status: 404 });
    if (typeof doc === "function") return doc();
    return Response.json(registryDocument(name, doc));
  }) as typeof globalThis.fetch;
  return { fetch, urls };
}

const options = (fetch: typeof globalThis.fetch, extra: Partial<CheckOptions> = {}) => ({
  fetch,
  now: NOW,
  exceptions: [],
  retryDelayMs: 0,
  ...extra,
});

describe("parseLockfile", () => {
  it("reads every package of the packages section, with its registry state", () => {
    const text = lockfile([
      registryEntry("'@types/node@22.20.5'"),
      registryEntry("typescript@6.0.3"),
      "  tar-dep@https://example.com/tar-dep-1.0.0.tgz:\n    resolution: {tarball: https://example.com/tar-dep-1.0.0.tgz}\n    version: 1.0.0",
      "  git-dep@git+https://github.com/x/git-dep.git#0123abc:\n    resolution: {commit: 0123abc, repo: https://github.com/x/git-dep.git, type: git}\n    version: 1.0.0",
      "  dir-dep@file:../dir-dep:\n    resolution: {directory: ../dir-dep, type: directory}\n    version: 1.0.0",
      "  '@jsr/std__fs@1.0.0':\n    resolution: {integrity: sha512-AAAA, tarball: https://npm.jsr.io/~/11/@jsr/std__fs/1.0.0.tgz}",
    ]);
    expect(parseLockfile(text)).toEqual([
      {
        key: "@types/node@22.20.5",
        name: "@types/node",
        version: "22.20.5",
        registry: true,
        integrity: "sha512-AAAA",
      },
      {
        key: "typescript@6.0.3",
        name: "typescript",
        version: "6.0.3",
        registry: true,
        integrity: "sha512-AAAA",
      },
      {
        key: "tar-dep@https://example.com/tar-dep-1.0.0.tgz",
        name: "tar-dep",
        version: "https://example.com/tar-dep-1.0.0.tgz",
        registry: false,
        resolution: { tarball: "https://example.com/tar-dep-1.0.0.tgz" },
      },
      {
        key: "git-dep@git+https://github.com/x/git-dep.git#0123abc",
        name: "git-dep",
        version: "git+https://github.com/x/git-dep.git#0123abc",
        registry: false,
        resolution: { commit: "0123abc", repo: "https://github.com/x/git-dep.git", type: "git" },
      },
      {
        key: "dir-dep@file:../dir-dep",
        name: "dir-dep",
        version: "file:../dir-dep",
        registry: false,
        resolution: { directory: "../dir-dep", type: "directory" },
      },
      {
        key: "@jsr/std__fs@1.0.0",
        name: "@jsr/std__fs",
        version: "1.0.0",
        registry: false,
        resolution: {
          integrity: "sha512-AAAA",
          tarball: "https://npm.jsr.io/~/11/@jsr/std__fs/1.0.0.tgz",
        },
      },
    ]);
  });

  it("accepts a tarball on the npm registry itself", () => {
    const text = lockfile([
      "  left-pad@1.3.0:\n    resolution: {integrity: sha512-AAAA, tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz}",
      "  '@scope/pkg@1.0.0':\n    resolution: {integrity: sha512-AAAA, tarball: https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz}",
      "  other@1.0.0:\n    resolution: {integrity: sha512-AAAA, tarball: https://registry.npmjs.org/evil/-/evil-6.6.6.tgz}",
    ]);
    expect(parseLockfile(text)).toMatchObject([
      { key: "left-pad@1.3.0", registry: true },
      { key: "@scope/pkg@1.0.0", registry: true },
      { key: "other@1.0.0", registry: false },
    ]);
  });

  it("refuses lockfile formats it does not know", () => {
    expect(() => parseLockfile("lockfileVersion: '6.0'\n")).toThrow(/lockfileVersion/);
    expect(() => parseLockfile("importers: {}\n")).toThrow(/lockfileVersion/);
  });

  it("refuses an entry without a resolution", () => {
    expect(() =>
      parseLockfile(lockfile(["  typescript@6.0.3:\n    engines: {node: '>=14'}"])),
    ).toThrow(/typescript@6\.0\.3/);
  });

  it("reads the repository's own lockfile", () => {
    const text = readFileSync(join(REPO_ROOT, "pnpm-lock.yaml"), "utf8");
    const packages = parseLockfile(text);
    expect(packages.length).toBeGreaterThan(100);
    expect(packages.filter((p) => !p.registry)).toEqual([]);
    expect(packages.map((p) => p.key)).toContain("typescript@6.0.3");
  });
});

describe("R6-03: the lockfile is read strictly", () => {
  const refuses = (text: string, message: RegExp) => {
    expect(() => parseLockfile(text)).toThrow(LockfileError);
    expect(() => parseLockfile(text)).toThrow(message);
  };
  /** The review's lockfile with `replace` applied once; the replaced text must be there. */
  const edited = (from: string, to: string) => {
    expect(REVIEW_LOCKFILE).toContain(from);
    return REVIEW_LOCKFILE.replace(from, to);
  };

  it("R6-03: reads the layout pnpm writes and fails the young version", async () => {
    expect(parseLockfile(REVIEW_LOCKFILE).map((p) => p.key)).toEqual([
      "@types/node@26.6.6",
      "undici-types@8.9.0",
    ]);
    const { fetch } = mockFetch(REVIEW_REGISTRY);
    const result = await checkReleaseAge(REVIEW_LOCKFILE, options(fetch));
    expect(result.failures).toMatchObject([{ package: "@types/node@26.6.6", reason: "too_young" }]);
  });

  it("R6-03: refuses an entry written on one flow-style line", () => {
    refuses(reviewLayout("flow"), /^pnpm-lock\.yaml line 17: .*one line/);
  });

  it("R6-03: refuses a comment after a key", () => {
    refuses(reviewLayout("comment"), /^pnpm-lock\.yaml line 17: a comment/);
  });

  it("R6-03: refuses a packages section indented by 3 spaces", () => {
    refuses(reviewLayout("indent"), /^pnpm-lock\.yaml line 17: .*indent 2.*indent 3/);
  });

  it("R6-03: main exits 1 for each of the review's layouts", async () => {
    for (const layout of ["flow", "comment", "indent"] as const) {
      const err: string[] = [];
      const { fetch } = mockFetch(REVIEW_REGISTRY);
      const code = await main({
        lockfile: reviewLayout(layout),
        packageJson: manifest({ packageManager: "pnpm@10.28.0" }),
        fetch,
        now: NOW,
        exceptions: [],
        log: () => {},
        error: (line) => err.push(line),
      });
      expect(code).toBe(1);
      expect(err).toEqual([expect.stringMatching(/^error: pnpm-lock\.yaml line 17: /)]);
    }
  });

  it("R6-03: refuses comment lines, which would end a section for a line reader", () => {
    const entry = "\n  undici-types@8.9.0:\n";
    refuses(edited(entry, `\n# note\n${entry.slice(1)}`), /line 20: .*top-level key/);
    refuses(edited(entry, `\n  # note\n${entry.slice(1)}`), /line 20: a comment/);
    refuses(
      edited(
        "    resolution: {integrity: sha512-K",
        "    # note\n    resolution: {integrity: sha512-K",
      ),
      /line 21: a comment/,
    );
    refuses(
      edited(`${UNDICI_TYPES_INTEGRITY}}`, `${UNDICI_TYPES_INTEGRITY}} # note`),
      /line 21: a comment/,
    );
  });

  it("R6-03: refuses top-level keys it would read differently from YAML", () => {
    refuses(edited("\npackages:\n", "\n'packages':\n"), /line 15: .*top-level key/);
    refuses(edited("\npackages:\n", "\npackages :\n"), /line 15: .*top-level key/);
    refuses(edited("\npackages:\n", "\npackages: # all\n"), /line 15: a comment/);
    refuses(
      edited("\nsnapshots:\n", "\npackages:\n\nsnapshots:\n"),
      /line 23: packages appears twice/,
    );
    refuses(`---\n${REVIEW_LOCKFILE}`, /line 1: .*start with lockfileVersion/);
    refuses(edited("\npackages:\n", "\n---\npackages:\n"), /line 15: .*top-level key/);
    refuses(edited("\npackages:\n", "\npackages: {}\n"), /line 15: packages on one line/);
    refuses(`settings: {}\n${REVIEW_LOCKFILE}`, /line 1: .*start with lockfileVersion/);
    refuses(`  ${REVIEW_LOCKFILE}`, /line 1: .*start with lockfileVersion/);
    refuses(
      edited("\npackages:\n\n", "\npackages:\n<<<<<<< HEAD\n"),
      /line 16: expected a top-level key/,
    );
  });

  it("R6-03: refuses values that continue on the next line", () => {
    const continued = (value: string) =>
      edited(
        `  undici-types@8.9.0:\n    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}\n`,
        `  undici-types@8.9.0:\n    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}\n    deprecated: ${value}\n  young@1.0.0:\n    resolution: {integrity: sha512-AAAA}\n    x'\n`,
      );
    refuses(continued("'starts"), /line 22: a quoted value that continues/);
    refuses(continued('"starts'), /line 22: a quoted value that continues/);
    refuses(continued("{a: b,"), /line 22: a flow collection that continues/);
    refuses(continued("[a,"), /line 22: a flow collection that continues/);
  });

  it("R6-03: refuses a value that continues on the next line in a section it does not read", () => {
    // YAML would read packages: as part of the settings value, and pnpm would
    // then take the resolution of the snapshot itself.
    const text = edited("  excludeLinksFromLockfile: false\n", "  excludeLinksFromLockfile: 'x\n")
      .replace(
        `    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}\n`,
        `    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}\n    engines:\n      y'\n`,
      )
      .replace(
        "  undici-types@8.9.0: {}\n",
        "  undici-types@8.9.0:\n    resolution: {integrity: sha512-AAAA, tarball: https://evil.example/u.tgz}\n",
      );
    refuses(text, /line 5: a quoted value that continues/);
  });

  it("R6-03: refuses anchors, aliases, tags and merge keys", () => {
    const resolution = `    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}`;
    refuses(edited(resolution, `    resolution: &r {integrity: sha512-AAAA}`), /line 21: .*anchor/);
    refuses(edited(resolution, "    resolution: *r"), /line 21: .*anchor/);
    refuses(
      edited(resolution, `    resolution: !!map {integrity: sha512-AAAA}`),
      /line 21: .*anchor/,
    );
    refuses(
      edited(resolution, `${resolution}\n    <<: {deprecated: x}`),
      /line 22: expected a field/,
    );
    refuses(edited("\n  undici-types@8.9.0:\n", "\n  <<:\n"), /line 20: .*key/);
    refuses(
      edited("\n  undici-types@8.9.0:\n", "\n  ? undici-types@8.9.0\n"),
      /line 20: .*explicit key/,
    );
  });

  it("R6-03: refuses an entry that is not a block mapping under its key", () => {
    refuses(
      edited("  undici-types@8.9.0:\n    resolution", "  undici-types@8.9.0:\n     resolution"),
      /line 21: .*indent 5/,
    );
    refuses(
      edited("  undici-types@8.9.0:\n    resolution", "  undici-types@8.9.0:\n      resolution"),
      /line 21: .*indent 6/,
    );
    refuses(
      edited(
        `    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}`,
        "    resolution:\n      integrity: sha512-AAAA",
      ),
      /line 21: the resolution of undici-types@8\.9\.0 is not a one-line flow map/,
    );
    refuses(
      edited(
        `    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}`,
        "    resolution: {integrity: sha512-AAAA}\n    resolution: {integrity: sha512-BBBB}",
      ),
      /line 22: undici-types@8\.9\.0 has resolution twice/,
    );
    refuses(
      edited(
        "\n  undici-types@8.9.0:\n    resolution",
        "\n  undici-types@8.9.0: {}\n    resolution",
      ),
      /line 20: .*no resolution|line 21/,
    );
  });

  it("R6-03: breaks lines at a lone CR, as YAML does", async () => {
    const text = edited(
      "  undici-types@8.9.0:\n",
      "  young@1.0.0:\r    resolution: {integrity: sha512-AAAA}\n\n  undici-types@8.9.0:\n",
    ).replace("  undici-types@8.9.0: {}\n", "  undici-types@8.9.0: {}\n\n  young@1.0.0: {}\n");
    expect(parseLockfile(text).map((p) => p.key)).toContain("young@1.0.0");
  });

  it("R6-03: reads block scalars, sequences and quoted values as pnpm writes them", () => {
    const text = edited(
      `    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}\n`,
      [
        `    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}, tarball: 'https://registry.npmjs.org/undici-types/-/undici-types-8.9.0.tgz'}`,
        "    engines: {node: '>=14.17', npm: ^9 || >=10}",
        "    cpu: [x64, arm64]",
        "    deprecated: |-",
        "      Don't use this; see #12:",
        "        '  {unbalanced [",
        "",
        "      undici-types@9.0.0: still the message",
        "    hasBin: true",
        "",
      ].join("\n"),
    ).replace(
      "    dependencies:\n      undici-types: 8.9.0\n",
      "    dependencies:\n      undici-types: 8.9.0\n    transitivePeerDependencies:\n      - supports-color\n      - '@types/react'\n",
    );
    expect(parseLockfile(text)).toEqual([
      expect.objectContaining({ key: "@types/node@26.6.6", registry: true }),
      expect.objectContaining({ key: "undici-types@8.9.0", registry: true }),
    ]);
  });

  it("R6-03: reads a resolution as YAML does, not split on ', '", () => {
    const text = edited(
      `    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY}}`,
      `    resolution: {integrity: ${UNDICI_TYPES_INTEGRITY},tarball: https://evil.example/undici-types-8.9.0.tgz}`,
    );
    expect(parseLockfile(text)).toMatchObject([
      { key: "@types/node@26.6.6", registry: true },
      { key: "undici-types@8.9.0", registry: false },
    ]);
  });

  it("R6-03: refuses a snapshot without an entry in packages", () => {
    // pnpm merges each snapshot with its packages entry; without one it would
    // take the snapshot's own fields, a resolution among them.
    const text = edited(
      "  undici-types@8.9.0: {}\n",
      "  undici-types@8.9.0: {}\n\n  young@1.0.0(react@19.0.0):\n    resolution: {tarball: https://evil.example/young.tgz}\n",
    );
    refuses(text, /line 31: snapshot young@1\.0\.0\(react@19\.0\.0\) has no entry in packages/);
  });

  it("R6-03: matches snapshots with peer and patch suffixes to their packages entry", () => {
    const text = edited(
      "  undici-types@8.9.0: {}\n",
      "  undici-types@8.9.0(patch_hash=abc123)(react@19.0.0(scheduler@0.25.0)): {}\n",
    );
    expect(parseLockfile(text)).toHaveLength(2);
  });

  it("R6-03: refuses an importer version without an entry in packages", () => {
    refuses(
      edited("        version: 26.6.6\n", "        version: 26.6.7\n"),
      /line 13: .*@types\/node@26\.6\.7, which has no entry in packages/,
    );
    refuses(
      edited("        specifier: 26.6.6\n        version: 26.6.6\n", "        specifier: 26.6.6\n"),
      /line 11: dependency @types\/node of importer \. has no version/,
    );
    refuses(
      edited(
        "    dependencies:\n      '@types/node':\n        specifier: 26.6.6\n        version: 26.6.6\n",
        "    dependencies: {'@types/node': {specifier: 26.6.6, version: 26.6.7}}\n",
      ),
      /line 10: .*dependencies of importer \. as a block/,
    );
  });

  it("R6-03: resolves importer versions as pnpm does: links, aliases and peer suffixes", () => {
    const text = edited(
      "        version: 26.6.6\n",
      [
        "        version: 26.6.6(undici-types@8.9.0)",
        "      types-alias:",
        "        specifier: npm:undici-types@8.9.0",
        "        version: undici-types@8.9.0",
        "      '@virga/graph':",
        "        specifier: workspace:*",
        "        version: link:../../packages/graph",
        "",
      ].join("\n"),
    );
    expect(parseLockfile(text)).toHaveLength(2);
  });
});

describe("R6-03: the locked integrity is the one the registry publishes", () => {
  it("R6-03: a locked integrity that is not the registry's fails, even with an exception", async () => {
    const text = lockfile([registryEntry("a@1.0.0")]);
    const { fetch } = mockFetch({
      a: () =>
        Response.json(
          registryDocument("a", { "1.0.0": ago(30) }, { "1.0.0": { integrity: "sha512-BBBB" } }),
        ),
    });
    const result = await checkReleaseAge(
      text,
      options(fetch, {
        exceptions: [{ package: "a@1.0.0", accepts: "too_young", reason: "not for this" }],
      }),
    );
    expect(result.failures).toEqual([
      {
        package: "a@1.0.0",
        reason: "mismatch",
        detail:
          "the lockfile's integrity is not the sha512 digest the registry publishes for this version, so the bytes installed would not be the version checked",
      },
    ]);
    expect(result.excepted).toEqual([]);
    expect(result.unusedExceptions).toEqual([]);
  });

  it("R6-03: a version field that makes pnpm fetch a younger version fails", async () => {
    // pnpm 10.28.0 takes the version for the tarball URL from a version field
    // of the entry (nameVerFromPkgSnapshot), not from the key.
    const young = `sha512-${"C".repeat(86)}==`;
    const text = lockfile([
      `  typescript@6.0.3:\n    resolution: {integrity: ${young}}\n    version: 6.1.0`,
    ]);
    const { fetch } = mockFetch({
      typescript: () =>
        Response.json(
          registryDocument(
            "typescript",
            { "6.0.3": ago(40), "6.1.0": ago(1) },
            { "6.1.0": { integrity: young } },
          ),
        ),
    });
    const result = await checkReleaseAge(text, options(fetch));
    expect(result.failures).toMatchObject([{ package: "typescript@6.0.3", reason: "mismatch" }]);
  });

  it("R6-03: a version without a digest to compare is not verified", async () => {
    const text = lockfile([registryEntry("a@1.0.0"), registryEntry("b@1.0.0")]);
    const shasum = "0102030405060708090a0b0c0d0e0f1011121314";
    const { fetch } = mockFetch({
      a: () => Response.json(registryDocument("a", { "1.0.0": ago(30) }, { "1.0.0": { shasum } })),
      b: () => Response.json({ name: "b", time: { "1.0.0": ago(30) }, versions: {} }),
    });
    const result = await checkReleaseAge(text, options(fetch));
    const detail = "the registry publishes no sha512 digest for this version to compare";
    expect(result.failures).toEqual([
      { package: "a@1.0.0", reason: "unverified", detail },
      { package: "b@1.0.0", reason: "unverified", detail },
    ]);
  });

  it("R6-03: compares a sha1 integrity with the registry's shasum", async () => {
    const text = lockfile([
      "  old@1.0.0:\n    resolution: {integrity: sha1-AQIDBAUGBwgJCgsMDQ4PEBESExQ=}",
    ]);
    const shasum = "0102030405060708090A0B0C0D0E0F1011121314";
    const { fetch } = mockFetch({
      old: () =>
        Response.json(registryDocument("old", { "1.0.0": ago(3000) }, { "1.0.0": { shasum } })),
    });
    const result = await checkReleaseAge(text, options(fetch));
    expect(result.failures).toEqual([]);
  });

  it("TM-32: a sha1 integrity equal to dist.shasum fails when the registry publishes sha512", async () => {
    const text = lockfile([
      "  old@1.0.0:\n    resolution: {integrity: sha1-AQIDBAUGBwgJCgsMDQ4PEBESExQ=}",
    ]);
    const shasum = "0102030405060708090a0b0c0d0e0f1011121314";
    const integrity = `sha512-${"A".repeat(86)}==`;
    const { fetch } = mockFetch({
      old: () =>
        Response.json(
          registryDocument("old", { "1.0.0": ago(30) }, { "1.0.0": { integrity, shasum } }),
        ),
    });
    const result = await checkReleaseAge(
      text,
      options(fetch, {
        exceptions: [{ package: "old@1.0.0", accepts: "too_young", reason: "not for this" }],
      }),
    );
    expect(result.failures).toEqual([
      {
        package: "old@1.0.0",
        reason: "mismatch",
        detail:
          "the lockfile's integrity is sha1, but the registry publishes a sha512 digest for this version; pnpm verifies only the algorithm the lockfile names, so lock the sha512 integrity",
      },
    ]);
    expect(result.excepted).toEqual([]);
  });

  it("TM-32: requires the strongest algorithm in dist.integrity", async () => {
    const sha256 = `sha256-${"B".repeat(43)}=`;
    const sha384 = `sha384-${"C".repeat(64)}`;
    const sha512 = `sha512-${"D".repeat(86)}==`;
    const sha1 = "sha1-AQIDBAUGBwgJCgsMDQ4PEBESExQ=";
    const text = lockfile([
      `  a@1.0.0:\n    resolution: {integrity: ${sha256}}`,
      `  b@1.0.0:\n    resolution: {integrity: ${sha384}}`,
      `  c@1.0.0:\n    resolution: {integrity: ${sha512}}`,
      `  d@1.0.0:\n    resolution: {integrity: ${sha384}}`,
    ]);
    const published = (name: string, integrity: string) => () =>
      Response.json(registryDocument(name, { "1.0.0": ago(30) }, { "1.0.0": { integrity } }));
    const { fetch } = mockFetch({
      a: published("a", `${sha256} ${sha512}`),
      b: published("b", `${sha512} ${sha384}`),
      c: published("c", `${sha1} ${sha512}`),
      d: published("d", `${sha1} ${sha384}`),
    });
    const result = await checkReleaseAge(text, options(fetch));
    expect(result.failures.map((f) => [f.package, f.reason, f.detail])).toEqual([
      [
        "a@1.0.0",
        "mismatch",
        expect.stringMatching(
          /^the lockfile's integrity is sha256, but the registry publishes a sha512 digest/,
        ),
      ],
      [
        "b@1.0.0",
        "mismatch",
        expect.stringMatching(
          /^the lockfile's integrity is sha384, but the registry publishes a sha512 digest/,
        ),
      ],
    ]);
  });
});

describe("checkReleaseAge", () => {
  it("R4-07: fails on a locked version published two days ago", async () => {
    // The review's scenario: @types/node 26.6.6 in the lockfile, published 2026-10-28.
    const text = lockfile([
      registryEntry("'@types/node@26.6.6'"),
      registryEntry("typescript@6.0.3"),
    ]);
    const { fetch } = mockFetch({
      "@types/node": { "26.6.6": "2026-10-28T18:36:00.000Z" },
      typescript: { "6.0.3": ago(40) },
    });
    const result = await checkReleaseAge(text, options(fetch));
    expect(result.failures).toEqual([
      {
        package: "@types/node@26.6.6",
        reason: "too_young",
        detail: "published 2026-10-28T18:36:00.000Z, 1.7 days ago",
      },
    ]);
    expect(result.checked).toBe(2);
  });

  it("R4-07: the limit is 14 days to the millisecond", async () => {
    const text = lockfile([registryEntry("a@1.0.0"), registryEntry("a@1.0.1")]);
    const { fetch } = mockFetch({
      a: {
        "1.0.0": ago(14),
        "1.0.1": new Date(NOW.getTime() - 14 * DAY + 1).toISOString(),
      },
    });
    const result = await checkReleaseAge(text, options(fetch));
    expect(result.failures.map((f) => [f.package, f.reason])).toEqual([["a@1.0.1", "too_young"]]);
  });

  it("R4-07: a publish time in the future fails", async () => {
    const text = lockfile([registryEntry("a@1.0.0")]);
    const { fetch } = mockFetch({ a: { "1.0.0": ago(-1) } });
    const result = await checkReleaseAge(text, options(fetch));
    expect(result.failures).toMatchObject([{ package: "a@1.0.0", reason: "too_young" }]);
  });

  it("passes old versions and fetches each name once", async () => {
    const text = lockfile([
      registryEntry("'@scope/pkg@1.0.0'"),
      registryEntry("'@scope/pkg@2.0.0'"),
      registryEntry("plain@0.1.0"),
    ]);
    const { fetch, urls } = mockFetch({
      "@scope/pkg": { "1.0.0": ago(400), "2.0.0": ago(15) },
      plain: { "0.1.0": ago(3000) },
    });
    const result = await checkReleaseAge(text, options(fetch));
    expect(result).toMatchObject({ checked: 3, failures: [], excepted: [] });
    expect(urls.sort()).toEqual([
      "https://registry.npmjs.org/@scope%2Fpkg",
      "https://registry.npmjs.org/plain",
    ]);
  });

  it("accepts a young version on the exception list and reports it", async () => {
    const text = lockfile([registryEntry("a@1.0.0"), registryEntry("b@1.0.0")]);
    const { fetch } = mockFetch({ a: { "1.0.0": ago(2) }, b: { "1.0.0": ago(30) } });
    const result = await checkReleaseAge(
      text,
      options(fetch, {
        exceptions: [
          { package: "a@1.0.0", accepts: "too_young", reason: "security fix" },
          { package: "b@1.0.0", accepts: "too_young", reason: "no longer needed" },
          { package: "c@1.0.0", accepts: "too_young", reason: "gone from the lockfile" },
        ],
      }),
    );
    expect(result.failures).toEqual([]);
    expect(result.excepted).toEqual([
      { package: "a@1.0.0", detail: "published 2026-10-28T12:00:00.000Z, 2.0 days ago" },
    ]);
    expect(result.unusedExceptions).toEqual(["b@1.0.0", "c@1.0.0"]);
  });

  it("an exception names an exact version", async () => {
    const text = lockfile([registryEntry("a@1.0.1")]);
    const { fetch } = mockFetch({ a: { "1.0.1": ago(2) } });
    const result = await checkReleaseAge(
      text,
      options(fetch, {
        exceptions: [{ package: "a@1.0.0", accepts: "too_young", reason: "older fix" }],
      }),
    );
    expect(result.failures).toMatchObject([{ package: "a@1.0.1", reason: "too_young" }]);
  });

  it("R4-07: a version it cannot check fails, unless it is on the exception list", async () => {
    const text = lockfile([
      "  tar-dep@https://example.com/tar-dep-1.0.0.tgz:\n    resolution: {tarball: https://example.com/tar-dep-1.0.0.tgz}\n    version: 1.0.0",
      "  dir-dep@file:../dir-dep:\n    resolution: {directory: ../dir-dep, type: directory}\n    version: 1.0.0",
    ]);
    const { fetch, urls } = mockFetch({});
    const result = await checkReleaseAge(
      text,
      options(fetch, {
        exceptions: [
          {
            package: "dir-dep@file:../dir-dep",
            accepts: "not_registry",
            resolution: { directory: "../dir-dep", type: "directory" },
            reason: "local",
          },
        ],
      }),
    );
    expect(result.failures).toEqual([
      {
        package: "tar-dep@https://example.com/tar-dep-1.0.0.tgz",
        reason: "not_registry",
        detail: "not resolved from the npm registry, so its release age is unknown",
      },
    ]);
    expect(result.excepted.map((e) => e.package)).toEqual(["dir-dep@file:../dir-dep"]);
    expect(urls).toEqual([]);
  });

  it("R4-07: a missing publish time or registry error is a failure, not a pass", async () => {
    const text = lockfile([
      registryEntry("no-time@1.0.0"),
      registryEntry("bad-time@1.0.0"),
      registryEntry("missing@1.0.0"),
      registryEntry("not-json@1.0.0"),
      registryEntry("no-time-map@1.0.0"),
      registryEntry("forbidden@1.0.0"),
    ]);
    const { fetch } = mockFetch({
      "no-time": { "0.9.0": ago(100) },
      "bad-time": { "1.0.0": "yesterday" },
      "not-json": () => new Response("<html>", { status: 200 }),
      "no-time-map": () => Response.json({ name: "no-time-map" }),
      forbidden: () => new Response("denied", { status: 403 }),
    });
    const result = await checkReleaseAge(text, options(fetch));
    expect(result.failures.map((f) => [f.package, f.reason, f.detail])).toEqual([
      ["bad-time@1.0.0", "unverified", "the registry has no valid publish time for this version"],
      ["forbidden@1.0.0", "unverified", "registry responded 403"],
      ["missing@1.0.0", "unverified", "not found in the registry"],
      ["no-time-map@1.0.0", "unverified", "the registry document has no publish times"],
      ["no-time@1.0.0", "unverified", "the registry has no valid publish time for this version"],
      ["not-json@1.0.0", "unverified", "the registry response is not JSON"],
    ]);
  });

  it("retries a transient registry error", async () => {
    const text = lockfile([registryEntry("a@1.0.0")]);
    let calls = 0;
    const { fetch } = mockFetch({
      a: () => {
        calls += 1;
        if (calls === 1) return new Response("busy", { status: 503 });
        if (calls === 2) throw new TypeError("fetch failed");
        return Response.json(registryDocument("a", { "1.0.0": ago(30) }));
      },
    });
    const result = await checkReleaseAge(text, options(fetch, { attempts: 3 }));
    expect(result.failures).toEqual([]);
    expect(calls).toBe(3);
  });

  it("gives up after the last attempt", async () => {
    const text = lockfile([registryEntry("a@1.0.0")]);
    let calls = 0;
    const { fetch } = mockFetch({
      a: () => {
        calls += 1;
        return new Response("busy", { status: 503 });
      },
    });
    const result = await checkReleaseAge(text, options(fetch, { attempts: 2 }));
    expect(result.failures).toMatchObject([{ package: "a@1.0.0", reason: "unverified" }]);
    expect(calls).toBe(2);
  });

  it("aborts a request that takes longer than the timeout", async () => {
    const text = lockfile([registryEntry("slow@1.0.0")]);
    const fetch = ((_input: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      })) as typeof globalThis.fetch;
    const result = await checkReleaseAge(text, options(fetch, { timeoutMs: 20, attempts: 1 }));
    expect(result.failures).toEqual([
      { package: "slow@1.0.0", reason: "unverified", detail: "registry request timed out" },
    ]);
  });

  it("keeps at most `concurrency` requests in flight", async () => {
    const names = Array.from({ length: 12 }, (_, i) => `p${i}`);
    const text = lockfile(names.map((name) => registryEntry(`${name}@1.0.0`)));
    let inFlight = 0;
    let peak = 0;
    const fetch = (async (input: string | URL | Request) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight -= 1;
      const name = String(input).split("/").pop();
      return Response.json(registryDocument(String(name), { "1.0.0": ago(30) }));
    }) as typeof globalThis.fetch;
    const result = await checkReleaseAge(text, options(fetch, { concurrency: 3 }));
    expect(result).toMatchObject({ checked: 12, failures: [] });
    expect(peak).toBe(3);
  });
});

describe("R8-03: an exception accepts only the failure and the resolution it names", () => {
  /** The review's exception: a@1.0.0, published two days ago, as a security fix. */
  const YOUNG_A: Exception = { package: "a@1.0.0", accepts: "too_young", reason: "security fix" };
  /** a 1.0.0 two days old and 1.0.1 one day old, each with the sha512 digest registryEntry locks. */
  const REGISTRY_A: Registry = { a: { "1.0.0": ago(2), "1.0.1": ago(1) } };
  const withYoungA = async (entry: string) => {
    const { fetch } = mockFetch(REGISTRY_A);
    return checkReleaseAge(lockfile([entry]), options(fetch, { exceptions: [YOUNG_A] }));
  };

  it("R8-03: still accepts a@1.0.0 from the registry with the registry's integrity", async () => {
    const result = await withYoungA(registryEntry("a@1.0.0"));
    expect(result.failures).toEqual([]);
    expect(result.excepted).toEqual([
      { package: "a@1.0.0", detail: "published 2026-10-28T12:00:00.000Z, 2.0 days ago" },
    ]);
  });

  it("R8-03: an exception for a@1.0.0 does not accept a foreign tarball", async () => {
    const result = await withYoungA(
      "  a@1.0.0:\n    resolution: {integrity: sha512-AAAA, tarball: https://attacker.invalid/a-1.0.0.tgz}",
    );
    expect(result.failures).toMatchObject([{ package: "a@1.0.0", reason: "not_registry" }]);
    expect(result.excepted).toEqual([]);
  });

  it("R8-03: an exception for a@1.0.0 does not accept a tarball without integrity", async () => {
    const result = await withYoungA(
      "  a@1.0.0:\n    resolution: {tarball: https://registry.npmjs.org/a/-/a-1.0.0.tgz}",
    );
    expect(result.failures).toMatchObject([{ package: "a@1.0.0", reason: "not_registry" }]);
    expect(result.excepted).toEqual([]);
  });

  it("R8-03: an exception for a@1.0.0 does not accept a sha384 integrity with version: 1.0.1", async () => {
    const result = await withYoungA(
      `  a@1.0.0:\n    resolution: {integrity: sha384-${"B".repeat(64)}}\n    version: 1.0.1`,
    );
    expect(result.failures).toEqual([
      {
        package: "a@1.0.0",
        reason: "unverified",
        detail: "the registry publishes no sha384 digest for this version to compare",
      },
    ]);
    expect(result.excepted).toEqual([]);
  });

  it("R8-03: a non-registry exception accepts only the exact resolution it names", async () => {
    const TAR = "tar-dep@https://example.com/tar-dep-1.0.0.tgz";
    const GIT = "git-dep@git+https://github.com/x/git-dep.git#0123abc";
    const DIR = "dir-dep@file:../dir-dep";
    const text = lockfile([
      `  ${TAR}:\n    resolution: {integrity: sha512-AAAA, tarball: https://example.com/tar-dep-1.0.0.tgz}\n    version: 1.0.0`,
      `  ${GIT}:\n    resolution: {commit: 0123abc, repo: https://github.com/x/git-dep.git, type: git}\n    version: 1.0.0`,
      `  ${DIR}:\n    resolution: {directory: ../dir-dep, type: directory}\n    version: 1.0.0`,
    ]);
    const exception = (key: string, resolution: Record<string, string>): Exception => ({
      package: key,
      accepts: "not_registry",
      resolution,
      reason: "a fork with the fix",
    });
    const check = (exceptions: Exception[]) =>
      checkReleaseAge(text, options(mockFetch({}).fetch, { exceptions }));
    const repo = "https://github.com/x/git-dep.git";

    const exact = await check([
      exception(TAR, {
        tarball: "https://example.com/tar-dep-1.0.0.tgz",
        integrity: "sha512-AAAA",
      }),
      exception(GIT, { commit: "0123abc", repo, type: "git" }),
      exception(DIR, { directory: "../dir-dep", type: "directory" }),
    ]);
    expect(exact.failures).toEqual([]);
    expect(exact.excepted.map((e) => e.package)).toEqual([DIR, GIT, TAR]);

    const other = await check([
      exception(TAR, {
        tarball: "https://example.com/tar-dep-1.0.0.tgz",
        integrity: "sha512-BBBB",
      }),
      exception(TAR, {
        tarball: "https://example.com/tar-dep-1.0.1.tgz",
        integrity: "sha512-AAAA",
      }),
      exception(GIT, { commit: "4567def", repo, type: "git" }),
      exception(GIT, { commit: "0123abc", repo }),
      exception(DIR, { directory: "../other", type: "directory" }),
      exception(DIR, { directory: "../dir-dep", type: "directory", path: "x" }),
    ]);
    expect(other.failures.map((f) => [f.package, f.reason])).toEqual([
      [DIR, "not_registry"],
      [GIT, "not_registry"],
      [TAR, "not_registry"],
    ]);
    expect(other.excepted).toEqual([]);
  });

  it("R8-03: an exception accepts only the failure it names", async () => {
    const text = lockfile([
      registryEntry("a@1.0.0"),
      "  dir-dep@file:../dir-dep:\n    resolution: {directory: ../dir-dep, type: directory}\n    version: 1.0.0",
    ]);
    const { fetch } = mockFetch(REGISTRY_A);
    const result = await checkReleaseAge(
      text,
      options(fetch, {
        exceptions: [
          {
            package: "a@1.0.0",
            accepts: "not_registry",
            resolution: {
              integrity: "sha512-AAAA",
              tarball: "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            },
            reason: "the registry tarball",
          },
          { package: "dir-dep@file:../dir-dep", accepts: "too_young", reason: "local" },
        ],
      }),
    );
    expect(result.failures.map((f) => [f.package, f.reason])).toEqual([
      ["a@1.0.0", "too_young"],
      ["dir-dep@file:../dir-dep", "not_registry"],
    ]);
    expect(result.excepted).toEqual([]);
  });

  it("R8-03: refuses an exception it cannot apply, and never one for unverified or mismatch", async () => {
    const refuses = async (exception: unknown, message: RegExp) => {
      const { fetch } = mockFetch(REGISTRY_A);
      const check = checkReleaseAge(
        lockfile([registryEntry("a@1.0.0")]),
        options(fetch, { exceptions: [exception as Exception] }),
      );
      await expect(check).rejects.toThrow(message);
    };
    const NEVER =
      /^EXCEPTIONS: the exception for a@1\.0\.0 must accept "too_young" or "not_registry"; no exception accepts an integrity mismatch or a version the check could not verify$/;
    for (const accepts of ["unverified", "mismatch", undefined, "TOO_YOUNG"]) {
      await refuses({ package: "a@1.0.0", accepts, reason: "fix" }, NEVER);
    }
    await refuses(
      {
        ...YOUNG_A,
        resolution: { tarball: "https://example.com/a.tgz", integrity: "sha512-AAAA" },
      },
      /^EXCEPTIONS: the exception for a@1\.0\.0 accepts too_young, which applies to the registry's version only, and names a resolution/,
    );
    const foreign = (resolution: unknown) => ({
      package: "a@1.0.0",
      accepts: "not_registry",
      resolution,
      reason: "fork",
    });
    await refuses(
      foreign(undefined),
      /^EXCEPTIONS: the exception for a@1\.0\.0 names no resolution/,
    );
    await refuses(foreign("../a"), /^EXCEPTIONS: the exception for a@1\.0\.0 names no resolution/);
    await refuses(
      foreign({ tarball: "https://example.com/a.tgz" }),
      /^EXCEPTIONS: the exception for a@1\.0\.0 names a tarball without its integrity/,
    );
    await refuses(
      foreign({ type: "directory" }),
      /^EXCEPTIONS: the exception for a@1\.0\.0 names no tarball, commit or directory/,
    );
    await refuses(
      foreign({ directory: 1, type: "directory" }),
      /^EXCEPTIONS: the exception for a@1\.0\.0 names a resolution with a value that is not a string/,
    );
    await refuses(
      { ...YOUNG_A, reason: " " },
      /^EXCEPTIONS: the exception for a@1\.0\.0 gives no reason/,
    );
    await refuses(
      { ...YOUNG_A, package: "a" },
      /^EXCEPTIONS: the exception for "a" does not name an exact lockfile key/,
    );
    const { code, err } = await runMain(checkout(), {
      exceptions: [{ package: "a@1.0.0", accepts: "unverified" } as unknown as Exception],
    });
    expect(code).toBe(1);
    expect(err).toEqual([expect.stringMatching(/^error: EXCEPTIONS: the exception for a@1\.0\.0/)]);
  });
});

/** A package.json with the given fields. */
const manifest = (fields: Record<string, unknown>) =>
  JSON.stringify({ name: "virga", private: true, ...fields }, null, 2);

const PNPM_INTEGRITY =
  "sha512-Bd9x0UIfITmeBT/eVnzqNNRG+gLHZXFEG/wceVbpjjYwiJgtlARl/TRIDU2QoGaLwSNi+KqIAApk6D0LDke+SA==";
/** The corepack form of PNPM_INTEGRITY: `pnpm@10.28.0+sha512.<hex>`. */
const PNPM_SHA512 = Buffer.from(PNPM_INTEGRITY.slice("sha512-".length), "base64").toString("hex");

/** pnpm as the registry lists it: 10.28.0 from January, 10.34.9 from five days before NOW. */
const PNPM_REGISTRY: Registry = {
  pnpm: () =>
    Response.json(
      registryDocument(
        "pnpm",
        { "10.28.0": "2026-01-09T23:05:04.751Z", "10.34.9": "2026-10-25T17:54:00.000Z" },
        { "10.28.0": { integrity: PNPM_INTEGRITY } },
      ),
    ),
};

describe("R6-04: the pnpm version package.json pins", () => {
  const refuses = (text: string, message: RegExp) => {
    expect(() => parsePackageManager(text)).toThrow(PackageJsonError);
    expect(() => parsePackageManager(text)).toThrow(message);
  };
  const check = (packageJson: string, extra: Partial<CheckOptions> = {}) => {
    const { fetch } = mockFetch(PNPM_REGISTRY);
    return checkReleaseAge(lockfile([]), options(fetch, { packageJson, ...extra }));
  };

  it("R6-04: reads the exact version in packageManager, with or without a sha512 hash", () => {
    expect(parsePackageManager(manifest({ packageManager: "pnpm@10.28.0" }))).toEqual([
      { field: "packageManager", version: "10.28.0" },
    ]);
    expect(
      parsePackageManager(manifest({ packageManager: `pnpm@10.28.0+sha512.${PNPM_SHA512}` })),
    ).toEqual([{ field: "packageManager", version: "10.28.0", sha512: PNPM_SHA512 }]);
  });

  it("R6-04: reads devEngines.packageManager as one entry or a list", () => {
    const one = manifest({
      packageManager: "pnpm@10.28.0",
      devEngines: { packageManager: { name: "pnpm", version: "10.34.9", onFail: "download" } },
    });
    expect(parsePackageManager(one)).toEqual([
      { field: "packageManager", version: "10.28.0" },
      { field: "devEngines.packageManager", version: "10.34.9" },
    ]);
    const list = manifest({
      packageManager: "pnpm@10.28.0",
      devEngines: {
        runtime: { name: "node" },
        packageManager: [{ name: "pnpm", version: "10.28.0" }],
      },
    });
    expect(parsePackageManager(list)).toEqual([
      { field: "packageManager", version: "10.28.0" },
      { field: "devEngines.packageManager", version: "10.28.0" },
    ]);
  });

  it("R6-04: refuses a packageManager without an exact pnpm version, and says why", () => {
    refuses(manifest({}), /names no packageManager; CI \(pnpm\/action-setup\) and corepack/);
    refuses(manifest({ packageManager: 10 }), /names no packageManager/);
    refuses(manifest({ packageManager: "yarn@4.5.0" }), /"yarn@4\.5\.0", not pnpm/);
    for (const version of ["^10.28.0", "10", "latest", "10.28.x", "https://example.com/pnpm.tgz"]) {
      refuses(
        manifest({ packageManager: `pnpm@${version}` }),
        /packageManager names pnpm ".*", not an exact version, so the check cannot date the pnpm that runs/,
      );
    }
    refuses("{", /package\.json is not valid JSON/);
    refuses("[]", /package\.json is not a JSON object/);
  });

  it("R6-04: refuses a hash it cannot compare with the registry, and says why", () => {
    for (const hash of [
      "sha256.6b9dfa2f0b8bd45d7d0f5d18a2a59c95a1b6e3d1a2a8a9a87e6e0e1e9a0d7e3a",
      "sha224.abc",
      `sha512.${PNPM_SHA512.slice(2)}`,
      `sha512.${PNPM_SHA512}zz`,
    ]) {
      refuses(
        manifest({ packageManager: `pnpm@10.28.0+${hash}` }),
        /pins pnpm 10\.28\.0 with the hash ".*", which the check cannot compare: the registry publishes a sha512 digest for each version/,
      );
    }
  });

  it("R6-04: refuses devEngines.packageManager without an exact pnpm version", () => {
    const withEngines = (packageManager: unknown) =>
      manifest({ packageManager: "pnpm@10.28.0", devEngines: { packageManager } });
    refuses(
      withEngines({ name: "pnpm", version: "^10.0.0" }),
      /devEngines\.packageManager names pnpm "\^10\.0\.0", not an exact version/,
    );
    refuses(withEngines({ name: "pnpm" }), /devEngines\.packageManager gives no pnpm version/);
    refuses(
      withEngines({ name: "yarn", version: "4.5.0" }),
      /devEngines\.packageManager has an entry that does not name pnpm/,
    );
    refuses(
      withEngines([
        { name: "pnpm", version: "10.28.0" },
        { name: "npm", version: "11.0.0" },
      ]),
      /does not name pnpm/,
    );
    refuses(withEngines("pnpm@10.28.0"), /does not name pnpm/);
    refuses(
      manifest({ packageManager: "pnpm@10.28.0", devEngines: [] }),
      /devEngines is not an object/,
    );
  });

  it("R6-04: fails a pnpm in packageManager published 5 days ago", async () => {
    // The review's scenario: pnpm@10.34.9, published 2026-10-25T17:54Z.
    const result = await check(manifest({ packageManager: "pnpm@10.34.9" }));
    expect(result.failures).toEqual([
      {
        package: "pnpm@10.34.9",
        reason: "too_young",
        detail: "packageManager in package.json: published 2026-10-25T17:54:00.000Z, 4.8 days ago",
      },
    ]);
    expect(result.checked).toBe(1);
  });

  it("R6-04: fails a young pnpm in devEngines.packageManager", async () => {
    const result = await check(
      manifest({
        packageManager: "pnpm@10.28.0",
        devEngines: { packageManager: { name: "pnpm", version: "10.34.9" } },
      }),
    );
    expect(result.failures).toMatchObject([
      {
        package: "pnpm@10.34.9",
        reason: "too_young",
        detail: expect.stringMatching(/^devEngines\.packageManager in package\.json: published/),
      },
    ]);
    expect(result.checked).toBe(2);
  });

  it("R6-04: passes an old pnpm and a sha512 hash that is the registry's", async () => {
    const plain = await check(manifest({ packageManager: "pnpm@10.28.0" }));
    expect(plain).toMatchObject({ checked: 1, failures: [] });
    const hashed = await check(manifest({ packageManager: `pnpm@10.28.0+sha512.${PNPM_SHA512}` }));
    expect(hashed).toMatchObject({ checked: 1, failures: [] });
  });

  it("R6-04: fails a sha512 hash that is not the registry's", async () => {
    const other = `${PNPM_SHA512.slice(0, -2)}00`;
    const result = await check(manifest({ packageManager: `pnpm@10.28.0+sha512.${other}` }));
    expect(result.failures).toMatchObject([
      {
        package: "pnpm@10.28.0",
        reason: "mismatch",
        detail: expect.stringMatching(
          /^packageManager in package\.json: the hash in packageManager is not the sha512 digest the registry publishes/,
        ),
      },
    ]);
  });

  it("R6-04: the exception list applies to the pnpm version", async () => {
    const result = await check(manifest({ packageManager: "pnpm@10.34.9" }), {
      exceptions: [{ package: "pnpm@10.34.9", accepts: "too_young", reason: "security fix" }],
    });
    expect(result.failures).toEqual([]);
    expect(result.excepted).toMatchObject([{ package: "pnpm@10.34.9" }]);
  });

  it("R6-04: main exits 1 for a young pnpm and for a packageManager it cannot check", async () => {
    const run = async (packageJson: string) => {
      const out: string[] = [];
      const err: string[] = [];
      const { fetch } = mockFetch(PNPM_REGISTRY);
      const code = await main({
        lockfile: lockfile([]),
        packageJson,
        fetch,
        now: NOW,
        exceptions: [],
        log: (line) => out.push(line),
        error: (line) => err.push(line),
      });
      return { code, out, err };
    };
    const young = await run(manifest({ packageManager: "pnpm@10.34.9" }));
    expect(young.code).toBe(1);
    expect(young.err[0]).toBe(
      "too young: pnpm@10.34.9 (packageManager in package.json: published 2026-10-25T17:54:00.000Z, 4.8 days ago)",
    );
    const range = await run(manifest({ packageManager: "pnpm@^10.28.0" }));
    expect(range.code).toBe(1);
    expect(range.err).toEqual([
      expect.stringMatching(/^error: package\.json packageManager names pnpm/),
    ]);
    const ok = await run(manifest({ packageManager: "pnpm@10.28.0" }));
    expect(ok).toEqual({
      code: 0,
      out: [
        "ok: all 0 locked package versions and pnpm 10.28.0 (packageManager) were published at least 14 days before 2026-10-30T12:00:00.000Z",
      ],
      err: [],
    });
  });

  it("R6-04: the repository pins an exact pnpm in packageManager", () => {
    const pins = parsePackageManager(readFileSync(join(REPO_ROOT, "package.json"), "utf8"));
    expect(pins).toEqual([
      { field: "packageManager", version: expect.stringMatching(/^\d+\.\d+\.\d+$/) },
    ]);
  });
});

/** A workspace file in the layout the repository uses. */
const WORKSPACE = [
  "packages:",
  "  - apps/*",
  "  - packages/*",
  "",
  "onlyBuiltDependencies:",
  "  - esbuild",
  "",
  "# Only resolve versions released at least 14 days ago.",
  "minimumReleaseAge: 20160",
  "",
].join("\n");

const checkouts: string[] = [];
afterEach(() => {
  for (const root of checkouts.splice(0)) rmSync(root, { recursive: true, force: true });
});

/**
 * A checkout in a temporary directory: package.json, pnpm-lock.yaml and
 * pnpm-workspace.yaml that pass, with `files` (paths relative to the root) over them.
 */
function checkout(files: Record<string, string> = {}): string {
  const root = mkdtempSync(join(tmpdir(), "virga-release-age-"));
  checkouts.push(root);
  const all: Record<string, string> = {
    "package.json": manifest({ packageManager: "pnpm@10.28.0" }),
    "pnpm-lock.yaml": lockfile([]),
    "pnpm-workspace.yaml": WORKSPACE,
    ...files,
  };
  for (const [path, text] of Object.entries(all)) put(join(root, path), text);
  return root;
}

/** main on a checkout, with pnpm 10.28.0 in the registry. */
async function runMain(root: string, extra: Partial<MainOptions> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const { fetch } = mockFetch(PNPM_REGISTRY);
  const code = await main({
    root,
    fetch,
    now: NOW,
    exceptions: [],
    retryDelayMs: 0,
    log: (line) => out.push(line),
    error: (line) => err.push(line),
    ...extra,
  });
  return { code, out, err };
}

/** main exits 1 with one error line that matches `message`. */
async function refusedBy(root: string, message: RegExp) {
  const { code, out, err } = await runMain(root);
  expect({ code, out, err }).toEqual({ code: 1, out: [], err: [expect.stringMatching(message)] });
}

const PASSES = {
  code: 0,
  out: [
    "ok: all 0 locked package versions and pnpm 10.28.0 (packageManager) were published at least 14 days before 2026-10-30T12:00:00.000Z",
  ],
  err: [],
};

describe("R8-01: config dependencies are refused", () => {
  /** A config dependency as pnpm declares one: version and integrity. */
  const PLUGIN = `pnpm-plugin-young: 1.0.0+sha512-${"A".repeat(86)}==`;
  const workspace = (text: string) => checkout({ "pnpm-workspace.yaml": text });
  const CONFIG_DEPENDENCIES =
    /configDependencies: pnpm installs config dependencies outside the lockfile/;

  it("R8-01: refuses configDependencies as a block key in pnpm-workspace.yaml", async () => {
    await refusedBy(
      workspace(`${WORKSPACE}\nconfigDependencies:\n  ${PLUGIN}\n`),
      new RegExp(`^error: pnpm-workspace\\.yaml line 11: ${CONFIG_DEPENDENCIES.source}`),
    );
    await refusedBy(
      workspace(`configDependencies: {${PLUGIN}}\n${WORKSPACE}`),
      new RegExp(`^error: pnpm-workspace\\.yaml line 1: ${CONFIG_DEPENDENCIES.source}`),
    );
  });

  it("R8-01: refuses configDependencies as a quoted key", async () => {
    for (const key of ["'configDependencies'", '"configDependencies"']) {
      await refusedBy(
        workspace(`packages:\n  - apps/*\n${key}:\n  ${PLUGIN}\n`),
        /^error: pnpm-workspace\.yaml line 3: expected a setting written as "name:" or "name: value"/,
      );
    }
  });

  it("R8-01: refuses configDependencies in a flow map", async () => {
    await refusedBy(
      workspace(`{packages: [apps/*], configDependencies: {${PLUGIN}}}\n`),
      /^error: pnpm-workspace\.yaml line 1: expected a setting/,
    );
    await refusedBy(
      workspace(`packages: [apps/*, {configDependencies: {${PLUGIN}}}]\n`),
      /^error: pnpm-workspace\.yaml line 1: write packages as a block sequence/,
    );
    await refusedBy(
      workspace(`packages:\n  - apps/*\n  - {configDependencies: {${PLUGIN}}}\n`),
      /^error: pnpm-workspace\.yaml line 3: expected a "- " item/,
    );
  });

  it("R8-01: refuses configDependencies under an anchor or merge key", async () => {
    await refusedBy(
      workspace(`packages:\n  - apps/*\n<<: {configDependencies: {${PLUGIN}}}\n`),
      /^error: pnpm-workspace\.yaml line 3: expected a setting/,
    );
    await refusedBy(
      workspace(`packages:\n  - apps/*\n<<:\n  configDependencies:\n    ${PLUGIN}\n`),
      /^error: pnpm-workspace\.yaml line 3: expected a setting/,
    );
    await refusedBy(
      workspace(`packages: &plugins\n  - apps/*\nminimumReleaseAge: *plugins\n`),
      /^error: pnpm-workspace\.yaml line 1: "&", which starts an anchor/,
    );
    await refusedBy(
      workspace(`packages:\n  - apps/*\nminimumReleaseAge: *plugins\n`),
      /^error: pnpm-workspace\.yaml line 3: "\*", which starts an anchor, alias/,
    );
    await refusedBy(
      workspace(`packages:\n  - !!str apps/*\n`),
      /^error: pnpm-workspace\.yaml line 2: "!", which starts an anchor, alias, tag/,
    );
  });

  it("R8-01: refuses configDependencies nested under another key", async () => {
    await refusedBy(
      workspace(
        `packages:\n  - apps/*\nonlyBuiltDependencies:\n  configDependencies:\n    ${PLUGIN}\n`,
      ),
      /^error: pnpm-workspace\.yaml line 4: expected a "- " item/,
    );
    await refusedBy(
      workspace(`packages:\n  - configDependencies:\n      ${PLUGIN}\n`),
      /^error: pnpm-workspace\.yaml line 2: expected a "- " item/,
    );
    await refusedBy(
      workspace(`minimumReleaseAge: 20160\n  configDependencies: {${PLUGIN}}\n`),
      /^error: pnpm-workspace\.yaml line 2: expected a "- " item/,
    );
  });

  it("R8-01: refuses configDependencies and a pnpm field that is not an object in package.json", async () => {
    const root = (pnpm: unknown) =>
      checkout({ "package.json": manifest({ packageManager: "pnpm@10.28.0", pnpm }) });
    await refusedBy(
      root({ configDependencies: { "pnpm-plugin-young": `1.0.0+sha512-${"A".repeat(86)}==` } }),
      /^error: package\.json pnpm\.configDependencies: pnpm installs config dependencies outside the lockfile/,
    );
    for (const pnpm of ["configDependencies", [], null]) {
      await refusedBy(root(pnpm), /^error: package\.json pnpm is not an object/);
    }
    expect(await runMain(root({}))).toEqual(PASSES);
  });

  it("R8-01: refuses settings that make pnpm read another lockfile or run code", async () => {
    for (const setting of [
      "gitBranchLockfile: true",
      "sharedWorkspaceLockfile: false",
      "lockfileDir: ..",
      "pnpmfile: .pnpmfile.cjs",
      "globalPnpmfile: /tmp/x.cjs",
      "useNodeVersion: 22.0.0",
      "packageExtensions:",
    ]) {
      await refusedBy(
        workspace(`${WORKSPACE}${setting}\n`),
        new RegExp(
          `^error: pnpm-workspace\\.yaml line 10: ${setting.slice(0, setting.indexOf(":"))} is not a setting the check accepts`,
        ),
      );
    }
  });

  it("R8-01: reads pnpm-workspace.yaml strictly", async () => {
    const cases: [string, RegExp][] = [
      ["packages:\n  - apps/*\npackages:\n  - packages/*\n", /line 3: packages appears twice/],
      ["packages:\n  - apps/* # apps\n", /line 2: a comment after a value/],
      ["packages:\n  -\tapps/*\n", /line 2: a tab/],
      ["packages:\n\t- apps/*\n", /line 2: a tab/],
      ["minimumReleaseAge: |\n  20160\n", /line 1: a block scalar/],
      ["minimumReleaseAge:\n  20160\n", /line 1: minimumReleaseAge needs a value on its line/],
      ["packages:\n    - apps/*\n", /line 2: expected a "- " item/],
      ["packages:\n- apps/*\n", /line 2: expected a setting/],
      ["packages:\n  - 'apps/*\n  - x'\n", /line 2: a quoted value that continues/],
      ["---\npackages:\n  - apps/*\n", /line 1: expected a setting/],
      ["packages :\n  - apps/*\n", /line 1: expected a setting/],
      ["packages:\n  - apps/*:\n", /line 2: expected a "- " item/],
      ["packages:\n  - - apps/*\n", /line 2: expected a "- " item/],
    ];
    for (const [text, message] of cases) {
      await refusedBy(
        workspace(text),
        new RegExp(`^error: pnpm-workspace\\.yaml ${message.source}`),
      );
    }
  });

  it("R8-01: accepts the layout the repository uses, and the committed file", async () => {
    expect(await runMain(checkout())).toEqual(PASSES);
    const quoted = [
      "\uFEFFpackages:\r\n  - 'apps/*'\r\n  - \"packages/*\"   ",
      "  # not built",
      "onlyBuiltDependencies: ",
      "minimumReleaseAge: 20160",
      "minimumReleaseAgeExclude:",
      "  - '@scope/fix'",
      "",
    ].join("\n");
    expect(await runMain(workspace(quoted))).toEqual(PASSES);
    const committed = await runMain(REPO_ROOT, {
      lockfile: lockfile([]),
      packageJson: manifest({ packageManager: "pnpm@10.28.0" }),
    });
    expect(committed).toEqual(PASSES);
    const settings = parseWorkspace(readFileSync(join(REPO_ROOT, "pnpm-workspace.yaml"), "utf8"));
    expect(settings.get("packages")).toContain("apps/*");
    expect(settings.get("minimumReleaseAge")).toBe("20160");
  });
});

describe("TM-29: package.json holds no pnpm settings the check does not know", () => {
  const root = (fields: Record<string, unknown>) =>
    checkout({ "package.json": manifest({ packageManager: "pnpm@10.28.0", ...fields }) });
  const NONE =
    "; the project sets no pnpm field in package.json, so the check accepts none; extend it before adding one";

  it("TM-29: refuses each pnpm field in package.json, with its reason", async () => {
    const BUILDS = "changes which packages may run install scripts";
    const OTHER =
      "is not a field the check accepts; pnpm settings here can change what pnpm installs or runs";
    const cases: [string, unknown, string][] = [
      ["overrides", { yaml: "2.9.1" }, ": replaces versions anywhere in the dependency graph"],
      [
        "patchedDependencies",
        { "yaml@2.8.0": "patches/yaml.patch" },
        ": applies patch files to installed packages",
      ],
      [
        "packageExtensions",
        { "yaml@*": { dependencies: { "left-pad": "1.3.0" } } },
        ": adds dependencies to the manifests of installed packages",
      ],
      ["neverBuiltDependencies", [], ": lets every package it does not list run install scripts"],
      ["onlyBuiltDependencies", ["esbuild"], `: ${BUILDS}`],
      ["onlyBuiltDependenciesFile", "builds.json", `: ${BUILDS}`],
      ["ignoredBuiltDependencies", ["esbuild"], `: ${BUILDS}`],
      [
        "executionEnv",
        { nodeVersion: "23.0.0" },
        ": makes pnpm download a Node\\.js runtime and run scripts with it",
      ],
      ["allowedDeprecatedVersions", { request: "*" }, ` ${OTHER}`],
      ["supportedArchitectures", { os: ["current"] }, ` ${OTHER}`],
    ];
    for (const [field, value, reason] of cases) {
      await refusedBy(
        root({ pnpm: { [field]: value } }),
        new RegExp(`^error: package\\.json pnpm\\.${field}${reason}.*${NONE}$`),
      );
    }
  });

  it("TM-29: refuses resolutions, which pnpm reads as overrides", async () => {
    await refusedBy(
      root({ resolutions: { yaml: "2.9.1" } }),
      new RegExp(
        `^error: package\\.json resolutions: pnpm reads it as overrides, which replace versions anywhere in the dependency graph${NONE}$`,
      ),
    );
  });

  it("TM-29: accepts an empty pnpm field, and none", async () => {
    expect(await runMain(root({ pnpm: {} }))).toEqual(PASSES);
    expect(await runMain(root({}))).toEqual(PASSES);
  });

  it("TM-29: refuses a pnpm field in an app's package.json", async () => {
    await refusedBy(
      checkout({
        "apps/web/package.json": manifest({
          name: "@virga/web",
          pnpm: { executionEnv: { nodeVersion: "23.0.0" } },
        }),
      }),
      /^error: apps\/web\/package\.json has a pnpm field; pnpm takes its settings from the root package\.json, where the check reads them, and executionEnv from each project/,
    );
  });
});

describe("R8-02: only the root names the package manager", () => {
  /** The review's pin: pnpm 10.33.2, published three days before NOW. */
  const YOUNG = "pnpm@10.33.2";
  const ONLY_ROOT =
    /only the root package\.json may name the package manager: corepack takes the nearest package\.json that names one/;
  const web = (fields: Record<string, unknown>) => ({
    "apps/web/package.json": manifest({ name: "@virga/web", ...fields }),
  });

  it("R8-02: refuses packageManager in apps/web/package.json", async () => {
    await refusedBy(
      checkout(web({ packageManager: YOUNG })),
      new RegExp(`^error: apps/web/package\\.json names packageManager; ${ONLY_ROOT.source}`),
    );
    await refusedBy(
      checkout(web({ packageManager: "pnpm@https://example.com/pnpm.tgz" })),
      /^error: apps\/web\/package\.json names packageManager/,
    );
  });

  it("R8-02: refuses devEngines.packageManager in apps/web/package.json", async () => {
    await refusedBy(
      checkout(web({ devEngines: { packageManager: { name: "pnpm", version: "10.33.2" } } })),
      new RegExp(
        `^error: apps/web/package\\.json names devEngines\\.packageManager; ${ONLY_ROOT.source}`,
      ),
    );
    await refusedBy(
      checkout(web({ devEngines: "pnpm" })),
      /^error: apps\/web\/package\.json devEngines is not an object/,
    );
  });

  it("R8-02: refuses .corepack.env at the root, in apps and in apps/web", async () => {
    const env = "COREPACK_ENABLE_UNSAFE_CUSTOM_URLS=1\n";
    for (const path of [".corepack.env", "apps/.corepack.env", "apps/web/.corepack.env"]) {
      await refusedBy(
        checkout({ ...web({}), [path]: env }),
        new RegExp(
          `^error: ${path.replaceAll(".", "\\.")}: corepack loads \\.corepack\\.env files`,
        ),
      );
    }
    await refusedBy(
      checkout({ "apps/web/.COREPACK.ENV": env }),
      /^error: apps\/web\/\.COREPACK\.ENV: corepack loads/,
    );
  });

  it("R8-02: refuses a pnpm-workspace.yaml other than the root", async () => {
    await refusedBy(
      checkout({ "apps/web/pnpm-workspace.yaml": "configDependencies: {}\n" }),
      /^error: apps\/web\/pnpm-workspace\.yaml: only the root may hold pnpm-workspace\.yaml/,
    );
  });

  it("R8-02: refuses a package.json it cannot read", async () => {
    await refusedBy(
      checkout({ "apps/web/package.json": "{" }),
      /^error: apps\/web\/package\.json is not valid JSON/,
    );
    await refusedBy(
      checkout({ "apps/web/package.json": "[]" }),
      /^error: apps\/web\/package\.json is not a JSON object/,
    );
  });

  it("R8-02: does not follow symbolic links, and refuses them", async () => {
    // Outside the checkout, with a young pin that corepack would read through the links.
    const target = checkout({ "package.json": manifest({ packageManager: YOUNG }) });
    const linkedFile = checkout();
    mkdirSync(join(linkedFile, "apps", "web"), { recursive: true });
    symlinkSync(join(target, "package.json"), join(linkedFile, "apps", "web", "package.json"));
    await refusedBy(
      linkedFile,
      /^error: apps\/web\/package\.json is a symbolic link, which the check does not follow; corepack and pnpm would/,
    );
    const linkedDirectory = checkout();
    mkdirSync(join(linkedDirectory, "apps"));
    symlinkSync(target, join(linkedDirectory, "apps", "web"));
    await refusedBy(linkedDirectory, /^error: apps\/web is a symbolic link/);
  });

  it("R8-02: leaves out node_modules and .git", async () => {
    const pinned = manifest({ packageManager: YOUNG });
    const root = checkout({
      "node_modules/.corepack.env": "",
      "node_modules/x/package.json": pinned,
      "apps/web/node_modules/.corepack.env": "",
      "apps/web/node_modules/.pnpm/x@1.0.0/node_modules/x/package.json": pinned,
      ".git/package.json": pinned,
      ...web({ scripts: { build: "vite build" } }),
    });
    symlinkSync("../../../elsewhere", join(root, "apps", "web", "node_modules", "y"));
    expect(await runMain(root)).toEqual(PASSES);
  });

  it("R8-02: accepts package.json files without a package manager, and the real checkout", async () => {
    const root = checkout({
      ...web({ scripts: { build: "vite build" }, devEngines: { runtime: { name: "node" } } }),
      "packages/graph/package.json": manifest({ name: "@virga/graph" }),
    });
    expect(await runMain(root)).toEqual(PASSES);
    const real = await runMain(REPO_ROOT, {
      lockfile: lockfile([]),
      packageJson: manifest({ packageManager: "pnpm@10.28.0" }),
    });
    expect(real).toEqual(PASSES);
  });
});

describe("R9-01: the root .npmrc is read strictly", () => {
  /** The committed .npmrc. */
  const NPMRC = "save-exact=true\nengine-strict=true\n";
  const npmrc = (text: string, files: Record<string, string> = {}) =>
    checkout({ ".npmrc": text, ...files });
  /** main exits 1 with one error for `.npmrc line <line>: <message>`. */
  const refuses = async (text: string, line: number, message: RegExp) => {
    const result = await runMain(npmrc(text));
    expect(result).toEqual({
      code: 1,
      out: [],
      err: [expect.stringMatching(new RegExp(`^error: \\.npmrc line ${line}: ${message.source}`))],
    });
    return result.err.join("\n");
  };
  const ONLY = "; the project's \\.npmrc holds only save-exact=true and engine-strict=true";

  it("R9-01: refuses lockfile-dir=other, which makes pnpm install from a lockfile the check never dated", async () => {
    // The review's case: the root lockfile locks yaml 2.8.0, 400 days old, and
    // other/pnpm-lock.yaml locks 2.9.1, one day old, which pnpm would install.
    const root = npmrc(`${NPMRC}lockfile-dir=other\n`, {
      "pnpm-lock.yaml": lockfile([registryEntry("yaml@2.8.0")]),
      "other/pnpm-lock.yaml": lockfile([registryEntry("yaml@2.9.1")]),
    });
    const { fetch } = mockFetch({ ...PNPM_REGISTRY, yaml: { "2.8.0": ago(400), "2.9.1": ago(1) } });
    expect(await runMain(root, { fetch })).toEqual({
      code: 1,
      out: [],
      err: [
        expect.stringMatching(
          /^error: \.npmrc line 3: lockfile-dir makes pnpm install from a lockfile other than the root pnpm-lock\.yaml the check dates/,
        ),
      ],
    });
  });

  it("R9-01: refuses each setting that changes the lockfile, the registry or the runtime, or runs code", async () => {
    const SECRET = "npm_SYNTHETICr9token0123456789abcdef";
    const LOCKFILE = "makes pnpm install from a lockfile other than the root pnpm-lock\\.yaml";
    const RUNTIME = "makes pnpm download and run a Node\\.js runtime the check does not date";
    const FETCH = "changes where or how pnpm fetches packages";
    const CODE = "makes pnpm run code the check does not read";
    const CREDENTIAL =
      "a registry credential, token helper or client certificate \\(the check prints neither key nor value\\)";
    const UNKNOWN = "an unknown setting, whose key the check does not print";
    const cases: [string, string][] = [
      ["lockfile-dir=other", `lockfile-dir ${LOCKFILE}`],
      ["git-branch-lockfile=true", `git-branch-lockfile ${LOCKFILE}`],
      [
        "merge-git-branch-lockfiles-branch-pattern=main",
        `merge-git-branch-lockfiles-branch-pattern ${LOCKFILE}`,
      ],
      ["shared-workspace-lockfile=false", `shared-workspace-lockfile ${LOCKFILE}`],
      ["lockfile=false", `lockfile ${LOCKFILE}`],
      ["use-node-version=23.0.0", `use-node-version ${RUNTIME}`],
      ["node-version=23.0.0", `node-version ${RUNTIME}`],
      ["node-mirror:release=http://127.0.0.1:8080/", `node-mirror:<channel> ${RUNTIME}`],
      ["registry=https://registry.invalid/", `registry ${FETCH}`],
      ["@virga:registry=https://registry.invalid/", `@<scope>:registry ${FETCH}`],
      ["strict-ssl=false", `strict-ssl ${FETCH}`],
      ["https-proxy=http://proxy.invalid/", `https-proxy ${FETCH}`],
      [`//registry.npmjs.org/:_authToken=${SECRET}`, CREDENTIAL],
      [`_authToken=${SECRET}`, CREDENTIAL],
      [`_auth=${SECRET}`, CREDENTIAL],
      ["//registry.npmjs.org/:tokenHelper=/tmp/helper", CREDENTIAL],
      [`${SECRET}=true`, UNKNOWN],
      ["pnpmfile=.pnpmfile.cjs", `pnpmfile ${CODE}`],
      ["global-pnpmfile=/tmp/x.cjs", `global-pnpmfile ${CODE}`],
      ["node-options=--require=./x.cjs", `node-options ${CODE}`],
      ["script-shell=/tmp/sh", `script-shell ${CODE}`],
      ["ignore-scripts=false", UNKNOWN],
    ];
    for (const [line, message] of cases) {
      const err = await refuses(`${NPMRC}${line}\n`, 3, new RegExp(`${message}.*${ONLY}`));
      expect(err).not.toContain(SECRET);
    }
  });

  it("R9-01: reads .npmrc strictly: one key=value per line, comments on their own lines", async () => {
    const VALUE =
      "save-exact has a value the check does not accept; it accepts save-exact=true only";
    const cases: [string, number, string][] = [
      ["save-exact = true\n", 1, "write the setting as key=value, without spaces around the key"],
      ["  save-exact=true\n", 1, "write the setting as key=value, without spaces around the key"],
      ["save-exact=false\n", 1, VALUE],
      ['save-exact="true"\n', 1, VALUE],
      ["save-exact= true\n", 1, VALUE],
      ["save-exact=true ; exact versions\n", 1, VALUE],
      ["save-exact=true # exact versions\n", 1, VALUE],
      [`save-exact=\${SAVE_EXACT}\n`, 1, VALUE],
      ["lockfile-dir\n", 1, "expected one key=value per line"],
      ["[registry]\nsave-exact=true\n", 1, "expected one key=value per line"],
      ["save-exact=true\nsave-exact=true\n", 2, "save-exact appears twice"],
      ["save-exact[]=true\n", 1, "an unknown setting, whose key the check does not print"],
      ["SAVE-EXACT=true\n", 1, "an unknown setting, whose key the check does not print"],
      ["save-exact=true\rlockfile-dir=other\n", 2, "lockfile-dir makes pnpm install"],
      ["\u00A0# not a comment line\n", 1, "expected one key=value per line"],
    ];
    for (const [text, line, message] of cases) await refuses(text, line, new RegExp(message));
  });

  it("R9-01: accepts the committed .npmrc, comment lines, CRLF, a BOM and no .npmrc", async () => {
    expect(parseNpmrc(readFileSync(join(REPO_ROOT, ".npmrc"), "utf8"))).toEqual(
      new Map([
        ["save-exact", "true"],
        ["engine-strict", "true"],
      ]),
    );
    expect(await runMain(npmrc(NPMRC))).toEqual(PASSES);
    const commented =
      "\uFEFF# exact versions\r\n  ; engines\r\n\r\nsave-exact=true \r\nengine-strict=true";
    expect(await runMain(npmrc(commented))).toEqual(PASSES);
    expect(await runMain(npmrc(""))).toEqual(PASSES);
    expect(await runMain(checkout())).toEqual(PASSES);
  });
});

describe("R9-02: only the root holds .npmrc", () => {
  it("R9-02: refuses an app's .npmrc, which makes its build fetch and run a Node.js runtime", async () => {
    const mirror = "use-node-version=23.0.0\nnode-mirror:release=http://127.0.0.1:8080/\n";
    for (const path of ["apps/web/.npmrc", "apps/.npmrc", "packages/graph/.npmrc"]) {
      await refusedBy(
        checkout({ ".npmrc": "save-exact=true\n", [path]: mirror }),
        new RegExp(
          `^error: ${path.replaceAll(".", "\\.")}: only the root may hold \\.npmrc; pnpm also reads the \\.npmrc of the directory a command runs in`,
        ),
      );
    }
    await refusedBy(
      checkout({ "apps/web/.npmrc": "" }),
      /^error: apps\/web\/\.npmrc: only the root may hold \.npmrc/,
    );
  });
});

describe(".npmrc messages (round 10 hardening): a refused key is printed only from the known lists", () => {
  /** A lowercase hex secret, shaped like a setting name. */
  const HEX = "0123456789abcdef0123456789abcdef01234567";
  const run = (line: string) => runMain(checkout({ ".npmrc": `save-exact=true\n${line}\n` }));

  it(".npmrc messages: says an unknown setting, with its line number, for a key on no list", async () => {
    for (const line of [
      `${HEX}=true`,
      `node-mirror-${HEX}=x`,
      "ignore-scripts=false",
      "lockfile-dirx=other",
      "npm_SYNTHETICr10token=true",
    ]) {
      const { code, out, err } = await run(line);
      expect({ code, out, err }, line).toEqual({
        code: 1,
        out: [],
        err: [
          expect.stringMatching(
            /^error: \.npmrc line 2: an unknown setting, whose key the check does not print; /,
          ),
        ],
      });
      expect(err.join("\n")).not.toContain(line.slice(0, line.indexOf("=")));
    }
  });

  it(".npmrc messages: prints a key on a list, and for a scope or channel only the setting", async () => {
    const cases: [string, RegExp][] = [
      ["lockfile-dir=other", /^error: \.npmrc line 2: lockfile-dir makes pnpm install/],
      [
        `@${HEX}:registry=https://registry.invalid/`,
        /^error: \.npmrc line 2: @<scope>:registry changes where or how pnpm fetches packages/,
      ],
      [
        `node-mirror:${HEX}=http://127.0.0.1:8080/`,
        /^error: \.npmrc line 2: node-mirror:<channel> makes pnpm download and run a Node\.js runtime/,
      ],
    ];
    for (const [line, message] of cases) {
      const { code, err } = await run(line);
      expect({ code, err }, line).toEqual({ code: 1, err: [expect.stringMatching(message)] });
      expect(err.join("\n")).not.toContain(HEX);
    }
  });
});

describe("L-1: names a case-insensitive file system opens as the files the check reads", () => {
  it("L-1: refuses pnpm-workspace.yaml spelled with U+017F (long s) below the root", async () => {
    // The review's case: toLowerCase does not fold U+017F, so this passed with config dependencies.
    await refusedBy(
      checkout({ "apps/web/pnpm-work\u017Fpace.yaml": "configDependencies: {}\n" }),
      /^error: apps\/web\/pnpm-work\u017Fpace\.yaml: only the root may hold pnpm-workspace\.yaml/,
    );
  });

  it("L-1: refuses .corepack.env, .npmrc and a package manager in package.json, however spelled", async () => {
    await refusedBy(
      checkout({ "apps/web/.corepac\u212A.env": "COREPACK_NPM_REGISTRY=https://x.invalid\n" }),
      /^error: apps\/web\/\.corepac\u212A\.env: corepack loads \.corepack\.env files/,
    );
    for (const name of [".NPMRC", ".npm\u200Brc", ".\uFF4Epmrc"]) {
      await refusedBy(
        checkout({ [`apps/web/${name}`]: "use-node-version=23.0.0\n" }),
        new RegExp(`^error: apps/web/${name.replace(".", "\\.")}: only the root may hold \\.npmrc`),
      );
    }
    await refusedBy(
      checkout({
        "apps/web/pac\u212Aage.json": manifest({
          name: "@virga/web",
          packageManager: "pnpm@10.33.2",
        }),
      }),
      /^error: apps\/web\/pac\u212Aage\.json names packageManager/,
    );
  });

  it("L-1: refuses a name at the root that folds to a file the check reads by its exact name", async () => {
    const variants: [string, string][] = [
      ["pnpm-work\u017Fpace.yaml", "pnpm-workspace.yaml"],
      ["pac\u212Aage.json", "package.json"],
      ["pnpm-loc\u212A.yaml", "pnpm-lock.yaml"],
      [".NPMRC", ".npmrc"],
    ];
    for (const [name, target] of variants) {
      await refusedBy(
        checkout({ [name]: "{}\n" }),
        new RegExp(
          `^error: ${name.replaceAll(".", "\\.")}: a case-insensitive file system opens this name as ${target.replaceAll(".", "\\.")}, which the check reads by that exact name only`,
        ),
      );
    }
  });
});

describe("R10-01: no pnpmfile, which pnpm loads on every command", () => {
  /** The review's hook: pnpm then installs from other/pnpm-lock.yaml. */
  const PNPMFILE =
    "module.exports = { hooks: { updateConfig: (config) => ({ ...config, lockfileDir: 'other' }) } };\n";
  const PNPMFILE_LOADED = "pnpm loads \\.pnpmfile\\.cjs on every command and runs its hooks";

  it("R10-01: refuses a root .pnpmfile.cjs whose updateConfig hook sets lockfileDir to other", async () => {
    // The review's case: the root lockfile locks yaml 2.8.0, 400 days old, and
    // other/pnpm-lock.yaml locks 2.9.1, one day old, which pnpm would install.
    const root = checkout({
      "package.json": manifest({ packageManager: "pnpm@10.28.0", dependencies: { yaml: "2.9.1" } }),
      "pnpm-lock.yaml": lockfile([registryEntry("yaml@2.8.0")]),
      ".pnpmfile.cjs": PNPMFILE,
      "other/pnpm-lock.yaml": lockfile([registryEntry("yaml@2.9.1")]),
    });
    const { fetch } = mockFetch({ ...PNPM_REGISTRY, yaml: { "2.8.0": ago(400), "2.9.1": ago(1) } });
    expect(await runMain(root, { fetch })).toEqual({
      code: 1,
      out: [],
      err: [expect.stringMatching(new RegExp(`^error: \\.pnpmfile\\.cjs: ${PNPMFILE_LOADED}`))],
    });
  });

  it("R10-01: refuses .pnpmfile.cjs and .pnpmfile.mjs anywhere, however spelled", async () => {
    for (const path of [
      ".pnpmfile.mjs",
      "apps/web/.pnpmfile.cjs",
      "apps/web/.pnpmfile.mjs",
      "packages/graph/.pnpmfile.cjs",
      ".PNPMFILE.CJS",
      "apps/web/.pnpm\u200Bfile.cjs",
      "apps/web/.pnpmfile.\uFF43js",
    ]) {
      await refusedBy(
        checkout({ [path]: PNPMFILE }),
        new RegExp(`^error: ${path.replaceAll(".", "\\.")}: ${PNPMFILE_LOADED}`),
      );
    }
  });

  it("R10-01: refuses the names Node's require tries for .pnpmfile.cjs, and .pnp.cjs", async () => {
    // pnpm requires <root>/.pnpmfile.cjs, so Node also opens .pnpmfile.cjs.js,
    // .json and .node, or a .pnpmfile.cjs directory.
    const required: [string, string][] = [
      [".pnpmfile.cjs.js", ".pnpmfile.cjs.js"],
      [".pnpmfile.cjs.json", ".pnpmfile.cjs.json"],
      [".pnpmfile.cjs.node", ".pnpmfile.cjs.node"],
      [".pnpmfile.cjs/index.js", ".pnpmfile.cjs"],
    ];
    for (const [path, shown] of required) {
      await refusedBy(
        checkout({ [path]: PNPMFILE }),
        new RegExp(`^error: ${shown.replaceAll(".", "\\.")}: ${PNPMFILE_LOADED}`),
      );
    }
    // pnpm run and pnpm exec require a .pnp.cjs of the workspace root or the
    // project into every script, whatever node-linker says.
    const pnp: [string, string][] = [
      [".pnp.cjs", ".pnp.cjs"],
      ["apps/web/.pnp.cjs", "apps/web/.pnp.cjs"],
      [".pnp.cjs/index.js", ".pnp.cjs"],
      ["apps/web/.PNP.CJS", "apps/web/.PNP.CJS"],
    ];
    for (const [path, shown] of pnp) {
      await refusedBy(
        checkout({ [path]: "console.log('loaded');\n" }),
        new RegExp(
          `^error: ${shown.replaceAll(".", "\\.")}: pnpm run and pnpm exec load \\.pnp\\.cjs into every script they run`,
        ),
      );
    }
  });
});

describe("R10-02: no package.yaml or package.json5", () => {
  const MANIFEST =
    "pnpm reads package\\.yaml and package\\.json5 as project manifests, and the check reads package\\.json only";

  it("R10-02: refuses apps/x/package.yaml with pnpm.executionEnv.nodeVersion 23.0.0", async () => {
    // The review's case: apps/* matches apps/x, and pnpm -r run build would
    // fetch Node.js 23.0.0 and run the build with it.
    await refusedBy(
      checkout({
        "apps/x/package.yaml": [
          "name: x",
          "scripts:",
          "  build: node -v",
          "pnpm:",
          "  executionEnv:",
          "    nodeVersion: 23.0.0",
          "",
        ].join("\n"),
      }),
      new RegExp(`^error: apps/x/package\\.yaml: ${MANIFEST}`),
    );
  });

  it("R10-02: refuses package.yaml and package.json5 anywhere, however spelled", async () => {
    for (const path of [
      "package.yaml",
      "package.json5",
      "apps/web/package.json5",
      "packages/graph/PACKAGE.YAML",
      "apps/x/pac\u212Aage.yaml",
    ]) {
      await refusedBy(
        checkout({ [path]: "{name: 'x'}\n" }),
        new RegExp(`^error: ${path.replaceAll(".", "\\.")}: ${MANIFEST}`),
      );
    }
  });
});

describe("EXCEPTIONS", () => {
  it("names exact versions and says why", () => {
    for (const exception of EXCEPTIONS) {
      expect(exception.package).toMatch(/^(@[^@/]+\/)?[^@/]+@\S+$/);
      expect(exception.reason.trim()).not.toBe("");
    }
  });

  it("R8-03: each names the failure it accepts and, for a non-registry package, its resolution", async () => {
    const { fetch } = mockFetch({});
    const check = checkReleaseAge(lockfile([]), options(fetch, { exceptions: EXCEPTIONS }));
    await expect(check).resolves.toMatchObject({ failures: [] });
  });
});

describe("CI workflow", () => {
  const WORKFLOWS = join(REPO_ROOT, ".github", "workflows");
  const workflow = readFileSync(join(WORKFLOWS, "ci.yml"), "utf8");
  const ci = parseWorkflow(workflow);
  /** A job of ci.yml. */
  const job = (name: string): Job => {
    const found = ci.jobs.get(name);
    expect(found, name).toBeDefined();
    return found as Job;
  };

  /** gateProblems of every file in a workflow directory, prefixed with its name. */
  const workflowProblems = (dir: string) =>
    readdirSync(dir)
      .sort()
      .flatMap((file) =>
        gateProblems(readFileSync(join(dir, file), "utf8")).map((problem) => `${file}: ${problem}`),
      );

  it("R8-04: every workflow in .github/workflows installs only after its release-age job", () => {
    expect(readdirSync(WORKFLOWS)).toContain("ci.yml");
    expect(workflowProblems(WORKFLOWS)).toEqual([]);
  });

  it("R8-04: the guard reads every file in the workflow directory", () => {
    const dir = mkdtempSync(join(tmpdir(), "virga-workflows-"));
    checkouts.push(dir);
    put(join(dir, "ci.yml"), workflow);
    const sha = "0".repeat(40);
    put(
      join(dir, "deploy.yml"),
      [
        "name: Deploy",
        "",
        "on:",
        "  push:",
        "    branches: [main]",
        "",
        "jobs:",
        "  # A job named release-age that does not run the check.",
        "  release-age:",
        "    steps:",
        "      - run: echo ok",
        "  deploy:",
        "    needs: release-age",
        "    steps:",
        `      - uses: pnpm/action-setup@${sha}`,
        "        with:",
        "          version: 10.34.9",
        "      - run: pnpm install --frozen-lockfile && pnpm deploy",
        "  'quoted':",
        "    steps:",
        "      - run: npm ci",
        "  reusable:",
        "    uses: example/workflows/.github/workflows/deploy.yml@main",
        "",
      ].join("\n"),
    );
    expect(workflowProblems(dir)).toEqual([
      "deploy.yml: job quoted installs or deploys before release-age",
      "deploy.yml: job reusable installs or deploys before release-age",
      "deploy.yml: no release-age job that runs the check before anything else",
      `deploy.yml: line 11: release-age runs "echo ok", not the check; a command there could change the check's environment through $GITHUB_ENV or $GITHUB_PATH`,
      "deploy.yml: pnpm/action-setup has a version input",
      "deploy.yml: example/workflows/.github/workflows/deploy.yml@main is not pinned by commit SHA",
    ]);
  });

  /** A workflow with a release-age job and an install job that needs it, with lines added. */
  function scratchWorkflow(
    extra: { top?: string[]; check?: string[]; step?: string[]; install?: string[] } = {},
  ): string {
    return [
      "name: CI",
      "",
      ...(extra.top ?? []),
      "jobs:",
      "  release-age:",
      "    runs-on: ubuntu-24.04",
      ...(extra.check ?? []),
      "    steps:",
      "      - name: Release age",
      "        run: node scripts/check-release-age.ts",
      "      - run: node scripts/check-release-age.ts",
      ...(extra.step ?? []),
      "  install:",
      "    needs: release-age",
      ...(extra.install ?? []),
      "    steps:",
      `      - uses: pnpm/action-setup@${"0".repeat(40)}`,
      "      - run: pnpm install --frozen-lockfile",
      "",
    ].join("\n");
  }

  const IGNORED =
    "release-age has continue-on-error, so the jobs that need it run when the check fails";
  const RUNS = "job install has an if: that runs it when release-age failed";
  const HIDES =
    "the guard refuses anchors, aliases, merge keys, tags and directives, which another parser may read differently and which could hide an if: or continue-on-error";

  it("H-1: flags a release-age check that can fail without failing its job", () => {
    expect(gateProblems(scratchWorkflow())).toEqual([]);
    for (const value of ["true", `\${{ true }}`, "false"]) {
      expect(
        gateProblems(scratchWorkflow({ step: [`        continue-on-error: ${value}`] })),
      ).toEqual([IGNORED]);
      expect(gateProblems(scratchWorkflow({ check: [`    continue-on-error: ${value}`] }))).toEqual(
        [IGNORED],
      );
    }
    // YAML reads the quoted key as continue-on-error too.
    expect(gateProblems(scratchWorkflow({ step: ["        'continue-on-error': true"] }))).toEqual([
      IGNORED,
    ]);
  });

  it("H-1: flags keys that change what the release-age check runs", () => {
    const unknown = (key: string) =>
      `release-age has "${key}", a key the guard does not know; keys such as shell, working-directory, env and if change what the check runs, or whether it runs`;
    const cases: [Parameters<typeof scratchWorkflow>[0], string[]][] = [
      [{ step: ["        shell: bash -c 'exit 0' {0}"] }, [unknown("shell")]],
      [{ step: ["        working-directory: other"] }, [unknown("working-directory")]],
      [{ step: ["        env:", "          NODE_OPTIONS: --import=./x.mjs"] }, [unknown("env")]],
      [{ step: ["        if: false"] }, [unknown("if")]],
      [
        { step: ["      - {run: 'exit 0', continue-on-error: true}"] },
        [
          IGNORED,
          `line 10: release-age runs "exit 0", not the check; a command there could change the check's environment through $GITHUB_ENV or $GITHUB_PATH`,
        ],
      ],
      [{ check: ["    defaults:", "      run:", "        shell: sh"] }, [unknown("defaults")]],
      [{ check: ["    container: node:22"] }, [unknown("container")]],
      [{ check: ["    if: false"] }, [unknown("if")]],
      [
        { top: ["defaults:", "  run:", "    working-directory: other", ""] },
        [
          "workflow-level defaults: applies to the release-age job too; set it on the jobs that need it",
        ],
      ],
      [
        { top: ["env:", "  NODE_OPTIONS: --import=./x.mjs", ""] },
        ["workflow-level env: applies to the release-age job too; set it on the jobs that need it"],
      ],
    ];
    for (const [extra, problems] of cases)
      expect(gateProblems(scratchWorkflow(extra))).toEqual(problems);
  });

  it("H-1: flags a release-age step that could change what the check runs or reads", () => {
    const sha = "0".repeat(40);
    // A command before the check can set NODE_OPTIONS for it through $GITHUB_ENV.
    const env = scratchWorkflow().replace(
      "      - name: Release age\n",
      `      - run: echo "NODE_OPTIONS=--import=./x.mjs" >> "$GITHUB_ENV"\n      - name: Release age\n`,
    );
    expect(gateProblems(env)).toEqual([
      `line 7: release-age runs "echo \\"NODE_OPTIONS=--import=./x.mjs\\" >> \\"$GITHUB_ENV\\"", not the check; a command there could change the check's environment through $GITHUB_ENV or $GITHUB_PATH`,
    ]);
    expect(gateProblems(scratchWorkflow({ step: [`      - uses: example/setup@${sha}`] }))).toEqual(
      [
        "release-age uses example/setup; only actions/checkout and actions/setup-node run before the check, since an action could change what it runs",
      ],
    );
    const mirror = scratchWorkflow({
      step: [
        `      - uses: actions/setup-node@${sha}`,
        "        with:",
        "          node-version-file: .nvmrc",
        "          mirror: https://nodejs.invalid",
      ],
    });
    expect(gateProblems(mirror)).toEqual([
      "release-age gives actions/setup-node the input mirror, which the guard does not know; inputs such as mirror change which Node.js runs the check",
    ]);
    // A checkout of another commit, in release-age or in a job that installs.
    const ref = (lines: string[]) => [`      - uses: actions/checkout@${sha}`, ...lines];
    expect(
      gateProblems(
        scratchWorkflow({ step: ref(["        with:", "          ref: refs/tags/old"]) }),
      ),
    ).toEqual([
      "job release-age gives actions/checkout the input ref; inputs such as ref, repository or path check out other files than the release-age job checked",
    ]);
    const install = scratchWorkflow().replace(
      "      - run: pnpm install --frozen-lockfile\n",
      `${ref(["        with:", "          Repository: example/other", "          persist-credentials: false"]).join("\n")}\n      - run: pnpm install --frozen-lockfile\n`,
    );
    expect(gateProblems(install)).toEqual([
      "job install gives actions/checkout the input repository; inputs such as ref, repository or path check out other files than the release-age job checked",
    ]);
    const plain = scratchWorkflow({
      step: ref(["        with:", "          persist-credentials: false"]),
    });
    expect(gateProblems(plain)).toEqual([]);
  });

  it("H-1: flags an installing job whose if: runs it when release-age failed", () => {
    for (const condition of [
      "always()",
      "failure()",
      `\${{ !cancelled() }}`,
      "success() || failure()",
      "Always ()",
      `\${{ always() && github.event_name == 'push' }}`,
      // With a status function GitHub adds no success() &&, so these run after a failed check too.
      "success() || true",
      `\${{ !success() }}`,
      "SUCCESS() && always()",
      `\${{ success() }} || \${{ true }}`,
    ]) {
      expect(
        gateProblems(scratchWorkflow({ install: [`    if: ${condition}`] })),
        condition,
      ).toEqual([RUNS]);
    }
    expect(gateProblems(scratchWorkflow({ install: ["    if: >-", "      always()"] }))).toEqual([
      RUNS,
    ]);
    expect(gateProblems(scratchWorkflow({ install: ["    'if': always()"] }))).toEqual([RUNS]);
    expect(gateProblems(scratchWorkflow({ install: ["    IF: always()"] }))).toEqual([RUNS]);
    for (const condition of [
      "success()",
      "github.event_name == 'push'",
      `\${{ success() && github.ref == 'refs/heads/main' }}`,
    ]) {
      expect(gateProblems(scratchWorkflow({ install: [`    if: ${condition}`] }))).toEqual([]);
    }
    // A step's if: runs only inside a job that has started.
    const upload = scratchWorkflow().replace(
      "      - run: pnpm install --frozen-lockfile\n",
      "      - run: pnpm install --frozen-lockfile\n      - if: always()\n        run: echo done\n",
    );
    expect(gateProblems(upload)).toEqual([]);
  });

  it("H-1: flags anchors, aliases and merge keys, which could hide an if: or continue-on-error", () => {
    const anchored = scratchWorkflow({
      top: ["env:", "  RUN: &run always()", ""],
      install: ["    if: *run"],
    });
    expect(gateProblems(anchored)).toEqual([
      `line 4: an anchor; ${HIDES}`,
      `line 15: an alias; ${HIDES}`,
    ]);
    const merged = scratchWorkflow({ step: ["        <<: {continue-on-error: true}"] });
    expect(gateProblems(merged)).toEqual([`line 10: a merge key; ${HIDES}`]);
    const aliased = scratchWorkflow({ step: ["      - *step"] });
    expect(gateProblems(aliased)).toEqual([`line 10: an alias; ${HIDES}`]);
  });

  it("R10-03: flags continue-on-error in a release-age job indented by 5 spaces", () => {
    // The review's case (a): the job's keys at 5 spaces, its steps at 6. YAML
    // reads continue-on-error as a key of the job.
    const [check = "", install = ""] = scratchWorkflow({
      check: ["    continue-on-error: true"],
    }).split("  install:\n");
    const fiveSpaces = `${check.replace(/^ {4}(?=\S)/gm, "     ")}  install:\n${install}`;
    expect(fiveSpaces).toContain(
      "  release-age:\n     runs-on: ubuntu-24.04\n     continue-on-error: true\n     steps:\n      - name:",
    );
    expect(gateProblems(fiveSpaces)).toEqual([IGNORED]);
  });

  it("R10-03: flags an installing job whose if: is always() written with a YAML escape", () => {
    // The review's case (b): YAML reads "\x61lways()" as always().
    expect(gateProblems(scratchWorkflow({ install: ['    if: "\\x61lways()"'] }))).toEqual([RUNS]);
    expect(gateProblems(scratchWorkflow({ install: ['    if: "\\u0061lways()"'] }))).toEqual([
      RUNS,
    ]);
  });

  it("R10-03: refuses what another parser could read differently", () => {
    const cases: [string, string[]][] = [
      [
        scratchWorkflow({ check: ["    runs-on: ubuntu-22.04"] }),
        ["line 6: Map keys must be unique"],
      ],
      [
        scratchWorkflow({
          step: ["        continue-on-error: false", "        'continue-on-error': true"],
        }),
        ["line 11: Map keys must be unique"],
      ],
      [scratchWorkflow({ install: ["    if: !!str always()"] }), [`line 12: a tag; ${HIDES}`]],
      [`%YAML 1.1\n---\n${scratchWorkflow()}`, [`line 1: a directive; ${HIDES}`]],
      [
        scratchWorkflow({ top: ["true: x"] }),
        ["line 3: a key that is not a string, which another parser may read differently"],
      ],
      [
        `${scratchWorkflow()}---\nname: other\n`,
        ["line 15: Source contains multiple documents; please use YAML.parseAllDocuments()"],
      ],
      ["", ["the workflow is not a mapping"]],
    ];
    for (const [source, problems] of cases) expect(gateProblems(source), source).toEqual(problems);
  });

  it("TM-32: .nvmrc pins an exact Node.js version of at least 22.18, and every setup-node reads it", () => {
    const pinned = readFileSync(join(REPO_ROOT, ".nvmrc"), "utf8");
    const [, major = "", minor = ""] = /^(\d+)\.(\d+)\.\d+\n$/.exec(pinned) ?? [];
    expect(pinned).toMatch(/^\d+\.\d+\.\d+\n$/);
    expect(Number(major) > 22 || (Number(major) === 22 && Number(minor) >= 18)).toBe(true);
    const steps = readdirSync(WORKFLOWS).flatMap((file) =>
      nodeProblems(readFileSync(join(WORKFLOWS, file), "utf8")).map((p) => `${file} ${p}`),
    );
    expect(steps).toEqual([]);
    expect(actions(ci).filter((action) => action.startsWith("actions/setup-node@"))).toHaveLength(
      3,
    );
  });

  it("TM-32: flags a setup-node step that does not read .nvmrc", () => {
    const sha = "0".repeat(40);
    const node = (step: string[]) =>
      nodeProblems(
        ["jobs:", "  check:", "    steps:", ...step, "      - run: node -v", ""].join("\n"),
      );
    const NOT = "line 4: actions/setup-node does not take the version from .nvmrc";
    expect(node([`      - uses: actions/setup-node@${sha}`])).toEqual([NOT]);
    expect(
      node([
        `      - uses: actions/setup-node@${sha}`,
        "        with:",
        "          node-version: 22",
      ]),
    ).toEqual([NOT]);
    expect(
      node([
        `      - uses: actions/setup-node@${sha}`,
        "        with:",
        "          node-version-file: .nvmrc",
        "          node-version: 23",
      ]),
    ).toEqual([NOT]);
    // GitHub reads input names without case.
    expect(
      node([
        `      - uses: Actions/Setup-Node@${sha}`,
        "        with:",
        "          node-version-file: .nvmrc",
        "          NODE-VERSION: 23",
      ]),
    ).toEqual([NOT]);
    expect(
      node([
        `      - uses: actions/setup-node@${sha}`,
        "        with:",
        "          node-version-file: '.nvmrc '",
      ]),
    ).toEqual([NOT]);
    // The parser reads a flow map like a block.
    expect(
      node([
        `      - uses: actions/setup-node@${sha}`,
        "        with: {node-version-file: .nvmrc}",
      ]),
    ).toEqual([]);
    expect(
      node([
        "      - name: Node",
        `        uses: actions/setup-node@${sha}`,
        "        with:",
        "          node-version-file: .nvmrc",
      ]),
    ).toEqual([]);
    expect(
      node([
        `      - uses: actions/setup-node@${sha}`,
        "        with:",
        "          node-version-file: .nvmrc",
        "          cache: pnpm",
      ]),
    ).toEqual([]);
  });

  it("R8-05: deploy-dry-run needs release-age and check, so one green status covers rules:check", () => {
    const deploy = job("deploy-dry-run");
    expect(runs(deploy)).toContain("node scripts/deploy.ts --dry-run");
    expect(needs(deploy).sort()).toEqual(["check", "release-age"]);
    expect(runs(job("check"))).toContain("pnpm rules:check");
  });

  it("R4-07: runs the check in its own job, which installs nothing and runs no package code", () => {
    const check = job("release-age");
    expect(runs(check)).toEqual(["node scripts/check-release-age.ts"]);
    expect(gated(check)).toBe(false);
    expect(needs(check)).toEqual([]);
  });

  it("R4-07, R6-04: every job that installs packages needs the release-age job", () => {
    const installing = [...ci.jobs.values()].filter(gated);
    expect(installing.map(({ name }) => name)).toEqual(["check", "deploy-dry-run"]);
    expect(ungated(ci)).toEqual([]);
  });

  it("R4-07, R6-04: finds a job that installs before the check, whatever it runs", () => {
    const sha = "0".repeat(40);
    const synthetic = [
      "name: CI",
      "",
      "jobs:",
      "  release-age:",
      "    steps:",
      "      - run: node scripts/check-release-age.ts",
      "  setup-only:",
      "    steps:",
      `      - uses: pnpm/action-setup@${sha}`,
      "  lint:",
      "    needs: build",
      "    steps:",
      "      - run: pnpm lint",
      "  cached:",
      "    steps:",
      `      - uses: actions/setup-node@${sha}`,
      "        with:",
      "          cache: npm",
      "  npm-ci:",
      "    steps:",
      "      - run: npm ci",
      "  gated:",
      "    needs: [build, release-age]",
      "    steps:",
      "      - run: npm ci && npx tsc",
      "  restored:",
      "    steps:",
      `      - uses: actions/cache@${sha}`,
      "  escaped:",
      "    steps:",
      '      - run: "\\x70npm install"',
      "  plain:",
      "    steps:",
      "      - run: node --version",
      "",
    ].join("\n");
    expect(ungated(parseWorkflow(synthetic))).toEqual([
      "setup-only",
      "lint",
      "cached",
      "npm-ci",
      "restored",
      "escaped",
    ]);
  });

  it("R6-04: pnpm/action-setup takes the pnpm version from packageManager, which the check dates", () => {
    // A version input would bypass package.json, and with it the check.
    const steps = [...ci.jobs.values()]
      .flatMap((found) => found.steps)
      .filter((step) => stringOf(step.entries.get("uses"))?.startsWith("pnpm/action-setup@"));
    expect(steps.length).toBeGreaterThan(0);
    for (const step of steps) expect(step.entries.has("with")).toBe(false);
    const withInput = (input: string) =>
      gateProblems(
        workflow.replace(
          /^( +)- uses: pnpm\/action-setup@(\S+).*$/m,
          `$1- uses: pnpm/action-setup@$2\n$1  with:\n$1    ${input}`,
        ),
      );
    expect(withInput("VERSION: 10.34.9")).toEqual(["pnpm/action-setup has a version input"]);
    // A package.json the check does not read, such as one in a directory its walk leaves out.
    expect(withInput("package_json_file: node_modules/x/package.json")).toEqual([
      "pnpm/action-setup has the input package_json_file, which the guard does not know; inputs such as version and package_json_file change which pnpm it installs",
    ]);
  });

  it("R4-07: the check imports nothing from node_modules, since CI runs it before any install", () => {
    const source = readFileSync(join(REPO_ROOT, "scripts", "check-release-age.ts"), "utf8");
    const imports = [...source.matchAll(/^import .* from "([^"]+)";$/gm)].map((match) => match[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const specifier of imports) expect(specifier).toMatch(/^node:/);
    expect(source).not.toMatch(/\bimport\(|\brequire\(/);
  });

  it("pins every action by commit SHA and grants read-only permissions", () => {
    const uses = actions(ci);
    expect(uses.length).toBeGreaterThan(0);
    for (const action of uses) expect(action).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
    expect(plain(ci.top.entries.get("permissions"))).toEqual({ contents: "read" });
    for (const found of ci.jobs.values()) expect(found.keys.entries.has("permissions")).toBe(false);
  });
});

describe("main", () => {
  const run = async (registry: Registry, entries: string[]) => {
    const out: string[] = [];
    const err: string[] = [];
    const { fetch } = mockFetch({ ...PNPM_REGISTRY, ...registry });
    const code = await main({
      lockfile: lockfile(entries),
      packageJson: manifest({ packageManager: "pnpm@10.28.0" }),
      fetch,
      now: NOW,
      exceptions: [],
      retryDelayMs: 0,
      log: (line) => out.push(line),
      error: (line) => err.push(line),
    });
    return { code, out, err };
  };

  it("R4-07: exits 1 and names each version that is too young", async () => {
    const { code, err } = await run({ a: { "1.0.0": ago(3) }, b: { "2.0.0": ago(400) } }, [
      registryEntry("a@1.0.0"),
      registryEntry("b@2.0.0"),
    ]);
    expect(code).toBe(1);
    expect(err).toEqual([
      "too young: a@1.0.0 (published 2026-10-27T12:00:00.000Z, 3.0 days ago)",
      "error: 1 of 3 package versions fail the 14-day release age check; re-resolve them or add a commented exception in scripts/check-release-age.ts",
    ]);
  });

  it("exits 0 when every version is old enough", async () => {
    const { code, out, err } = await run({ b: { "2.0.0": ago(400) } }, [registryEntry("b@2.0.0")]);
    expect(code).toBe(0);
    expect(err).toEqual([]);
    expect(out).toEqual([
      "ok: all 1 locked package versions and pnpm 10.28.0 (packageManager) were published at least 14 days before 2026-10-30T12:00:00.000Z",
    ]);
  });
});
