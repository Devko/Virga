import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  type CheckOptions,
  checkReleaseAge,
  EXCEPTIONS,
  LockfileError,
  main,
  parseLockfile,
} from "../check-release-age.ts";
import { REPO_ROOT } from "./helpers.ts";

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

const REVIEW_REGISTRY = {
  "@types/node": { "26.6.6": "2026-10-28T18:36:00.000Z" },
  "undici-types": { "8.9.0": "2026-06-01T00:00:00.000Z" },
};

const registryEntry = (key: string) =>
  `  ${key}:\n    resolution: {integrity: sha512-AAAA}\n    engines: {node: '>=14.17'}`;

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
    return Response.json({ name, time: { created: ago(1000), modified: ago(1), ...doc } });
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
      { key: "@types/node@22.20.5", name: "@types/node", version: "22.20.5", registry: true },
      { key: "typescript@6.0.3", name: "typescript", version: "6.0.3", registry: true },
      {
        key: "tar-dep@https://example.com/tar-dep-1.0.0.tgz",
        name: "tar-dep",
        version: "https://example.com/tar-dep-1.0.0.tgz",
        registry: false,
      },
      {
        key: "git-dep@git+https://github.com/x/git-dep.git#0123abc",
        name: "git-dep",
        version: "git+https://github.com/x/git-dep.git#0123abc",
        registry: false,
      },
      {
        key: "dir-dep@file:../dir-dep",
        name: "dir-dep",
        version: "file:../dir-dep",
        registry: false,
      },
      { key: "@jsr/std__fs@1.0.0", name: "@jsr/std__fs", version: "1.0.0", registry: false },
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
          { package: "a@1.0.0", reason: "security fix" },
          { package: "b@1.0.0", reason: "no longer needed" },
          { package: "c@1.0.0", reason: "gone from the lockfile" },
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
      options(fetch, { exceptions: [{ package: "a@1.0.0", reason: "older fix" }] }),
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
      options(fetch, { exceptions: [{ package: "dir-dep@file:../dir-dep", reason: "local" }] }),
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
        return Response.json({ time: { "1.0.0": ago(30) } });
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
      return Response.json({ name, time: { "1.0.0": ago(30) } });
    }) as typeof globalThis.fetch;
    const result = await checkReleaseAge(text, options(fetch, { concurrency: 3 }));
    expect(result).toMatchObject({ checked: 12, failures: [] });
    expect(peak).toBe(3);
  });
});

describe("EXCEPTIONS", () => {
  it("names exact versions and says why", () => {
    for (const exception of EXCEPTIONS) {
      expect(exception.package).toMatch(/^(@[^@/]+\/)?[^@/]+@\S+$/);
      expect(exception.reason.trim()).not.toBe("");
    }
  });
});

describe("CI workflow", () => {
  const workflow = readFileSync(join(REPO_ROOT, ".github", "workflows", "ci.yml"), "utf8");

  /** The text of each job under `jobs:`, by job name. */
  function jobs(): Map<string, string> {
    const result = new Map<string, string>();
    let name: string | undefined;
    for (const line of workflow.slice(workflow.indexOf("\njobs:\n")).split("\n").slice(2)) {
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

  it("R4-07: runs the check in its own job, before every job that installs", () => {
    const all = jobs();
    const check = all.get("release-age") ?? "";
    expect(check).toContain("- run: node scripts/check-release-age.ts\n");
    expect(check).not.toContain("pnpm install");
    const installing = [...all].filter(([, text]) => text.includes("pnpm install"));
    expect(installing.map(([name]) => name)).toEqual(["check", "deploy-dry-run"]);
    for (const [, text] of installing) {
      expect(text).toContain("    needs: release-age\n");
      expect(text).not.toContain("check-release-age");
    }
  });

  it("pins every action by commit SHA and grants read-only permissions", () => {
    const uses = [...workflow.matchAll(/uses: (\S+)/g)].map((match) => match[1]);
    expect(uses.length).toBeGreaterThan(0);
    for (const action of uses) expect(action).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
    expect(workflow).toContain("\npermissions:\n  contents: read\n\n");
    expect(workflow.match(/permissions:/g)).toHaveLength(1);
  });
});

describe("main", () => {
  const run = async (registry: Registry, entries: string[]) => {
    const out: string[] = [];
    const err: string[] = [];
    const { fetch } = mockFetch(registry);
    const code = await main({
      lockfile: lockfile(entries),
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
      "error: 1 of 2 locked package versions fail the 14-day release age check; re-resolve them or add a commented exception in scripts/check-release-age.ts",
    ]);
  });

  it("exits 0 when every version is old enough", async () => {
    const { code, out, err } = await run({ b: { "2.0.0": ago(400) } }, [registryEntry("b@2.0.0")]);
    expect(code).toBe(0);
    expect(err).toEqual([]);
    expect(out).toEqual([
      "ok: all 1 locked package versions were published at least 14 days before 2026-10-30T12:00:00.000Z",
    ]);
  });
});
