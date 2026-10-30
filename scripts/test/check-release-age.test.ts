import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  type CheckOptions,
  checkReleaseAge,
  EXCEPTIONS,
  main,
  parseLockfile,
} from "../check-release-age.ts";
import { REPO_ROOT } from "./helpers.ts";

const NOW = new Date("2026-10-30T12:00:00Z");
const DAY = 86_400_000;
const ago = (days: number) => new Date(NOW.getTime() - days * DAY).toISOString();

function lockfile(entries: string[]): string {
  return [
    "lockfileVersion: '9.0'",
    "",
    "settings:",
    "  autoInstallPeers: true",
    "",
    "importers:",
    "",
    "  .:",
    "    devDependencies:",
    "      typescript:",
    "        specifier: 6.0.3",
    "        version: 6.0.3",
    "",
    "packages:",
    "",
    ...entries.flatMap((entry) => [entry, ""]),
    "snapshots:",
    "",
    "  typescript@6.0.3: {}",
    "",
  ].join("\n");
}

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
