// Usage: node scripts/check-release-age.ts
//
// Checks that every package version in pnpm-lock.yaml was published to the
// npm registry at least 14 days ago (R4-07). minimumReleaseAge in
// pnpm-workspace.yaml applies only when pnpm resolves a version; an install
// from the lockfile, as in CI, takes whatever the lockfile holds. A version the
// check cannot date (not from the registry, no publish time, registry error)
// fails too. Needs network access to registry.npmjs.org and nothing else.
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

export const MIN_AGE_DAYS = 14;

export interface Exception {
  /** The exact lockfile entry: name@version, or the lockfile key of a non-registry package. */
  package: string;
  reason: string;
}

/**
 * Versions the project accepts although they fail the check, for example a
 * security fix that cannot wait 14 days. One entry per exact version, each with
 * a comment and a reason. The check names entries it no longer needs.
 */
export const EXCEPTIONS: readonly Exception[] = [];

const REGISTRY = "https://registry.npmjs.org";
const DAY_MS = 86_400_000;

export class LockfileError extends Error {}

export interface LockedPackage {
  /** The key in the lockfile's packages section, for example `@types/node@22.20.5`. */
  key: string;
  name: string;
  version: string;
  /** Resolved from the npm registry by integrity, so the registry knows its publish time. */
  registry: boolean;
}

const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PACKAGE_NAME = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

function unquote(value: string): string {
  if (value.startsWith("'") && value.endsWith("'") && value.length >= 2) {
    return value.slice(1, -1).replaceAll("''", "'");
  }
  if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
    return JSON.parse(value) as string;
  }
  return value;
}

/** A one-line YAML flow map as pnpm writes it: `{integrity: sha512-…, tarball: https://…}`. */
function flowMap(text: string): Map<string, string> {
  const fields = new Map<string, string>();
  for (const part of text.slice(1, -1).split(", ")) {
    const colon = part.indexOf(": ");
    if (colon > 0) fields.set(part.slice(0, colon).trim(), unquote(part.slice(colon + 2).trim()));
  }
  return fields;
}

function lockedPackage(key: string, resolution: string): LockedPackage {
  const at = key.indexOf("@", 1);
  const name = at > 0 ? key.slice(0, at) : key;
  const version = at > 0 ? key.slice(at + 1) : "";
  const fields = flowMap(resolution);
  const tarball = fields.get("tarball");
  // Anything else (git, a local directory, another registry such as JSR) has
  // no npm publish time, so the check cannot date it.
  const registry =
    PACKAGE_NAME.test(name) &&
    SEMVER.test(version) &&
    fields.has("integrity") &&
    [...fields.keys()].every((field) => field === "integrity" || field === "tarball") &&
    (tarball === undefined ||
      tarball === `${REGISTRY}/${name}/-/${name.slice(name.indexOf("/") + 1)}-${version}.tgz`);
  return { key, name, version, registry };
}

/**
 * The entries of the packages section of a pnpm lockfile (format 9). Reads
 * only the layout pnpm writes and refuses anything else rather than skip
 * entries.
 */
export function parseLockfile(text: string): LockedPackage[] {
  const lines = text.split(/\r?\n/);
  const declared = lines.find((line) => line.startsWith("lockfileVersion:"));
  const format = declared === undefined ? undefined : unquote(declared.slice(16).trim());
  if (format === undefined || !/^9\.\d+$/.test(format)) {
    throw new LockfileError(`unsupported lockfileVersion ${format ?? "(missing)"}; expected 9.x`);
  }

  const packages: LockedPackage[] = [];
  let inPackages = false;
  let current: { key: string; resolution?: string } | undefined;
  const finish = () => {
    if (current === undefined) return;
    if (current.resolution === undefined) {
      throw new LockfileError(`lockfile entry ${current.key} has no resolution`);
    }
    packages.push(lockedPackage(current.key, current.resolution));
    current = undefined;
  };
  for (const line of lines) {
    if (/^\S/.test(line)) {
      finish();
      inPackages = line.trimEnd() === "packages:";
      continue;
    }
    if (!inPackages) continue;
    const key = /^ {2}(\S.*):(?: \{\})?$/.exec(line);
    if (key?.[1] !== undefined) {
      finish();
      current = { key: unquote(key[1]) };
      continue;
    }
    const resolution = /^ {4}resolution: (\{.*\})$/.exec(line);
    if (resolution?.[1] !== undefined && current !== undefined) current.resolution = resolution[1];
  }
  finish();
  return packages;
}

export interface CheckOptions {
  fetch?: typeof fetch;
  now?: Date;
  minAgeDays?: number;
  exceptions?: readonly Exception[];
  /** Registry requests in flight at once. */
  concurrency?: number;
  /** Per request, including reading the body. */
  timeoutMs?: number;
  /** Tries per package name; network errors, timeouts, 408, 429 and 5xx are retried. */
  attempts?: number;
  retryDelayMs?: number;
}

export interface Failure {
  package: string;
  reason: "too_young" | "not_registry" | "unverified";
  detail: string;
}

export interface CheckResult {
  /** Every locked package version, from the registry or not. */
  checked: number;
  failures: Failure[];
  /** Failures the exception list accepts. */
  excepted: { package: string; detail: string }[];
  /** Exceptions that match no failure: the version is gone or old enough. */
  unusedExceptions: string[];
}

type PublishTimes = { times: Record<string, unknown> } | { error: string };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function requestError(error: unknown): string {
  if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
    return "registry request timed out";
  }
  const message = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error && isRecord(error.cause) ? error.cause.code : undefined;
  return `registry request failed: ${message.slice(0, 200)}${typeof cause === "string" ? ` (${cause})` : ""}`;
}

async function fetchPublishTimes(
  name: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  attempts: number,
  retryDelayMs: number,
): Promise<PublishTimes> {
  // Only the full document has `time`; the abbreviated install document does not.
  const url = `${REGISTRY}/${name.replace("/", "%2F")}`;
  let error = "registry request failed";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (attempt > 1 && retryDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs * (attempt - 1)));
    }
    let response: Response;
    try {
      response = await fetchImpl(url, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (cause) {
      error = requestError(cause);
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      if (response.status === 404) return { error: "not found in the registry" };
      error = `registry responded ${response.status}`;
      if (response.status === 408 || response.status === 429 || response.status >= 500) continue;
      return { error };
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch (cause) {
      if (cause instanceof SyntaxError) return { error: "the registry response is not JSON" };
      error = requestError(cause);
      continue;
    }
    const times = isRecord(body) ? body.time : undefined;
    if (!isRecord(times)) return { error: "the registry document has no publish times" };
    return { times };
  }
  return { error };
}

async function forEachLimited<T>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const worker = async () => {
    for (let index = next++; index < items.length; index = next++) await task(items[index] as T);
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

function ageProblem(
  published: unknown,
  now: number,
  minAgeMs: number,
): Omit<Failure, "package"> | undefined {
  const time =
    typeof published === "string" && ISO_TIME.test(published) ? new Date(published) : undefined;
  if (time === undefined || Number.isNaN(time.getTime())) {
    return {
      reason: "unverified",
      detail: "the registry has no valid publish time for this version",
    };
  }
  const age = now - time.getTime();
  if (age >= minAgeMs) return undefined;
  const when = age < 0 ? "after the time of the check" : `${(age / DAY_MS).toFixed(1)} days ago`;
  return { reason: "too_young", detail: `published ${time.toISOString()}, ${when}` };
}

const byPackage = (a: { package: string }, b: { package: string }) =>
  a.package < b.package ? -1 : a.package > b.package ? 1 : 0;

export async function checkReleaseAge(
  lockfile: string,
  options: CheckOptions = {},
): Promise<CheckResult> {
  const now = (options.now ?? new Date()).getTime();
  const minAgeMs = (options.minAgeDays ?? MIN_AGE_DAYS) * DAY_MS;
  const exceptions = options.exceptions ?? EXCEPTIONS;
  const fetchImpl = options.fetch ?? fetch;
  const concurrency = Math.max(1, Math.floor(options.concurrency ?? 8));
  const timeoutMs = options.timeoutMs ?? 30_000;
  const attempts = Math.max(1, Math.floor(options.attempts ?? 3));
  const retryDelayMs = options.retryDelayMs ?? 1_000;

  const packages = parseLockfile(lockfile);
  const names = [...new Set(packages.filter((p) => p.registry).map((p) => p.name))];
  const documents = new Map<string, PublishTimes>();
  await forEachLimited(names, concurrency, async (name) => {
    documents.set(
      name,
      await fetchPublishTimes(name, fetchImpl, timeoutMs, attempts, retryDelayMs),
    );
  });

  const problems: Failure[] = [];
  for (const locked of packages) {
    if (!locked.registry) {
      problems.push({
        package: locked.key,
        reason: "not_registry",
        detail: "not resolved from the npm registry, so its release age is unknown",
      });
      continue;
    }
    const document = documents.get(locked.name) ?? { error: "registry request failed" };
    if ("error" in document) {
      problems.push({ package: locked.key, reason: "unverified", detail: document.error });
      continue;
    }
    const problem = ageProblem(document.times[locked.version], now, minAgeMs);
    if (problem) problems.push({ package: locked.key, ...problem });
  }

  const accepted = new Set(exceptions.map((exception) => exception.package));
  const failures = problems.filter((problem) => !accepted.has(problem.package)).sort(byPackage);
  const excepted = problems
    .filter((problem) => accepted.has(problem.package))
    .map((problem) => ({ package: problem.package, detail: problem.detail }))
    .sort(byPackage);
  const used = new Set(excepted.map((entry) => entry.package));
  const unusedExceptions = exceptions
    .map((exception) => exception.package)
    .filter((key) => !used.has(key))
    .sort();
  return { checked: packages.length, failures, excepted, unusedExceptions };
}

export interface MainOptions extends CheckOptions {
  /** The lockfile's text; by default pnpm-lock.yaml at the repository root. */
  lockfile?: string;
  log?: (line: string) => void;
  error?: (line: string) => void;
}

const LABELS: Record<Failure["reason"], string> = {
  too_young: "too young",
  not_registry: "not checked",
  unverified: "not verified",
};

export async function main(options: MainOptions = {}): Promise<number> {
  const log = options.log ?? console.log;
  const error = options.error ?? console.error;
  const now = options.now ?? new Date();
  const minAgeDays = options.minAgeDays ?? MIN_AGE_DAYS;
  const lockfile =
    options.lockfile ?? readFileSync(new URL("../pnpm-lock.yaml", import.meta.url), "utf8");

  let result: CheckResult;
  try {
    result = await checkReleaseAge(lockfile, { ...options, now, minAgeDays });
  } catch (cause) {
    if (!(cause instanceof LockfileError)) throw cause;
    error(`error: ${cause.message}`);
    return 1;
  }
  for (const entry of result.excepted) log(`excepted: ${entry.package} (${entry.detail})`);
  for (const key of result.unusedExceptions) {
    log(`note: the exception for ${key} is no longer needed; remove it`);
  }
  for (const failure of result.failures) {
    error(`${LABELS[failure.reason]}: ${failure.package} (${failure.detail})`);
  }
  if (result.failures.length > 0) {
    error(
      `error: ${result.failures.length} of ${result.checked} locked package versions fail the ${minAgeDays}-day release age check; re-resolve them or add a commented exception in scripts/check-release-age.ts`,
    );
    return 1;
  }
  log(
    `ok: all ${result.checked} locked package versions were published at least ${minAgeDays} days before ${now.toISOString()}`,
  );
  return 0;
}

const USAGE = "usage: node scripts/check-release-age.ts";

async function cli(): Promise<number> {
  try {
    if (parseArgs({ options: { help: { type: "boolean" } } }).values.help) {
      console.log(USAGE);
      return 0;
    }
  } catch {
    console.error(USAGE);
    return 2;
  }
  try {
    return await main();
  } catch (cause) {
    console.error(`error: ${cause instanceof Error ? (cause.stack ?? cause.message) : cause}`);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await cli();
