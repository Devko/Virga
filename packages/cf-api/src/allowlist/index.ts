import { CORE_READS } from "./core.ts";
import { IDENTITY_READS } from "./identity.ts";
import { PLATFORM_READS } from "./platform.ts";
import type { ReadRule } from "./types.ts";

export type { ReadRule } from "./types.ts";

export const ALLOWED_READS: readonly ReadRule[] = [
  ...CORE_READS,
  ...PLATFORM_READS,
  ...IDENTITY_READS,
];

const SEGMENT = /^[A-Za-z0-9._~@-]+$/;

/**
 * Rejects anything that is not a plain absolute path: no query, fragment,
 * traversal, encoded slashes or empty segments.
 */
export function isPlainPath(path: string): boolean {
  if (!path.startsWith("/") || path.length > 2048) return false;
  const segments = path.slice(1).split("/");
  return segments.every((s) => s !== "" && s !== "." && s !== ".." && SEGMENT.test(s));
}

export function matchesRule(rule: ReadRule, method: string, path: string): boolean {
  if (rule.method !== method) return false;
  const want = rule.pattern.slice(1).split("/");
  const got = path.slice(1).split("/");
  if (want.length !== got.length) return false;
  return want.every((w, i) => (w.startsWith(":") ? (got[i] ?? "") !== "" : w === got[i]));
}

/** True if `method path` is a plain path that matches an allowed read. */
export function isAllowedRead(
  method: string,
  path: string,
  rules: readonly ReadRule[] = ALLOWED_READS,
): boolean {
  if (!isPlainPath(path)) return false;
  return rules.some((rule) => matchesRule(rule, method, path));
}

/** The account a path is scoped to, if it starts with `/accounts/:id`. */
export function accountOfPath(path: string): string | undefined {
  const match = /^\/accounts\/([^/]+)(\/|$)/.exec(path);
  return match?.[1];
}
