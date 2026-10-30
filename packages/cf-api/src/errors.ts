import type { CfMessage } from "./types.ts";

export class CfApiError extends Error {
  readonly status: number;
  readonly path: string;
  readonly errors: CfMessage[];

  constructor(status: number, path: string, errors: CfMessage[], message?: string) {
    super(
      message ?? `${status} on ${path}: ${errors.map((e) => `${e.code} ${e.message}`).join("; ")}`,
    );
    this.name = "CfApiError";
    this.status = status;
    this.path = path;
    this.errors = errors;
  }
}

/**
 * The token lacks permission, or the broker has no usable token: none is
 * stored, or the stored one failed its recheck and was deleted (TM-04).
 * Collectors let it propagate; the scan records `no_permission`.
 */
export class NoPermissionError extends CfApiError {
  constructor(status: number, path: string, errors: CfMessage[]) {
    super(status, path, errors);
    this.name = "NoPermissionError";
  }
}

export class NotFoundError extends CfApiError {
  constructor(status: number, path: string, errors: CfMessage[]) {
    super(status, path, errors);
    this.name = "NotFoundError";
  }
}

export class RateLimitedError extends CfApiError {
  readonly retryAfter: number;

  constructor(path: string, errors: CfMessage[], retryAfter: number) {
    super(429, path, errors);
    this.name = "RateLimitedError";
    this.retryAfter = retryAfter;
  }
}

/** The broker refused the call because it is not on the read allowlist. A bug, never retried. */
export class NotAllowedError extends CfApiError {
  constructor(path: string) {
    super(400, path, [], `not on the read allowlist: ${path}`);
    this.name = "NotAllowedError";
  }
}

/** Error code the broker uses when it refuses a call that is not on the allowlist. */
export const NOT_ALLOWED_CODE = 99001;

// Codes Cloudflare uses for authorization failures, also seen with status 400.
const PERMISSION_CODES = new Set([9109, 10000]);

export function errorFor(
  status: number,
  path: string,
  errors: CfMessage[],
  retryAfter?: number,
): CfApiError {
  if (errors.some((e) => e.code === NOT_ALLOWED_CODE)) return new NotAllowedError(path);
  if (status === 429) return new RateLimitedError(path, errors, retryAfter ?? 300);
  if (status === 403 || status === 401 || errors.some((e) => PERMISSION_CODES.has(e.code))) {
    return new NoPermissionError(status, path, errors);
  }
  if (status === 404) return new NotFoundError(status, path, errors);
  return new CfApiError(status, path, errors);
}
