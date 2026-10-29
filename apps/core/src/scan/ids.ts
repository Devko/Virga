/** Cloudflare account IDs, as the broker accepts them. */
export const ACCOUNT_ID = /^[0-9a-f]{32}$/;

/** Workflow instance IDs: at most 100 characters of this pattern. */
export const INSTANCE_ID = /^[a-zA-Z0-9_][a-zA-Z0-9-_]*$/;
export const INSTANCE_ID_MAX = 100;

export const isAccountId = (value: unknown): value is string =>
  typeof value === "string" && ACCOUNT_ID.test(value);

export function assertAccountId(accountId: unknown): asserts accountId is string {
  if (!isAccountId(accountId)) throw new TypeError("invalid account ID");
}

export const isInstanceId = (id: string): boolean =>
  id.length <= INSTANCE_ID_MAX && INSTANCE_ID.test(id);

const pad = (n: number, width = 2) => String(n).padStart(width, "0");

/** `yyyymmddhh` in UTC, plus `mm` when `minutes` is set. */
function stamp(at: number, minutes: boolean): string {
  const d = new Date(at);
  if (Number.isNaN(d.getTime())) throw new RangeError("invalid time");
  const hour = `${pad(d.getUTCFullYear(), 4)}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}`;
  return minutes ? `${hour}${pad(d.getUTCMinutes())}` : hour;
}

function checked(id: string): string {
  if (!isInstanceId(id)) throw new RangeError(`invalid instance ID: ${id}`);
  return id;
}

/**
 * The scheduled scan of an account in the hour of `at`. Deterministic, so a
 * second dispatch in the same hour finds the instance and skips it.
 */
export function scanInstanceId(accountId: string, at: number): string {
  assertAccountId(accountId);
  return checked(`scan-${accountId}-${stamp(at, false)}`);
}

/** A scan started by hand, deterministic per minute so a double click starts one scan. */
export function manualScanInstanceId(accountId: string, at: number): string {
  assertAccountId(accountId);
  return checked(`scan-${accountId}-${stamp(at, true)}-manual`);
}
