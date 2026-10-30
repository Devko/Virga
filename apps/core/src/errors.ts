const MAX_DETAIL = 500;

/**
 * A short description of an error for coverage rows and scan summaries.
 * It may quote Cloudflare API messages and paths, so it is untrusted text.
 */
export function describe(error: unknown): string {
  const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  return text.length > MAX_DETAIL ? `${text.slice(0, MAX_DETAIL)}…` : text;
}

const STALE_SCAN = "StaleScanError";

/**
 * The graph refused a write because the scan is no longer the running scan
 * of its account: it was marked failed as stale, it ended, or a newer scan
 * took over. A retry cannot fix that, so the scan stops.
 */
export class StaleScanError extends Error {
  constructor(scanId: string) {
    super(`scan ${scanId.slice(0, 100)} is not the running scan of its account`);
    this.name = STALE_SCAN;
  }
}

/** Also true on the far side of RPC, which keeps an error's name but not its class. */
export const isStaleScanError = (error: unknown): boolean =>
  error instanceof Error && error.name === STALE_SCAN;
