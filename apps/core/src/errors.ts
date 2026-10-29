const MAX_DETAIL = 500;

/**
 * A short description of an error for coverage rows and scan summaries.
 * It may quote Cloudflare API messages and paths, so it is untrusted text.
 */
export function describe(error: unknown): string {
  const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  return text.length > MAX_DETAIL ? `${text.slice(0, MAX_DETAIL)}…` : text;
}
