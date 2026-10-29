// Rate limit headers of the Cloudflare API:
// https://developers.cloudflare.com/fundamentals/api/reference/limits/
// `Ratelimit: "default";r=1199;t=1` gives the remaining quota (r) and the
// seconds until the window resets (t); `retry-after` comes with a 429.

export interface RatelimitInfo {
  remaining: number;
  reset: number;
}

/** Parses `Ratelimit`. With several items, the one with the least remaining quota wins. */
export function parseRatelimit(header: string | null): RatelimitInfo | undefined {
  if (!header) return undefined;
  let best: RatelimitInfo | undefined;
  for (const item of header.split(",")) {
    let remaining: number | undefined;
    let reset = 0;
    for (const param of item.split(";").slice(1)) {
      const match = /^\s*([a-z]+)\s*=\s*(\d{1,9})\s*$/.exec(param);
      if (!match) continue;
      if (match[1] === "r") remaining = Number(match[2]);
      else if (match[1] === "t") reset = Number(match[2]);
    }
    if (remaining !== undefined && (!best || remaining < best.remaining)) {
      best = { remaining, reset };
    }
  }
  return best;
}

/** Parses `retry-after` as seconds (delta seconds or an HTTP date). */
export function parseRetryAfter(header: string | null, now: number): number | undefined {
  if (!header) return undefined;
  const value = header.trim();
  if (/^\d{1,9}$/.test(value)) return Number(value);
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - now) / 1000));
}
