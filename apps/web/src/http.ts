// No inline scripts or styles anywhere: the SPA is built into files under /assets.
export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Content-Security-Policy": CSP,
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "Strict-Transport-Security": "max-age=31536000",
};

/** The response with the security headers set; asset responses may have immutable headers. */
export function secure(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...SECURITY_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

export const error = (status: number, code: string) => json({ error: code }, status);

/**
 * Logs a failure by error name only: messages from RPC callees can quote
 * tokens (onboarding) or text from scanned accounts.
 */
export function logFailure(what: string, cause: unknown): void {
  console.error(`${what} failed`, cause instanceof Error ? cause.name : typeof cause);
}

/**
 * CSRF check for state-changing requests: a JSON body (not sendable by a
 * plain form) from this origin. Returns the refusal, or null.
 */
export function refuseCrossSite(request: Request): Response | null {
  const type = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (type !== "application/json") return error(415, "json_required");
  const origin = request.headers.get("origin");
  if (origin === null || origin !== new URL(request.url).origin) {
    return error(403, "cross_origin");
  }
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin") return error(403, "cross_origin");
  return null;
}

export const MAX_BODY = 16_384;

/** The body's bytes, or null when it is larger than `max`. */
export async function readLimited(
  body: ReadableStream<Uint8Array>,
  max: number,
): Promise<Uint8Array | null> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/** The parsed JSON body, or a refusal when it is too large or not JSON. */
export async function readJson(
  request: Request,
  max = MAX_BODY,
): Promise<{ ok: true; value: unknown } | { ok: false; response: Response }> {
  if (Number(request.headers.get("content-length") ?? "0") > max) {
    return { ok: false, response: error(413, "body_too_large") };
  }
  const bytes = request.body ? await readLimited(request.body, max) : new Uint8Array();
  if (bytes === null) return { ok: false, response: error(413, "body_too_large") };
  try {
    return {
      ok: true,
      value: JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes)),
    };
  } catch {
    return { ok: false, response: error(400, "invalid_json") };
  }
}
