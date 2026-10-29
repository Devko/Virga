import { vi } from "vitest";

/** Test-only master key: bytes 1..32, base64. */
export const TEST_MASTER_KEY = btoa(
  String.fromCharCode(...Array.from({ length: 32 }, (_, i) => i + 1)),
);

/** A second test-only key for rotation tests. */
export const NEXT_MASTER_KEY = btoa(
  String.fromCharCode(...Array.from({ length: 32 }, (_, i) => 255 - i)),
);

/**
 * A fake account token in the documented `cfat_` format (prefix, 40
 * characters, checksum). Distinctive so the leak test can search for it.
 */
export const TEST_TOKEN = "cfat_Zq8LEAKCANARYx9Rt2Vw7Kp4Mn6Bv1Cx3Hj5Ld0Fs8Wq2e9";

export interface RecordedCall {
  method: string;
  url: URL;
  authorization: string | null;
  redirect: string;
  body: string | null;
}

export type Route = (call: RecordedCall) => Response | Promise<Response>;

export function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/** The v4 envelope around a result. */
export const ok = (result: unknown) => ({ success: true, errors: [], messages: [], result });

export const cfError = (code: number, message: string) => ({
  success: false,
  errors: [{ code, message }],
  messages: [],
  result: null,
});

/**
 * Replaces the global fetch, which the broker shares with the tests (the
 * main Worker runs in the test isolate). Routes are keyed `METHOD /path`
 * relative to /client/v4. Anything else fails the request.
 */
export function mockCloudflare(routes: Record<string, Route>) {
  const calls: RecordedCall[] = [];
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const call: RecordedCall = {
      method: request.method,
      url,
      authorization: request.headers.get("authorization"),
      redirect: request.redirect,
      body: request.method === "POST" ? await request.text() : null,
    };
    calls.push(call);
    if (url.origin !== "https://api.cloudflare.com" || !url.pathname.startsWith("/client/v4/")) {
      throw new TypeError("unexpected host in test");
    }
    const route = routes[`${request.method} ${url.pathname.slice("/client/v4".length)}`];
    if (!route) return json(404, cfError(7003, "No route for that URI"));
    return route(call);
  });
  return { calls, spy };
}
