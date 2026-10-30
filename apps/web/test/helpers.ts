import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { vi } from "vitest";
import { resetKeyCache } from "../src/auth.ts";
import worker from "../src/index.ts";
import { ORIGIN, TEST_ACCESS, VIEWER } from "./config.ts";

/** An RSA key pair standing in for the Access team's signing key. */
interface Signer {
  kid: string;
  privateKey: CryptoKey;
  jwk: JsonWebKey;
}

const RSA = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

export async function newSigner(kid: string): Promise<Signer> {
  const pair = (await crypto.subtle.generateKey(RSA, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return { kid, privateKey: pair.privateKey, jwk };
}

const encoder = new TextEncoder();
const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const part = (value: object) => b64url(encoder.encode(JSON.stringify(value)));

export async function sign(signer: Signer, claims: object, header: object = {}): Promise<string> {
  const head = part({ alg: "RS256", kid: signer.kid, typ: "JWT", ...header });
  const body = part(claims);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    signer.privateKey,
    encoder.encode(`${head}.${body}`),
  );
  return `${head}.${body}.${b64url(new Uint8Array(signature))}`;
}

export const nowS = () => Math.floor(Date.now() / 1000);

/** Claims of an identity login, as in the Access application token docs. */
export function claims(email: string | null, extra: object = {}): Record<string, unknown> {
  return {
    aud: [TEST_ACCESS.ACCESS_AUD],
    ...(email === null ? {} : { email }),
    exp: nowS() + 300,
    iat: nowS() - 10,
    nbf: nowS() - 10,
    iss: TEST_ACCESS.ACCESS_TEAM_DOMAIN,
    type: "app",
    identity_nonce: "6ei69kawdKzMIAPF",
    sub: email === null ? "" : "7335d417-61da-459d-899c-0a01c76a2f94",
    country: "US",
    ...extra,
  };
}

export const CERTS_URL = `${TEST_ACCESS.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`;

/**
 * Answers the team's certs endpoint with these signers' public keys; every
 * other outbound fetch fails the test. Returns the spy to count calls.
 */
export function serveCerts(...signers: Signer[]) {
  resetKeyCache();
  const spy = vi.spyOn(globalThis, "fetch");
  spy.mockImplementation(async (input) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== CERTS_URL) throw new Error(`unexpected fetch to ${url}`);
    return Response.json({
      keys: signers.map((s) => ({ ...s.jwk, kid: s.kid, alg: "RS256", use: "sig" })),
    });
  });
  return spy;
}

let defaultSigner: Promise<Signer> | undefined;
export const signer = () => {
  defaultSigner ??= newSigner("test-key-1");
  return defaultSigner;
};

export async function tokenFor(email: string | null = VIEWER, extra: object = {}) {
  return sign(await signer(), claims(email, extra));
}

export interface CallOptions {
  method?: string;
  token?: string | null;
  body?: unknown;
  headers?: Record<string, string>;
  /** Sends no Origin with a body, like a non-browser client. */
  noOrigin?: boolean;
  /** Simulates the runtime's ctx.access. */
  access?: { aud: string };
}

/** Calls the Worker's fetch handler directly, so ctx.access can be set. */
export async function call(path: string, options: CallOptions = {}): Promise<Response> {
  const headers = new Headers(options.headers);
  if (options.token) headers.set("Cf-Access-Jwt-Assertion", options.token);
  const method = options.method ?? (options.body === undefined ? "GET" : "POST");
  if (options.body !== undefined) {
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
    if (!headers.has("origin") && !options.noOrigin) headers.set("origin", ORIGIN);
  }
  const request = new Request(`${ORIGIN}${path}`, {
    method,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const ctx = createExecutionContext();
  const withAccess = options.access
    ? ({
        waitUntil: (p: Promise<unknown>) => ctx.waitUntil(p),
        passThroughOnException: () => ctx.passThroughOnException(),
        props: {},
        access: { aud: options.access.aud, getIdentity: async () => undefined },
      } as unknown as ExecutionContext)
    : ctx;
  const response = await worker.fetch(
    request as Parameters<typeof worker.fetch>[0],
    env,
    withAccess,
  );
  await waitOnExecutionContext(ctx);
  return response;
}

/** Collects console output so tests can assert that a secret never reaches the logs. */
export function captureLogs(): { text: () => string; restore: () => void } {
  const lines: string[] = [];
  const spies = (["log", "info", "warn", "error", "debug"] as const).map((level) =>
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
      lines.push(
        args.map((a) => (a instanceof Error ? `${a.name} ${a.message}` : String(a))).join(" "),
      );
    }),
  );
  return {
    text: () => lines.join("\n"),
    restore: () => {
      for (const spy of spies) spy.mockRestore();
    },
  };
}
