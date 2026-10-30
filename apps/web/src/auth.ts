/**
 * Cloudflare Access check that runs on every request, in addition to the
 * Worker-level Access application in front of the Worker. It verifies the
 * application token in `Cf-Access-Jwt-Assertion` (RS256 against the team's
 * certs endpoint, `iss`, `aud`, `exp`, `nbf`) with Web Crypto, and compares
 * `ctx.access` with it when the runtime provides one.
 *
 * https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
 * https://developers.cloudflare.com/workers/configuration/cloudflare-access/
 */

import { readLimited } from "./http.ts";

export interface AccessEnv {
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
  ADMIN_EMAILS: string;
  REQUIRE_ACCESS_CONTEXT?: string;
}

export interface Identity {
  /** Email of the signed-in user, lowercase; null for a service token. */
  email: string | null;
  /** Client ID of the service token (`common_name`) for service token logins. */
  serviceToken: string | null;
  /** The email is in ADMIN_EMAILS. */
  admin: boolean;
}

export type AuthFailure =
  | "config"
  | "no_access_context"
  | "access_context_mismatch"
  | "missing_token"
  | "malformed"
  | "unsupported_algorithm"
  | "keys_unavailable"
  | "unknown_key"
  | "bad_signature"
  | "wrong_issuer"
  | "wrong_audience"
  | "wrong_type"
  | "expired"
  | "not_yet_valid"
  | "no_identity";

export type AuthResult = { ok: true; identity: Identity } | { ok: false; reason: AuthFailure };

interface AccessConfig {
  teamDomain: string;
  aud: string;
  admins: ReadonlySet<string>;
  requireContext: boolean;
}

const TEAM_DOMAIN = /^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/;
const AUD = /^[A-Za-z0-9_-]{1,256}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const MAX_TOKEN = 16_384;
const MAX_CERTS_BYTES = 65_536;
const MAX_KEYS = 16;
const CERTS_TIMEOUT_MS = 5_000;
// Tolerated clock difference between Access and this Worker.
const SKEW_S = 30;
// Access rotates its signing key every 6 weeks and keeps the previous one
// valid for 7 days, so an hour-old key set is fresh enough.
const KEYS_TTL_MS = 60 * 60 * 1000;
// Older keys are used only while the certs endpoint fails, and not past this age.
const MAX_STALE_MS = 24 * 60 * 60 * 1000;
// The keys are fetched at most this often, also for an unknown `kid`.
const REFETCH_MS = 30 * 1000;

export function accessConfig(env: AccessEnv): AccessConfig | null {
  const teamDomain = String(env.ACCESS_TEAM_DOMAIN ?? "")
    .trim()
    .replace(/\/$/, "");
  const aud = String(env.ACCESS_AUD ?? "").trim();
  if (!TEAM_DOMAIN.test(teamDomain) || !AUD.test(aud)) return null;
  const admins = new Set(
    String(env.ADMIN_EMAILS ?? "")
      .split(",")
      .map((e) => e.trim().toLowerCase())
      .filter((e) => e !== ""),
  );
  return { teamDomain, aud, admins, requireContext: env.REQUIRE_ACCESS_CONTEXT === "true" };
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function base64url(text: string): Uint8Array<ArrayBuffer> {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function jsonPart(text: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(base64url(text)),
    );
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

interface KeySet {
  keys: Map<string, CryptoKey>;
  fetchedAt: number;
}

// Per isolate, by team domain.
const keySets = new Map<string, KeySet>();
const pending = new Map<string, Promise<KeySet | null>>();
const lastFetch = new Map<string, number>();

async function importKeys(body: unknown): Promise<Map<string, CryptoKey>> {
  const keys = new Map<string, CryptoKey>();
  const list = isRecord(body) && Array.isArray(body.keys) ? body.keys.slice(0, MAX_KEYS) : [];
  for (const jwk of list) {
    if (!isRecord(jwk) || jwk.kty !== "RSA") continue;
    if (jwk.alg !== undefined && jwk.alg !== "RS256") continue;
    if (jwk.use !== undefined && jwk.use !== "sig") continue;
    const { kid, n, e } = jwk;
    if (typeof kid !== "string" || kid === "" || kid.length > 256) continue;
    if (typeof n !== "string" || typeof e !== "string") continue;
    try {
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: "RSA", n, e, alg: "RS256", ext: true },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
      keys.set(kid, key);
    } catch {
      // A key Web Crypto rejects cannot verify anything; skip it.
    }
  }
  return keys;
}

async function fetchKeys(teamDomain: string, now: number): Promise<KeySet | null> {
  lastFetch.set(teamDomain, now);
  try {
    const response = await fetch(`${teamDomain}/cdn-cgi/access/certs`, {
      headers: { accept: "application/json" },
      redirect: "manual",
      signal: AbortSignal.timeout(CERTS_TIMEOUT_MS),
    });
    if (response.status !== 200) {
      await response.body?.cancel();
      return null;
    }
    const bytes = response.body ? await readLimited(response.body, MAX_CERTS_BYTES) : null;
    if (bytes === null) return null;
    const keys = await importKeys(JSON.parse(new TextDecoder().decode(bytes)));
    if (keys.size === 0) return null;
    const set = { keys, fetchedAt: now };
    keySets.set(teamDomain, set);
    return set;
  } catch {
    return null;
  }
}

function refreshKeys(teamDomain: string, now: number): Promise<KeySet | null> {
  let running = pending.get(teamDomain);
  if (!running) {
    running = fetchKeys(teamDomain, now).finally(() => pending.delete(teamDomain));
    pending.set(teamDomain, running);
  }
  return running;
}

async function signingKey(
  teamDomain: string,
  kid: string,
  now: number,
): Promise<CryptoKey | "unavailable" | "unknown"> {
  let cached = keySets.get(teamDomain);
  if (cached && now - cached.fetchedAt >= MAX_STALE_MS) cached = undefined;
  const key = cached?.keys.get(kid);
  if (key && cached && now - cached.fetchedAt < KEYS_TTL_MS) return key;
  const recently = now - (lastFetch.get(teamDomain) ?? Number.NEGATIVE_INFINITY) < REFETCH_MS;
  const set = recently && !pending.has(teamDomain) ? null : await refreshKeys(teamDomain, now);
  // When the refresh fails, the previous keys stay in use for a while: Access
  // keeps a rotated-out key valid for 7 days.
  const found = set ? set.keys.get(kid) : key;
  if (found) return found;
  return set === null && cached === undefined ? "unavailable" : "unknown";
}

/** Forgets cached signing keys. Tests only. */
export function resetKeyCache(): void {
  keySets.clear();
  pending.clear();
  lastFetch.clear();
}

type Claims = Record<string, unknown>;

async function verifyToken(
  token: string,
  config: AccessConfig,
  now: number,
): Promise<{ ok: true; claims: Claims } | { ok: false; reason: AuthFailure }> {
  const parts = token.split(".");
  if (token.length > MAX_TOKEN || parts.length !== 3 || !parts.every((p) => BASE64URL.test(p))) {
    return { ok: false, reason: "malformed" };
  }
  const [head, body, signature] = parts as [string, string, string];
  const header = jsonPart(head);
  const claims = jsonPart(body);
  if (!header || !claims) return { ok: false, reason: "malformed" };
  if (header.alg !== "RS256") return { ok: false, reason: "unsupported_algorithm" };
  if (typeof header.kid !== "string" || header.kid === "")
    return { ok: false, reason: "malformed" };

  const key = await signingKey(config.teamDomain, header.kid, now);
  if (key === "unavailable") return { ok: false, reason: "keys_unavailable" };
  if (key === "unknown") return { ok: false, reason: "unknown_key" };
  let valid = false;
  try {
    valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      base64url(signature),
      new TextEncoder().encode(`${head}.${body}`),
    );
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "bad_signature" };

  if (claims.iss !== config.teamDomain) return { ok: false, reason: "wrong_issuer" };
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(config.aud)) return { ok: false, reason: "wrong_audience" };
  // `app` is the application token; `org` is the team domain's own session.
  if (claims.type !== undefined && claims.type !== "app")
    return { ok: false, reason: "wrong_type" };
  const seconds = now / 1000;
  if (typeof claims.exp !== "number" || claims.exp + SKEW_S <= seconds) {
    return { ok: false, reason: "expired" };
  }
  if (
    claims.nbf !== undefined &&
    (typeof claims.nbf !== "number" || claims.nbf - SKEW_S > seconds)
  ) {
    return { ok: false, reason: "not_yet_valid" };
  }
  return { ok: true, claims };
}

function identityOf(claims: Claims, config: AccessConfig): Identity | null {
  const email =
    typeof claims.email === "string" && claims.email !== "" && claims.email.length <= 320
      ? claims.email.toLowerCase()
      : null;
  // Service token logins carry the client ID in `common_name` and an empty `sub`.
  const serviceToken =
    email === null && typeof claims.common_name === "string" && claims.common_name !== ""
      ? claims.common_name.slice(0, 256)
      : null;
  if (email === null && serviceToken === null) return null;
  return { email, serviceToken, admin: email !== null && config.admins.has(email) };
}

/**
 * Decides whether a request carries a valid Access identity. Never logs or
 * returns the token; the failure reason is a fixed code.
 */
export async function authenticate(
  request: Request,
  env: AccessEnv,
  ctx: { readonly access?: { readonly aud: string } },
  now = Date.now(),
): Promise<AuthResult> {
  const config = accessConfig(env);
  if (!config) return { ok: false, reason: "config" };
  if (ctx.access) {
    if (ctx.access.aud !== config.aud) return { ok: false, reason: "access_context_mismatch" };
  } else if (config.requireContext) {
    return { ok: false, reason: "no_access_context" };
  }
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return { ok: false, reason: "missing_token" };
  const verified = await verifyToken(token, config, now);
  if (!verified.ok) return verified;
  const identity = identityOf(verified.claims, config);
  return identity ? { ok: true, identity } : { ok: false, reason: "no_identity" };
}
