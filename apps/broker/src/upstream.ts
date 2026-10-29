import {
  accountOfPath,
  type CfEnvelope,
  type CfGraphqlResponse,
  type CfQuery,
  type CfResponse,
  isAllowedRead,
  NOT_ALLOWED_CODE,
} from "@virga/cf-api";
import type { BudgetKind, BudgetReport } from "./budget.ts";
import { VaultError } from "./crypto.ts";
import type { BrokerEnv } from "./env.ts";
import { checkReadOnlyDocument } from "./graphql.ts";
import { parseRatelimit, parseRetryAfter } from "./headers.ts";

/**
 * The only place that sends a token to Cloudflare. Both entrypoints call
 * through here, so every request passes the read allowlist, the account
 * check and the rate budget. Nothing returned from here contains the token.
 */

export const API_BASE = "https://api.cloudflare.com/client/v4";

/** Pauses up to this long are waited out here; longer ones go back to the caller as a 429. */
export const MAX_WAIT_MS = 5_000;

// Broker error codes next to NOT_ALLOWED_CODE (99001) from @virga/cf-api.
export const BUDGET_EXHAUSTED_CODE = 99002;
export const NO_TOKEN_CODE = 99003;
export const BROKER_ERROR_CODE = 99004;

export const ACCOUNT_ID = /^[0-9a-f]{32}$/;

const QUERY_KEY = /^[A-Za-z0-9_.[\]-]{1,64}$/;
const MAX_QUERY_VALUE = 1024;
const MAX_VARIABLES = 64 * 1024;
const MAX_BODY_CHARS = 16 * 1024 * 1024;
const MAX_MESSAGE = 1000;
const DEFAULT_RETRY_AFTER = 300;

export interface Upstream {
  env: BrokerEnv;
  accountId: string;
  token: string;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const clip = (value: string, max = 200) => (value.length > max ? `${value.slice(0, max)}…` : value);

export const failure = (status: number, code: number, message: string): CfResponse<null> => ({
  status,
  body: { success: false, errors: [{ code, message }], result: null },
});

/**
 * A fixed message for errors of the broker itself. Other errors are not
 * described, since their messages could carry request details.
 */
export function brokerErrorMessage(error: unknown): string {
  if (error instanceof VaultError) return `broker vault error: ${error.message}`;
  console.error("broker: internal error", error instanceof Error ? error.name : typeof error);
  return "internal broker error";
}

export const refused = (why: string): CfResponse<null> =>
  failure(400, NOT_ALLOWED_CODE, `not on the read allowlist: ${why}`);

const graphqlFailure = (status: number, message: string): CfGraphqlResponse => ({
  status,
  data: null,
  errors: [{ message }],
});

export const graphqlRefused = (why: string): CfGraphqlResponse =>
  graphqlFailure(400, `not on the read allowlist: ${why}`);

/** Why a REST read is refused, or null if it may go out. */
export function checkRest(accountId: unknown, path: unknown, query: unknown): string | null {
  if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId)) return "invalid account ID";
  if (typeof path !== "string" || !isAllowedRead("GET", path)) {
    return `GET ${clip(String(path))}`;
  }
  const scoped = accountOfPath(path);
  if (scoped !== undefined && scoped !== accountId) {
    return `GET ${clip(path)} is not scoped to account ${accountId}`;
  }
  if (query === undefined) return null;
  if (!isRecord(query)) return "query must be an object";
  for (const [key, value] of Object.entries(query)) {
    if (!QUERY_KEY.test(key)) return `query parameter ${clip(key, 64)}`;
    if (value === undefined || typeof value === "boolean") continue;
    if (typeof value === "number" && Number.isFinite(value)) continue;
    if (typeof value === "string" && value.length <= MAX_QUERY_VALUE) continue;
    return `value of query parameter ${key}`;
  }
  return null;
}

/** Why a GraphQL request is refused, or null if it may go out. */
export function checkGraphql(
  accountId: unknown,
  query: unknown,
  variables: unknown,
): string | null {
  if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId)) return "invalid account ID";
  if (!isAllowedRead("POST", "/graphql")) return "POST /graphql";
  const document = checkReadOnlyDocument(query);
  if (!document.ok) return document.reason;
  if (variables !== undefined) {
    if (!isRecord(variables)) return "variables must be an object";
    let size: number;
    try {
      size = JSON.stringify(variables).length;
    } catch {
      return "variables are not JSON";
    }
    if (size > MAX_VARIABLES) return "variables are too large";
  }
  return null;
}

function budgetOf(env: BrokerEnv, accountId: string) {
  return env.RATE_BUDGET.get(env.RATE_BUDGET.idFromName(accountId));
}

type Budget = ReturnType<typeof budgetOf>;

/** Waits for the budget, or returns the seconds the caller should wait instead. */
async function admit(budget: Budget, kind: BudgetKind): Promise<number | undefined> {
  let waited = 0;
  for (;;) {
    const decision = await budget.acquire(kind);
    if (decision.ok) return undefined;
    if (waited + decision.waitMs > MAX_WAIT_MS) {
      return Math.max(1, Math.ceil(decision.waitMs / 1000));
    }
    await scheduler.wait(decision.waitMs);
    waited += decision.waitMs;
  }
}

const exhaustedMessage = (seconds: number) =>
  `rate budget exhausted, retry after ${seconds} s (not sent to Cloudflare)`;

async function send(
  token: string,
  url: string,
  init: { method: "GET" | "POST"; headers: Record<string, string>; body?: string },
): Promise<Response | null> {
  try {
    return await fetch(url, {
      method: init.method,
      headers: { ...init.headers, authorization: `Bearer ${token}` },
      body: init.body,
      // A redirect must never carry the token to another host.
      redirect: "manual",
    });
  } catch {
    // The error could describe the request; log nothing from it.
    console.warn("broker: Cloudflare API unreachable");
    return null;
  }
}

/** Reads the body as text, capped, with every occurrence of the token removed. */
async function readText(response: Response, token: string): Promise<string | null> {
  const length = Number(response.headers.get("content-length") ?? "0");
  if (length > MAX_BODY_CHARS) {
    await response.body?.cancel();
    return null;
  }
  const text = await response.text();
  if (text.length > MAX_BODY_CHARS) return null;
  return text.includes(token) ? text.split(token).join("[redacted]") : text;
}

function report(response: Response, now: number): BudgetReport {
  const rate = parseRatelimit(response.headers.get("ratelimit"));
  return {
    status: response.status,
    ...(rate ? { remaining: rate.remaining, reset: rate.reset } : {}),
    ...(response.status === 429
      ? {
          retryAfter:
            parseRetryAfter(response.headers.get("retry-after"), now) ?? DEFAULT_RETRY_AFTER,
        }
      : {}),
  };
}

function envelopeOf(text: string | null, status: number): CfEnvelope {
  const unexpected = (what: string) => failure(status, BROKER_ERROR_CODE, what).body;
  if (text === null) return unexpected("Cloudflare response is too large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return unexpected(`Cloudflare returned a non-JSON response (HTTP ${status})`);
  }
  if (!isRecord(parsed) || typeof parsed.success !== "boolean") {
    return unexpected(`Cloudflare returned an unexpected response (HTTP ${status})`);
  }
  return {
    ...parsed,
    success: parsed.success,
    errors: Array.isArray(parsed.errors) ? parsed.errors : [],
    result: parsed.result ?? null,
  };
}

function buildUrl(path: string, query: CfQuery | undefined): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined) params.append(key, String(value));
  }
  const qs = params.toString();
  return `${API_BASE}${path}${qs ? `?${qs}` : ""}`;
}

/** One REST read with the given token. */
export async function restGet(u: Upstream, path: string, query?: CfQuery): Promise<CfResponse> {
  const refusal = checkRest(u.accountId, path, query);
  if (refusal) return refused(refusal);
  const budget = budgetOf(u.env, u.accountId);
  const wait = await admit(budget, "rest");
  if (wait !== undefined) {
    return { ...failure(429, BUDGET_EXHAUSTED_CODE, exhaustedMessage(wait)), retryAfter: wait };
  }
  const response = await send(u.token, buildUrl(path, query), {
    method: "GET",
    headers: { accept: "application/json" },
  });
  if (!response) return failure(502, BROKER_ERROR_CODE, "Cloudflare API unreachable");
  const seen = report(response, Date.now());
  await budget.report("rest", seen);
  const body = envelopeOf(await readText(response, u.token), response.status);
  return {
    status: response.status,
    body,
    ...(seen.retryAfter !== undefined ? { retryAfter: seen.retryAfter } : {}),
    ...(seen.remaining !== undefined ? { rateRemaining: seen.remaining } : {}),
  };
}

function graphqlOf(text: string | null, status: number): CfGraphqlResponse {
  if (text === null) return graphqlFailure(status, "Cloudflare response is too large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return graphqlFailure(status, `Cloudflare returned a non-JSON response (HTTP ${status})`);
  }
  if (!isRecord(parsed)) {
    return graphqlFailure(status, `Cloudflare returned an unexpected response (HTTP ${status})`);
  }
  const errors = Array.isArray(parsed.errors)
    ? parsed.errors.filter(isRecord).map((e) => ({
        message: clip(typeof e.message === "string" ? e.message : "error", MAX_MESSAGE),
        ...(Array.isArray(e.path)
          ? {
              path: e.path.filter(
                (p): p is string | number => typeof p === "string" || typeof p === "number",
              ),
            }
          : {}),
      }))
    : null;
  return { status, data: parsed.data ?? null, errors };
}

/** One GraphQL Analytics query with the given token. */
export async function graphqlPost(
  u: Upstream,
  query: string,
  variables?: Record<string, unknown>,
): Promise<CfGraphqlResponse> {
  const refusal = checkGraphql(u.accountId, query, variables);
  if (refusal) return graphqlRefused(refusal);
  const budget = budgetOf(u.env, u.accountId);
  const wait = await admit(budget, "graphql");
  if (wait !== undefined) return graphqlFailure(429, exhaustedMessage(wait));
  const response = await send(u.token, `${API_BASE}/graphql`, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ query, variables: variables ?? {} }),
  });
  if (!response) return graphqlFailure(502, "Cloudflare API unreachable");
  await budget.report("graphql", report(response, Date.now()));
  return graphqlOf(await readText(response, u.token), response.status);
}
