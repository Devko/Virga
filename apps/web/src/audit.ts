import type { Identity } from "./auth.ts";
import { logFailure } from "./http.ts";
import { type Channel, coreAdmin, isAccountId, type ToolCall } from "./rpc.ts";

/**
 * The tool audit trail (design spec, "Audit trail"): one entry per API
 * request and per MCP tool call, written to core's `tool_audit` table
 * after the answer is ready. An entry holds the Access identity, the
 * channel, a route template or tool name, a checked account ID and the
 * outcome: never a raw URL, a body, a header value or a token. A write that
 * fails is logged by error name and never changes the answer.
 */

interface Waiter {
  waitUntil(promise: Promise<unknown>): void;
}

const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const ACCOUNT_VIEWS = new Set(["findings", "finding", "neighborhood", "scan"]);
const COLLECTIONS = new Set(["me", "accounts", "audit"]);
// As in the Access check and in core's table.
const MAX_IDENTITY = 320;

/** The route template an API request matched, and its account ID; `unmatched` otherwise. */
export function apiAction(
  method: string,
  parts: readonly string[],
): { action: string; accountId: string | null } {
  const verb = METHODS.has(method) ? method : "OTHER";
  const [collection = "", id, view, ...rest] = parts;
  const accountId = collection === "accounts" && isAccountId(id) ? id : null;
  let template = "unmatched";
  if (parts.length === 1 && COLLECTIONS.has(collection)) template = `/api/${collection}`;
  else if (accountId !== null && view === undefined) template = "/api/accounts/{id}";
  else if (accountId !== null && view !== undefined && rest.length === 0) {
    if (ACCOUNT_VIEWS.has(view)) template = `/api/accounts/{id}/${view}`;
  } else if (accountId !== null && view === "findings" && rest.length === 1) {
    if (rest[0] === "export") template = "/api/accounts/{id}/findings/export";
  }
  return { action: `${verb} ${template}`, accountId };
}

/**
 * `ui` for the SPA's own requests, `api` for everything else. Browsers set
 * `Sec-Fetch-Site`, but any client can, so the channel describes the call
 * and only the identity is verified.
 */
export const channelOf = (request: Request): Channel =>
  request.headers.get("sec-fetch-site") === "same-origin" ? "ui" : "api";

/** The identity as the trail records it: the email, else the service token's client ID. */
export function actorOf(identity: Identity): Pick<ToolCall, "identity" | "identityType"> {
  return identity.email !== null
    ? { identity: identity.email.slice(0, MAX_IDENTITY), identityType: "email" }
    : {
        identity: (identity.serviceToken ?? "").slice(0, MAX_IDENTITY),
        identityType: "service_token",
      };
}

/** Writes one entry; resolves when it is written or its failure is logged. */
export function writeToolCall(env: Env, entry: ToolCall): Promise<void> {
  return Promise.resolve()
    .then(() => coreAdmin(env).recordToolCall(entry))
    .then(
      () => undefined,
      (cause: unknown) => logFailure("audit: record", cause),
    );
}

/** Writes one entry after the answer, without holding it up. */
export function recordToolCall(env: Env, ctx: Waiter, entry: ToolCall): void {
  ctx.waitUntil(writeToolCall(env, entry));
}

/** Records an API request with the status it was answered with. */
export function recordApiCall(
  env: Env,
  ctx: Waiter,
  identity: Identity,
  request: Request,
  parts: readonly string[],
  status: number,
): void {
  const { action, accountId } = apiAction(request.method, parts);
  recordToolCall(env, ctx, {
    ...actorOf(identity),
    channel: channelOf(request),
    action,
    accountId,
    outcome: String(status),
  });
}
