import { recordApiCall } from "./audit.ts";
import type { Identity } from "./auth.ts";
import {
  EXPORT_MAX,
  type ExportFormat,
  type ExportRequest,
  exportFindings,
  FORMATS,
  refuseCrossSiteRead,
} from "./export.ts";
import { error, json, logFailure, readJson, refuseCrossSite } from "./http.ts";
import {
  coreAdmin,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  type FindingFilters,
  type FindingSeverity,
  type FindingStatus,
  graphReader,
  type IntakeResult,
  isAccountId,
  PROFILES,
  type Profile,
  type RemoveResult,
  tokenIntake,
} from "./rpc.ts";

/**
 * JSON API for the SPA under /api. Reads go to core's GraphReader; the admin
 * actions (onboarding, starting a scan, removing an account) and the audit
 * trail need an email in ADMIN_EMAILS. Values from scanned accounts pass
 * through as JSON data; the SPA renders them as text. Every request lands in
 * the tool audit trail (src/audit.ts).
 */

// GraphReader's limits (apps/core/src/graph/read.ts).
const MAX_KEY = 2048;
const FINDINGS_MAX = 200;
const NEIGHBORHOOD_MAX = 500;
const MAX_NAME = 200;
const MAX_TOKEN = 512;

class BadRequest extends Error {}

function oneOf<T extends string>(values: string[], allowed: readonly T[], what: string): T[] {
  for (const value of values) {
    if (!(allowed as readonly string[]).includes(value)) throw new BadRequest(`invalid_${what}`);
  }
  return values as T[];
}

function integer(url: URL, name: string, min: number, max: number): number | undefined {
  const raw = url.searchParams.get(name);
  if (raw === null) return undefined;
  const value = Number(raw);
  if (!/^\d+$/.test(raw) || value < min || value > max) throw new BadRequest(`invalid_${name}`);
  return value;
}

function text(url: URL, name: string, required: boolean): string | undefined {
  const value = url.searchParams.get(name);
  if (value === null || value === "") {
    if (required) throw new BadRequest(`missing_${name}`);
    return undefined;
  }
  if (value.length > MAX_KEY) throw new BadRequest(`invalid_${name}`);
  return value;
}

/** Status, severity and cursor of a findings query; the caller adds the limit. */
function findingSelection(url: URL): FindingFilters {
  const filters: FindingFilters = {};
  const status = oneOf<FindingStatus>(
    url.searchParams.getAll("status"),
    FINDING_STATUSES,
    "status",
  );
  const severity = oneOf<FindingSeverity>(
    url.searchParams.getAll("severity"),
    FINDING_SEVERITIES,
    "severity",
  );
  if (status.length > 0) filters.status = status;
  if (severity.length > 0) filters.severity = severity;
  const cursor = text(url, "cursor", false);
  if (cursor !== undefined) filters.cursor = cursor;
  return filters;
}

export function findingFilters(url: URL): FindingFilters {
  const filters = findingSelection(url);
  const limit = integer(url, "limit", 1, FINDINGS_MAX);
  if (limit !== undefined) filters.limit = limit;
  return filters;
}

export function exportRequest(url: URL, accountId: string): ExportRequest {
  const format = url.searchParams.get("format") ?? "json";
  if (!(FORMATS as readonly string[]).includes(format)) throw new BadRequest("invalid_format");
  const request: ExportRequest = {
    accountId,
    format: format as ExportFormat,
    filters: findingSelection(url),
  };
  const limit = integer(url, "limit", 1, EXPORT_MAX);
  if (limit !== undefined) request.limit = limit;
  return request;
}

// Control characters, including line breaks, have no place in a display name (as in core).
const hasControl = (s: string) =>
  [...s].some((c) => {
    const code = c.codePointAt(0) ?? 0;
    return code < 0x20 || (code >= 0x7f && code <= 0x9f);
  });

export interface Onboarding {
  accountId: string;
  token: string;
  profile: Profile;
  name: string;
  cadenceHours?: number;
}

export function parseOnboarding(body: unknown): Onboarding {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new BadRequest("invalid_body");
  }
  const input = body as Record<string, unknown>;
  if (!isAccountId(input.accountId)) throw new BadRequest("invalid_account_id");
  if (typeof input.token !== "string" || input.token === "" || input.token.length > MAX_TOKEN) {
    throw new BadRequest("invalid_token");
  }
  if (!PROFILES.includes(input.profile as Profile)) throw new BadRequest("invalid_profile");
  const name =
    input.name === undefined || input.name === null ? "" : String(input.name).slice(0, 1000);
  const trimmed = name.trim() || input.accountId;
  if (trimmed.length > MAX_NAME || hasControl(trimmed)) throw new BadRequest("invalid_name");
  const result: Onboarding = {
    accountId: input.accountId,
    token: input.token,
    profile: input.profile as Profile,
    name: trimmed,
  };
  if (input.cadenceHours !== undefined && input.cadenceHours !== null) {
    const hours = input.cadenceHours;
    if (typeof hours !== "number" || !Number.isInteger(hours) || hours < 1 || hours > 720) {
      throw new BadRequest("invalid_cadence");
    }
    result.cadenceHours = hours;
  }
  return result;
}

const capText = (value: unknown, max: number): string => String(value ?? "").slice(0, max);

/** The parts of the write check the operator needs, rebuilt field by field. */
function intakeView(result: IntakeResult) {
  const issues = (list: unknown) =>
    (Array.isArray(list) ? list : []).slice(0, 50).map((issue) => ({
      code: capText(issue?.code, 64),
      message: capText(issue?.message, 500),
    }));
  return {
    ok: result.ok === true,
    stored: result.stored === true,
    retryable: result.retryable === true,
    tokenId: typeof result.tokenId === "string" ? capText(result.tokenId, 64) : null,
    expiresOn: typeof result.expiresOn === "string" ? capText(result.expiresOn, 64) : null,
    permissionGroups: (Array.isArray(result.permissionGroups) ? result.permissionGroups : [])
      .slice(0, 200)
      .map((g) => capText(g, 200)),
    reasons: issues(result.reasons),
    warnings: issues(result.warnings),
  };
}

/** Replaces every occurrence of `secret` in the strings of `value`. */
export function scrub<T>(value: T, secret: string): T {
  if (secret === "") return value;
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return v.includes(secret) ? v.split(secret).join("[redacted]") : v;
    if (Array.isArray(v)) return v.map(walk);
    if (v !== null && typeof v === "object") {
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [walk(k), walk(x)]));
    }
    return v;
  };
  return walk(value) as T;
}

function rpcFailed(what: string, cause: unknown): Response {
  logFailure(`api: ${what}`, cause);
  return error(502, "upstream_error");
}

async function onboard(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  if (!body.ok) return body.response;
  const input = parseOnboarding(body.value);
  let intake: IntakeResult;
  try {
    intake = await tokenIntake(env).store(input.accountId, input.token, input.profile);
  } catch (cause) {
    return rpcFailed("token intake", cause);
  }
  const view = scrub(intakeView(intake), input.token);
  if (!view.stored) return json({ error: "token_rejected", intake: view }, 422);
  try {
    const account = await coreAdmin(env).addAccount({
      id: input.accountId,
      name: input.name,
      profile: input.profile,
      ...(input.cadenceHours === undefined ? {} : { cadenceHours: input.cadenceHours }),
    });
    return json({ account, intake: view }, 201);
  } catch (cause) {
    // The token is stored; submitting the form again rechecks it and retries.
    logFailure("api: add account", cause);
    return json({ error: "account_not_added", intake: view }, 502);
  }
}

// Only `removed` is passed on, rebuilt as a boolean.
const removedView = (result: RemoveResult | null | undefined): RemoveResult => ({
  removed: result?.removed === true,
});

const confirms = (body: unknown, accountId: string) =>
  typeof body === "object" &&
  body !== null &&
  !Array.isArray(body) &&
  (body as Record<string, unknown>).confirm === accountId;

/**
 * Offboarding. The broker goes first: without the token a scan that still
 * runs gets no more API access. When it fails, core is not called, so the
 * account stays listed and the removal can be repeated. When core fails, the
 * account stays listed as `removing` until a repeat finishes it (R5-08); both
 * calls are idempotent. The body must name the account, so a stray request
 * removes nothing.
 */
async function removeAccount(request: Request, env: Env, accountId: string): Promise<Response> {
  const body = await readJson(request);
  if (!body.ok) return body.response;
  if (!confirms(body.value, accountId)) throw new BadRequest("confirmation_required");
  let token: RemoveResult;
  try {
    token = removedView(await tokenIntake(env).remove(accountId));
  } catch (cause) {
    logFailure("api: token removal", cause);
    return json({ error: "token_not_removed", token: null, account: null }, 502);
  }
  try {
    const account = removedView(await coreAdmin(env).removeAccount(accountId));
    return json({ token, account });
  } catch (cause) {
    logFailure("api: account removal", cause);
    return json({ error: "account_not_removed", token, account: null }, 502);
  }
}

async function triggerScan(env: Env, accountId: string): Promise<Response> {
  const result = await coreAdmin(env).triggerScan(accountId);
  if (result.started) return json(result, 202);
  return json(result, result.reason === "unknown_account" ? 404 : 409);
}

const found = (value: unknown) => (value === null ? error(404, "not_found") : json(value));

function methodNotAllowed(allow: string): Response {
  const response = error(405, "method_not_allowed");
  response.headers.set("Allow", allow);
  return response;
}

// A cursor of the audit trail is a row ID (apps/core/src/audit.ts).
const AUDIT_CURSOR = /^[1-9][0-9]{0,15}$/;
const AUDIT_MAX = 200;

function auditQuery(url: URL): { limit?: number; cursor?: string } {
  const query: { limit?: number; cursor?: string } = {};
  const limit = integer(url, "limit", 1, AUDIT_MAX);
  if (limit !== undefined) query.limit = limit;
  const cursor = url.searchParams.get("cursor");
  if (cursor !== null) {
    if (!AUDIT_CURSOR.test(cursor)) throw new BadRequest("invalid_cursor");
    query.cursor = cursor;
  }
  return query;
}

/**
 * `read`: any identity; `download`: any identity, not for another site;
 * `admin_read`: admins only; `admin`: admins only, JSON body from this origin.
 */
type Route =
  | { kind: "read"; run: () => Promise<unknown> }
  | { kind: "download"; run: () => Promise<Response> }
  | { kind: "admin_read"; run: () => Promise<unknown> }
  | { kind: "admin"; run: () => Promise<Response> };

function route(
  method: string,
  parts: string[],
  url: URL,
  env: Env,
  request: Request,
): Route | Response {
  const reader = graphReader(env);
  const [collection, accountId, view, ...rest] = parts;
  const only = (expected: string, r: Route) =>
    method === expected ? r : methodNotAllowed(expected);

  if (collection === "audit" && accountId === undefined) {
    return only("GET", {
      kind: "admin_read",
      run: () => coreAdmin(env).listToolCalls(auditQuery(url)),
    });
  }
  if (collection === "accounts" && accountId === undefined) {
    if (method === "GET") return { kind: "read", run: () => reader.listAccounts() };
    if (method === "POST") return { kind: "admin", run: () => onboard(request, env) };
    return methodNotAllowed("GET, POST");
  }
  if (collection !== "accounts" || !isAccountId(accountId)) return error(404, "not_found");
  if (rest.length > 0) {
    if (view === "findings" && rest.length === 1 && rest[0] === "export") {
      return only("GET", {
        kind: "download",
        run: () => exportFindings(reader, exportRequest(url, accountId)),
      });
    }
    return error(404, "not_found");
  }
  switch (view) {
    case undefined:
      if (method === "GET") return { kind: "read", run: () => reader.getScanSummary(accountId) };
      if (method === "DELETE") {
        return { kind: "admin", run: () => removeAccount(request, env, accountId) };
      }
      return methodNotAllowed("GET, DELETE");
    case "findings":
      return only("GET", {
        kind: "read",
        run: () => reader.listFindings(accountId, findingFilters(url)),
      });
    case "finding":
      return only("GET", {
        kind: "read",
        run: () => reader.getFinding(accountId, text(url, "fingerprint", true) as string),
      });
    case "neighborhood":
      return only("GET", {
        kind: "read",
        run: () =>
          reader.getNeighborhood(accountId, text(url, "node", true) as string, {
            depth: integer(url, "depth", 1, 2) ?? 1,
            limit: integer(url, "limit", 1, NEIGHBORHOOD_MAX) ?? 100,
          }),
      });
    case "scan":
      return only("POST", { kind: "admin", run: () => triggerScan(env, accountId) });
    default:
      return error(404, "not_found");
  }
}

/**
 * Answers an API request of an identity that passed the Access check, then
 * records it in the tool audit trail without holding up the answer.
 */
export async function handleApi(
  request: Request,
  env: Env,
  identity: Identity,
  ctx: ExecutionContext,
): Promise<Response> {
  const parts = new URL(request.url).pathname.split("/").slice(2);
  let status = 500;
  try {
    const response = await answer(request, env, identity, parts);
    status = response.status;
    return response;
  } finally {
    recordApiCall(env, ctx, identity, request, parts, status);
  }
}

async function answer(
  request: Request,
  env: Env,
  identity: Identity,
  parts: string[],
): Promise<Response> {
  const url = new URL(request.url);
  if (parts.length === 1 && parts[0] === "me") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return json({
      email: identity.email,
      serviceToken: identity.serviceToken,
      admin: identity.admin,
    });
  }
  const matched = route(request.method, parts, url, env, request);
  if (matched instanceof Response) return matched;
  try {
    if (matched.kind === "admin") {
      const refused = refuseCrossSite(request);
      if (refused) return refused;
      if (!identity.admin) return error(403, "admin_required");
      return await matched.run();
    }
    if (matched.kind === "download") return refuseCrossSiteRead(request) ?? (await matched.run());
    if (matched.kind === "admin_read" && !identity.admin) return error(403, "admin_required");
    return found(await matched.run());
  } catch (cause) {
    if (cause instanceof BadRequest) return error(400, cause.message);
    return rpcFailed(`${request.method} ${parts[0] ?? ""}`, cause);
  }
}
