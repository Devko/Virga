import { isAccountId } from "./scan/ids.ts";
import type { ScanStep } from "./scan/step.ts";
import { STORE_STEP } from "./scan/step.ts";

/**
 * The tool audit trail in the account index (`tool_audit`, migration 0003):
 * one row per web API request and per MCP tool call. The web Worker sends
 * the entries; this module checks every field against a fixed shape, so no
 * request body, token, header value or string from a scanned account fits.
 */

export const IDENTITY_TYPES = ["email", "service_token"] as const;
export type IdentityType = (typeof IDENTITY_TYPES)[number];

export const CHANNELS = ["ui", "api", "mcp"] as const;
export type Channel = (typeof CHANNELS)[number];

export interface ToolCall {
  /** A lowercase email, or a service token's client ID; at most 320 characters. */
  identity: string;
  identityType: IdentityType;
  channel: Channel;
  /** A route template (`GET /api/accounts/{id}`) or an MCP tool name. */
  action: string;
  accountId: string | null;
  /** The HTTP status, or `ok`, `not_found`, `error` or `refused` for a tool call. */
  outcome: string;
}

export interface ToolCallRow extends ToolCall {
  id: number;
  at: number;
}

export interface ToolCallQuery {
  /** Default 50, at most 200. */
  limit?: number;
  /** `cursor` of the previous page: rows older than it. */
  cursor?: string;
}

export interface ToolCallPage {
  /** Newest first. */
  entries: ToolCallRow[];
  /** Pass as `cursor` for the next, older page; null on the last page. */
  cursor: string | null;
}

export const MAX_IDENTITY = 320;
export const AUDIT_PAGE = { default: 50, max: 200 };
/** Rows older than this are deleted by the hourly dispatcher. */
export const AUDIT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
/** Rows one purge statement deletes, and statements per purge step. */
export const PURGE_BATCH = 5000;
export const PURGE_ROUNDS = 20;
/** Rows one purge step deletes at most: 100,000. */
export const PURGE_STEP_ROWS = PURGE_BATCH * PURGE_ROUNDS;
/**
 * Purge steps per dispatch at most. The dispatcher runs another step while
 * the last one deleted PURGE_STEP_ROWS, so it deletes up to 5,000,000 rows an
 * hour in at most 1,000 D1 statements, far inside the Workflow limits (10,000
 * steps and 10,000 subrequests per instance).
 */
export const PURGE_STEPS = 50;

// Spaces, C0 and C1 controls, bidi embeddings, overrides and isolates, zero-width
// marks: an email or a client ID has none of them.
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching them is the point.
const NOT_IN_IDENTITY = /[\u0000-\u0020\u007f-\u00a0\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/;
// A surrogate without its partner: the string is not well-formed Unicode, and
// D1 may store U+FFFD in its place. With the `u` flag the pattern reads code
// points, so a pair is one character and does not match. The same answer as
// `!value.isWellFormed()` (ES2024), which the es2023 lib does not declare.
const LONE_SURROGATE = /\p{Surrogate}/u;
const ACTION = /^[A-Za-z0-9_ /{}.-]{1,100}$/;
const OUTCOME = /^[a-z0-9_]{1,32}$/;
const CURSOR = /^[1-9][0-9]{0,15}$/;

/** The entry rebuilt field by field, or a TypeError naming the field that does not fit. */
export function checkToolCall(input: ToolCall): ToolCall {
  if (typeof input !== "object" || input === null) throw new TypeError("invalid tool call");
  const { identity, identityType, channel, action, accountId, outcome } = input;
  if (
    typeof identity !== "string" ||
    identity === "" ||
    identity.length > MAX_IDENTITY ||
    NOT_IN_IDENTITY.test(identity) ||
    LONE_SURROGATE.test(identity)
  ) {
    throw new TypeError("invalid identity");
  }
  if (!IDENTITY_TYPES.includes(identityType)) throw new TypeError("invalid identity type");
  if (!CHANNELS.includes(channel)) throw new TypeError("invalid channel");
  if (typeof action !== "string" || !ACTION.test(action)) throw new TypeError("invalid action");
  if (accountId !== null && !isAccountId(accountId)) throw new TypeError("invalid account ID");
  if (typeof outcome !== "string" || !OUTCOME.test(outcome)) throw new TypeError("invalid outcome");
  return { identity, identityType, channel, action, accountId, outcome };
}

export async function recordToolCall(db: D1Database, input: ToolCall, at: number): Promise<void> {
  const e = checkToolCall(input);
  await db
    .prepare(
      `INSERT INTO tool_audit (at, identity, identity_type, channel, action, account_id, outcome)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(at, e.identity, e.identityType, e.channel, e.action, e.accountId, e.outcome)
    .run();
}

interface ToolCallRecord {
  id: number;
  at: number;
  identity: string;
  identity_type: IdentityType;
  channel: Channel;
  action: string;
  account_id: string | null;
  outcome: string;
}

const toolCallRow = (r: ToolCallRecord): ToolCallRow => ({
  id: r.id,
  at: r.at,
  identity: r.identity,
  identityType: r.identity_type,
  channel: r.channel,
  action: r.action,
  accountId: r.account_id,
  outcome: r.outcome,
});

/** One page of the audit trail, newest first. */
export async function listToolCalls(
  db: D1Database,
  query: ToolCallQuery = {},
): Promise<ToolCallPage> {
  const limit = query.limit ?? AUDIT_PAGE.default;
  if (!Number.isInteger(limit) || limit < 1 || limit > AUDIT_PAGE.max) {
    throw new RangeError(`limit must be 1 to ${AUDIT_PAGE.max}`);
  }
  if (query.cursor !== undefined && !CURSOR.test(query.cursor)) {
    throw new TypeError("invalid cursor");
  }
  const before = query.cursor === undefined ? null : Number(query.cursor);
  const { results } = await db
    .prepare("SELECT * FROM tool_audit WHERE ? IS NULL OR id < ? ORDER BY id DESC LIMIT ?")
    .bind(before, before, limit + 1)
    .all<ToolCallRecord>();
  const entries = results.slice(0, limit).map(toolCallRow);
  const last = entries.at(-1);
  return { entries, cursor: results.length > limit && last ? String(last.id) : null };
}

/**
 * Deletes rows from before `before`, oldest first, in batches of
 * PURGE_BATCH and at most PURGE_ROUNDS batches. Returns the number of rows
 * deleted: PURGE_STEP_ROWS when rows may be left.
 */
export async function purgeToolCalls(db: D1Database, before: number): Promise<number> {
  let deleted = 0;
  for (let round = 0; round < PURGE_ROUNDS; round++) {
    const result = await db
      .prepare(
        `DELETE FROM tool_audit WHERE id IN (
           SELECT id FROM tool_audit WHERE at < ? ORDER BY id LIMIT ?)`,
      )
      .bind(before, PURGE_BATCH)
      .run();
    const changes = result.meta.changes ?? 0;
    deleted += changes;
    if (changes < PURGE_BATCH) break;
  }
  return deleted;
}

/**
 * The dispatcher's purge: deletes audit rows older than the retention, one
 * step `audit:purge:<n>` after the other while the last one deleted a full
 * PURGE_STEP_ROWS, at most PURGE_STEPS steps. The cutoff is fixed by `at`, so
 * a replay deletes the same rows. One MCP request can write up to 100 rows
 * (a JSON-RPC batch), and audit writes are not rate limited (TM-13): the
 * purge keeps up with 5,000,000 new rows an hour on average. A burst above
 * that is deleted at that rate in the hours after it expires, so its rows
 * outlive the retention by at most their number divided by 5,000,000 hours.
 * Returns the rows deleted. A step that still fails after its retries is
 * logged and ends the purge with null; it does not fail the dispatch, and
 * the next hour goes on.
 */
export async function runAuditPurge(
  step: ScanStep,
  purge: (before: number) => Promise<number>,
  at: number,
): Promise<number | null> {
  const before = at - AUDIT_RETENTION_MS;
  let total = 0;
  try {
    for (let n = 1; n <= PURGE_STEPS; n++) {
      const deleted = await step.do(`audit:purge:${n}`, STORE_STEP, () => purge(before));
      total += deleted;
      if (deleted < PURGE_STEP_ROWS) break;
    }
    return total;
  } catch (error) {
    console.error("audit purge failed", error instanceof Error ? error.name : typeof error);
    return null;
  }
}
