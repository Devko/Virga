import { McpServer, type RequestId } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { actorOf, recordToolCall, writeToolCall } from "./audit.ts";
import type { Identity } from "./auth.ts";
import { logFailure, readLimited } from "./http.ts";
import {
  ACCOUNT_ID,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  type FindingFilters,
  graphReader,
  isAccountId,
} from "./rpc.ts";
import { UNTRUSTED_NOTICE, untrustedBlock } from "./untrusted.ts";

/**
 * MCP server at /mcp with read-only tools over GraphReader. Stateless: one
 * server per request (createMcpHandler). Access and the Worker's own check
 * run before it; there are no admin tools. Tool calls land in the tool
 * audit trail (src/audit.ts).
 */

const INSTRUCTIONS =
  "Virga is a read-only security graph of Cloudflare accounts. Tools return findings, " +
  `account summaries and graph neighborhoods. ${UNTRUSTED_NOTICE}`;

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, openWorldHint: false } as const;

// Smaller than the API's limits: tool output goes into a model's context.
const MCP_FINDINGS = { default: 20, max: 50 };
const MCP_NEIGHBORHOOD = { default: 40, max: 100 };

const accountId = z
  .string()
  .regex(ACCOUNT_ID)
  .describe("Cloudflare account ID (32 hex characters)");
const key = z.string().min(1).max(2048);

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

function result(data: unknown): ToolResult {
  return {
    content: [
      { type: "text", text: UNTRUSTED_NOTICE },
      { type: "text", text: untrustedBlock(data) },
    ],
  };
}

const failure = (text: string): ToolResult => ({
  content: [{ type: "text", text }],
  isError: true,
});

const NOT_FOUND = "Not found: the account is not onboarded, or the item does not exist.";

export const TOOL_NAMES = [
  "list_accounts",
  "get_scan_summary",
  "list_findings",
  "get_finding",
  "get_neighborhood",
] as const;
type ToolName = (typeof TOOL_NAMES)[number];

/** A tool call for the audit trail: `refused` when no tool ran, for example on invalid input. */
export interface ToolCallOutcome {
  tool: ToolName | "unknown_tool";
  accountId: string | null;
  outcome: "ok" | "not_found" | "error" | "refused";
}

/**
 * Tool calls that run in one request, at most; a JSON-RPC batch can hold
 * 100. A call that runs makes one GraphReader call and one audit write
 * through service bindings, and the runtime allows a request at most 32
 * Worker invocations through them. 8 calls make 8 reads, 8 writes and one
 * `refused` row (25 if each read's Durable Object counts too), so every
 * tool that runs can be recorded, and a request writes at most 9 rows.
 * Calls past the limit run nothing and get an error result.
 */
export const MAX_TOOL_CALLS = 8;

const TOO_MANY =
  `Refused: a request runs at most ${MAX_TOOL_CALLS} tool calls. ` +
  "Send the rest in another request.";

/** How the server reports tool calls to the audit trail. */
export interface ToolAudit {
  /** Asked before a tool runs; false refuses the call, and nothing runs. */
  admit(): boolean;
  /** A tool ran with this outcome, for the JSON-RPC request `request`. */
  ran(call: ToolCallOutcome, request: RequestId): void;
}

const UNAUDITED: ToolAudit = { admit: () => true, ran: () => {} };

/** The part of a tool handler's context the audit trail reads. */
type CallContext = { mcpReq: { id: RequestId } };

export function virgaMcpServer(env: Env, audit: ToolAudit = UNAUDITED): McpServer {
  const reader = graphReader(env);
  const server = new McpServer({ name: "virga", version: "0.0.0" }, { instructions: INSTRUCTIONS });

  const guarded = async (
    name: ToolName,
    accountId: string | null,
    context: CallContext,
    run: () => Promise<unknown>,
  ): Promise<ToolResult> => {
    if (!audit.admit()) return failure(TOO_MANY);
    const request = context.mcpReq.id;
    try {
      const data = await run();
      audit.ran({ tool: name, accountId, outcome: data === null ? "not_found" : "ok" }, request);
      return data === null ? failure(NOT_FOUND) : result(data);
    } catch (cause) {
      logFailure(`mcp: ${name}`, cause);
      audit.ran({ tool: name, accountId, outcome: "error" }, request);
      return failure("The graph could not be read. Try again later.");
    }
  };

  server.registerTool(
    "list_accounts",
    {
      title: "List accounts",
      description:
        "Cloudflare accounts onboarded in Virga, with status, scan profile and last scan time. " +
        "Status `removing`: a removal began and did not finish. No scan of it begins, its graph " +
        "may already be deleted, and an administrator finishes it by repeating the removal.",
      inputSchema: z.object({}),
      annotations: READ_ONLY,
    },
    (_args, context) => guarded("list_accounts", null, context, () => reader.listAccounts()),
  );

  server.registerTool(
    "get_scan_summary",
    {
      title: "Get scan summary",
      description:
        "One account's latest scan: coverage per resource class, counts of nodes, findings and " +
        "exposure, and per rule its status, hits (decided rows), undecided rows and error. " +
        "Unknown is a result: a rule that is not_evaluated, or a row that is undecided, is not " +
        "a pass. A class with coverage `partial`: some chunks were written before one failed, or " +
        "every chunk was written but one left resources out, and then its detail reads " +
        "`truncated (<count>): <reasons>`. A partial class is not swept and rules that require " +
        "it are not_evaluated, so their findings neither open nor resolve. For an account with " +
        "status `removing` the graph may already be deleted, so empty counts do not mean a " +
        "clean account.",
      inputSchema: z.object({ account_id: accountId }),
      annotations: READ_ONLY,
    },
    ({ account_id }, context) =>
      guarded("get_scan_summary", account_id, context, () => reader.getScanSummary(account_id)),
  );

  server.registerTool(
    "list_findings",
    {
      title: "List findings",
      description:
        "Findings of one account, most severe first. Filter by status and severity; pass the " +
        "returned cursor to get the next page.",
      inputSchema: z.object({
        account_id: accountId,
        status: z.array(z.enum(FINDING_STATUSES)).max(3).optional(),
        severity: z.array(z.enum(FINDING_SEVERITIES)).max(5).optional(),
        limit: z.number().int().min(1).max(MCP_FINDINGS.max).optional(),
        cursor: key.optional(),
      }),
      annotations: READ_ONLY,
    },
    ({ account_id, status, severity, limit, cursor }, context) =>
      guarded("list_findings", account_id, context, () => {
        const filters: FindingFilters = { limit: limit ?? MCP_FINDINGS.default };
        if (status?.length) filters.status = status;
        if (severity?.length) filters.severity = severity;
        if (cursor) filters.cursor = cursor;
        return reader.listFindings(account_id, filters);
      }),
  );

  server.registerTool(
    "get_finding",
    {
      title: "Get finding",
      description: "One finding with its evidence and the graph nodes it is about.",
      inputSchema: z.object({ account_id: accountId, fingerprint: key }),
      annotations: READ_ONLY,
    },
    ({ account_id, fingerprint }, context) =>
      guarded("get_finding", account_id, context, () => reader.getFinding(account_id, fingerprint)),
  );

  server.registerTool(
    "get_neighborhood",
    {
      title: "Get graph neighborhood",
      description:
        "Nodes and edges within 1 or 2 hops of a node (for example a finding's subject). " +
        "`missing` lists IDs that edges point to but that were not collected.",
      inputSchema: z.object({
        account_id: accountId,
        node_id: key,
        depth: z.number().int().min(1).max(2).optional(),
        limit: z.number().int().min(1).max(MCP_NEIGHBORHOOD.max).optional(),
      }),
      annotations: READ_ONLY,
    },
    ({ account_id, node_id, depth, limit }, context) =>
      guarded("get_neighborhood", account_id, context, () =>
        reader.getNeighborhood(account_id, node_id, {
          depth: depth ?? 1,
          limit: limit ?? MCP_NEIGHBORHOOD.default,
        }),
      ),
  );

  return server;
}

/**
 * Request bodies larger than this are refused with 413 before the MCP SDK
 * reads them (its own limit is 4 MiB). A tool call is far smaller, and every
 * call that can run was read here first, so the audit trail always knows
 * what a request asked for (R9-03).
 */
export const MAX_MCP_BODY = 65_536;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** A `tools/call` request in a body, as the audit trail names it. */
interface Attempt extends Omit<ToolCallOutcome, "outcome"> {
  /** The JSON-RPC ID, as the client sent it. */
  id: unknown;
}

function attemptOf(message: Record<string, unknown>): Attempt {
  const params = isRecord(message.params) ? message.params : {};
  const name = params.name;
  const args = isRecord(params.arguments) ? params.arguments : {};
  return {
    id: message.id,
    tool: TOOL_NAMES.includes(name as ToolName) ? (name as ToolName) : "unknown_tool",
    accountId: isAccountId(args.account_id) ? args.account_id : null,
  };
}

/**
 * The `tools/call` requests a body holds, as one message or a JSON-RPC
 * batch, in order; `too_large` for a body over MAX_MCP_BODY.
 */
async function toolCallsIn(request: Request): Promise<Attempt[] | "too_large"> {
  if (request.method !== "POST" || request.body === null) return [];
  if (Number(request.headers.get("content-length") ?? "0") > MAX_MCP_BODY) return "too_large";
  const body = request.clone().body;
  const bytes = body === null ? new Uint8Array() : await readLimited(body, MAX_MCP_BODY);
  if (bytes === null) return "too_large";
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return [];
  }
  const messages: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  return messages
    .filter((m): m is Record<string, unknown> => isRecord(m) && m.method === "tools/call")
    .map(attemptOf);
}

/** The first attempt whose request ran no tool; `ran` holds the IDs of those that did. */
function firstRefused(
  attempts: readonly Attempt[],
  ran: readonly RequestId[],
): Attempt | undefined {
  const left = [...ran];
  return attempts.find((attempt) => {
    const i = left.indexOf(attempt.id as RequestId);
    if (i !== -1) left.splice(i, 1);
    return i === -1;
  });
}

/** The MCP SDK's answer to a body over its limit, with ours. */
const tooLarge = () =>
  Response.json(
    {
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: `Payload Too Large: Request body must not exceed ${MAX_MCP_BODY} bytes`,
      },
      id: null,
    },
    { status: 413 },
  );

/**
 * Serves /mcp. A browser Origin must be the Worker's own host (the default
 * list would admit localhost pages), and no CORS headers are sent. The Host
 * is the Custom Domain that Cloudflare routed the request for.
 *
 * Every tool that runs lands in the audit trail with its outcome, at most
 * MAX_TOOL_CALLS per request. When `tools/call` requests in the body run no
 * tool (an unknown tool, invalid input, a refused Origin, past the limit),
 * one `refused` row names the first of them once the answer has ended, after
 * the rows of the tools that ran: if a write fails then, it is this one. A
 * body over MAX_MCP_BODY runs nothing and lands there as one `refused` row
 * with the tool `unknown_tool` and no account: nobody read what it asked for.
 */
export async function handleMcp(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  identity: Identity,
): Promise<Response> {
  const entry = (call: ToolCallOutcome) => ({
    ...actorOf(identity),
    channel: "mcp" as const,
    action: call.tool,
    accountId: call.accountId,
    outcome: call.outcome,
  });
  const attempts = await toolCallsIn(request);
  if (attempts === "too_large") {
    recordToolCall(env, ctx, entry({ tool: "unknown_tool", accountId: null, outcome: "refused" }));
    return tooLarge();
  }
  let admitted = 0;
  const ran: RequestId[] = [];
  const writes: Promise<void>[] = [];
  const audit: ToolAudit = {
    admit: () => ++admitted <= MAX_TOOL_CALLS,
    ran: (call, id) => {
      ran.push(id);
      const write = writeToolCall(env, entry(call));
      writes.push(write);
      ctx.waitUntil(write);
    },
  };
  const handler = createMcpHandler(() => virgaMcpServer(env, audit), {
    route: "/mcp",
    corsOptions: false,
    allowedOriginHostnames: [new URL(request.url).hostname],
  });
  const response = await handler(request, env, ctx);
  if (attempts.length > 0) {
    // The answer can stream; once it has ended, a tool that was going to run has run.
    const ended =
      response.body === null
        ? Promise.resolve()
        : response
            .clone()
            .arrayBuffer()
            .then(
              () => undefined,
              () => undefined,
            );
    ctx.waitUntil(
      ended
        .then(() => Promise.all(writes))
        .then(() => {
          const refused = firstRefused(attempts, ran);
          if (refused === undefined) return;
          const { tool, accountId } = refused;
          return writeToolCall(env, entry({ tool, accountId, outcome: "refused" }));
        }),
    );
  }
  return response;
}
