import { McpServer } from "@modelcontextprotocol/server";
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

type OnCall = (call: ToolCallOutcome) => void;

export function virgaMcpServer(env: Env, onCall: OnCall = () => {}): McpServer {
  const reader = graphReader(env);
  const server = new McpServer({ name: "virga", version: "0.0.0" }, { instructions: INSTRUCTIONS });

  const guarded = async (
    name: ToolName,
    accountId: string | null,
    run: () => Promise<unknown>,
  ): Promise<ToolResult> => {
    try {
      const data = await run();
      onCall({ tool: name, accountId, outcome: data === null ? "not_found" : "ok" });
      return data === null ? failure(NOT_FOUND) : result(data);
    } catch (cause) {
      logFailure(`mcp: ${name}`, cause);
      onCall({ tool: name, accountId, outcome: "error" });
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
    () => guarded("list_accounts", null, () => reader.listAccounts()),
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
    ({ account_id }) =>
      guarded("get_scan_summary", account_id, () => reader.getScanSummary(account_id)),
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
    ({ account_id, status, severity, limit, cursor }) =>
      guarded("list_findings", account_id, () => {
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
    ({ account_id, fingerprint }) =>
      guarded("get_finding", account_id, () => reader.getFinding(account_id, fingerprint)),
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
    ({ account_id, node_id, depth, limit }) =>
      guarded("get_neighborhood", account_id, () =>
        reader.getNeighborhood(account_id, node_id, {
          depth: depth ?? 1,
          limit: limit ?? MCP_NEIGHBORHOOD.default,
        }),
      ),
  );

  return server;
}

// A tool call is far smaller; a larger body is not read twice.
const MAX_CALL_BODY = 65_536;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** The tool call a request body names, if it is one JSON-RPC `tools/call` request. */
async function toolCallIn(request: Request): Promise<Omit<ToolCallOutcome, "outcome"> | null> {
  if (request.method !== "POST" || request.body === null) return null;
  const body = request.clone().body;
  const bytes = body === null ? null : await readLimited(body, MAX_CALL_BODY);
  if (bytes === null) return null;
  let message: unknown;
  try {
    message = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  if (!isRecord(message) || message.method !== "tools/call") return null;
  const params = isRecord(message.params) ? message.params : {};
  const name = params.name;
  const args = isRecord(params.arguments) ? params.arguments : {};
  return {
    tool: TOOL_NAMES.includes(name as ToolName) ? (name as ToolName) : "unknown_tool",
    accountId: isAccountId(args.account_id) ? args.account_id : null,
  };
}

/**
 * Serves /mcp. A browser Origin must be the Worker's own host (the default
 * list would admit localhost pages), and no CORS headers are sent. The Host
 * is the Custom Domain that Cloudflare routed the request for.
 *
 * Every tool that runs lands in the audit trail with its outcome. A
 * `tools/call` request that runs no tool (an unknown tool, invalid input, a
 * refused Origin) lands there as `refused` once its answer has ended.
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
  const attempted = await toolCallIn(request);
  let ran = 0;
  const handler = createMcpHandler(
    () =>
      virgaMcpServer(env, (call) => {
        ran++;
        recordToolCall(env, ctx, entry(call));
      }),
    {
      route: "/mcp",
      corsOptions: false,
      allowedOriginHostnames: [new URL(request.url).hostname],
    },
  );
  const response = await handler(request, env, ctx);
  if (attempted !== null) {
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
      ended.then(() =>
        ran === 0 ? writeToolCall(env, entry({ ...attempted, outcome: "refused" })) : undefined,
      ),
    );
  }
  return response;
}
