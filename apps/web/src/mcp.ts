import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { logFailure } from "./http.ts";
import {
  ACCOUNT_ID,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  type FindingFilters,
  graphReader,
} from "./rpc.ts";
import { UNTRUSTED_NOTICE, untrustedBlock } from "./untrusted.ts";

/**
 * MCP server at /mcp with read-only tools over GraphReader. Stateless: one
 * server per request (createMcpHandler). Access and the Worker's own check
 * run before it; there are no admin tools.
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

async function guarded(name: string, run: () => Promise<unknown>): Promise<ToolResult> {
  try {
    const data = await run();
    return data === null ? failure(NOT_FOUND) : result(data);
  } catch (cause) {
    logFailure(`mcp: ${name}`, cause);
    return failure("The graph could not be read. Try again later.");
  }
}

export function virgaMcpServer(env: Env): McpServer {
  const reader = graphReader(env);
  const server = new McpServer({ name: "virga", version: "0.0.0" }, { instructions: INSTRUCTIONS });

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
    () => guarded("list_accounts", () => reader.listAccounts()),
  );

  server.registerTool(
    "get_scan_summary",
    {
      title: "Get scan summary",
      description:
        "One account's latest scan: coverage per resource class, counts of nodes, findings and " +
        "exposure, and per rule its status, hits (decided rows), undecided rows and error. " +
        "Unknown is a result: a rule that is not_evaluated, or a row that is undecided, is not " +
        "a pass. For an account with status `removing` the graph may already be deleted, so " +
        "empty counts do not mean a clean account.",
      inputSchema: z.object({ account_id: accountId }),
      annotations: READ_ONLY,
    },
    ({ account_id }) => guarded("get_scan_summary", () => reader.getScanSummary(account_id)),
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
      guarded("list_findings", () => {
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
      guarded("get_finding", () => reader.getFinding(account_id, fingerprint)),
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
      guarded("get_neighborhood", () =>
        reader.getNeighborhood(account_id, node_id, {
          depth: depth ?? 1,
          limit: limit ?? MCP_NEIGHBORHOOD.default,
        }),
      ),
  );

  return server;
}

/**
 * Serves /mcp. A browser Origin must be the Worker's own host (the default
 * list would admit localhost pages), and no CORS headers are sent. The Host
 * is the Custom Domain that Cloudflare routed the request for.
 */
export function handleMcp(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const handler = createMcpHandler(() => virgaMcpServer(env), {
    route: "/mcp",
    corsOptions: false,
    allowedOriginHostnames: [new URL(request.url).hostname],
  });
  return handler(request, env, ctx);
}
