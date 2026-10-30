import { error, SECURITY_HEADERS } from "./http.ts";
import { byteLength, detectionFinding, exportJson } from "./ocsf.ts";
import type { FindingFilters, GraphReaderRpc } from "./rpc.ts";

/**
 * GET /api/accounts/{id}/findings/export: the account's findings as OCSF
 * Detection Findings (src/ocsf.ts), as one JSON array or as NDJSON, for
 * download. One response holds at most `limit` findings (default and
 * maximum EXPORT_MAX) and stops after the chunk that passes
 * EXPORT_MAX_BYTES; a `Link: <…>; rel="next"` header then names the URL of
 * the rest. Strings from scanned accounts stay JSON strings.
 */

export const FORMATS = ["json", "ndjson"] as const;
export type ExportFormat = (typeof FORMATS)[number];

/** Findings in one response, at most. */
export const EXPORT_MAX = 1000;
/** Findings read from core per call: with MAX_EVIDENCE_BYTES, it bounds the overshoot. */
export const EXPORT_CHUNK = 50;
/** No chunk is read once the records reach this size. */
export const EXPORT_MAX_BYTES = 4 * 1024 * 1024;

const CONTENT_TYPES: Record<ExportFormat, string> = {
  json: "application/json; charset=utf-8",
  ndjson: "application/x-ndjson; charset=utf-8",
};

export interface ExportRequest {
  accountId: string;
  format: ExportFormat;
  /** Findings in this response; EXPORT_MAX when the request names none. */
  limit?: number;
  filters: FindingFilters;
}

/** The query that continues an export at `cursor`. */
function nextUrl(request: ExportRequest, cursor: string): string {
  const query = new URLSearchParams();
  for (const s of [request.filters.status ?? []].flat()) query.append("status", s);
  for (const s of [request.filters.severity ?? []].flat()) query.append("severity", s);
  query.set("format", request.format);
  if (request.limit !== undefined) query.set("limit", String(request.limit));
  query.set("cursor", cursor);
  return `/api/accounts/${request.accountId}/findings/export?${query}`;
}

/**
 * Fetch metadata says whether a browser sent the request from another
 * site. A download needs no CSRF protection, but another site must not
 * start one in the user's name: only the SPA, an address typed by the user
 * (`none`) and non-browser clients (no header) get the export.
 */
export function refuseCrossSiteRead(request: Request): Response | null {
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin" && site !== "none") {
    return error(403, "cross_origin");
  }
  const origin = request.headers.get("origin");
  if (origin !== null && origin !== new URL(request.url).origin) return error(403, "cross_origin");
  return null;
}

export async function exportFindings(
  reader: GraphReaderRpc,
  request: ExportRequest,
): Promise<Response> {
  const limit = request.limit ?? EXPORT_MAX;
  const records: string[] = [];
  let bytes = 0;
  let cursor = request.filters.cursor;
  let next: string | null = null;
  for (;;) {
    const filters: FindingFilters = {
      ...request.filters,
      limit: Math.min(EXPORT_CHUNK, limit - records.length),
    };
    if (cursor === undefined) delete filters.cursor;
    else filters.cursor = cursor;
    const page = await reader.listFindings(request.accountId, filters);
    if (page === null) return error(404, "not_found");
    for (const finding of page.findings) {
      const record = exportJson(detectionFinding(finding, request.accountId));
      records.push(record);
      bytes += byteLength(record) + 1;
    }
    next = page.cursor;
    if (next === null || page.findings.length === 0) {
      next = null;
      break;
    }
    if (records.length >= limit || bytes >= EXPORT_MAX_BYTES) break;
    cursor = next;
  }

  const body =
    request.format === "json"
      ? `[${records.join(",")}]`
      : records.map((record) => `${record}\n`).join("");
  const headers = new Headers({
    ...SECURITY_HEADERS,
    "Content-Type": CONTENT_TYPES[request.format],
    "Cache-Control": "no-store",
    "Content-Disposition": `attachment; filename="virga-findings-${request.accountId}.ocsf.${request.format}"`,
    "Virga-Export-Count": String(records.length),
  });
  if (next !== null) headers.set("Link", `<${nextUrl(request, next)}>; rel="next"`);
  return new Response(body, { status: 200, headers });
}
