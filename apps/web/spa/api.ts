import type {
  AccountRow,
  FindingDetail,
  FindingPage,
  FindingSeverity,
  FindingStatus,
  Neighborhood,
  Profile,
  ScanSummaryView,
  ToolCallPage,
  TriggerResult,
} from "../src/rpc.ts";

/** Client for the Worker's JSON API. Same origin; the Access cookie authenticates. */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly body: unknown;

  constructor(status: number, code: string, body: unknown) {
    super(`${status} ${code}`);
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { accept: "application/json", ...init?.headers },
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const code =
      body && typeof body === "object" && "error" in body ? String(body.error) : "request_failed";
    throw new ApiError(response.status, code, body);
  }
  return body as T;
}

// A JSON body even where none is needed: the API's CSRF check requires one.
const send = <T>(method: "POST" | "DELETE", path: string, body: unknown) =>
  request<T>(path, {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

const account = (id: string) => `/api/accounts/${encodeURIComponent(id)}`;

export interface Me {
  email: string | null;
  serviceToken: string | null;
  admin: boolean;
}

export interface IntakeView {
  ok: boolean;
  stored: boolean;
  retryable: boolean;
  tokenId: string | null;
  expiresOn: string | null;
  permissionGroups: string[];
  reasons: { code: string; message: string }[];
  warnings: { code: string; message: string }[];
}

/** Answer of DELETE /api/accounts/{id}; null where that step failed or did not run. */
export interface RemovalView {
  token: { removed: boolean } | null;
  account: { removed: boolean } | null;
}

export interface OnboardingInput {
  accountId: string;
  name: string;
  profile: Profile;
  cadenceHours: number;
  token: string;
}

export interface FindingQuery {
  status: FindingStatus[];
  severity: FindingSeverity[];
  cursor?: string;
}

export type ExportFormat = "json" | "ndjson";

/** One response of the OCSF export, ready to save. */
export interface ExportPart {
  blob: Blob;
  /** Findings in this part. */
  count: number;
  /** The URL of the next part (`Link: <…>; rel="next"`), or null after the last part. */
  next: string | null;
}

// The export only ever links to itself; anything else in the header is ignored.
const EXPORT_LINK = /^<(\/api\/accounts\/[0-9a-f]{32}\/findings\/export\?[^<>\s]*)>; rel="next"$/;

/** The next part's path from a `Link` header, if it is the export's own. */
export function nextExportPart(link: string | null): string | null {
  return EXPORT_LINK.exec(link ?? "")?.[1] ?? null;
}

export function exportPath(id: string, query: FindingQuery, format: ExportFormat): string {
  const params = new URLSearchParams();
  for (const s of query.status) params.append("status", s);
  for (const s of query.severity) params.append("severity", s);
  params.set("format", format);
  return `${account(id)}/findings/export?${params}`;
}

/** Fetches one part of the OCSF export: `path` is exportPath() or a previous part's `next`. */
export async function exportPart(path: string): Promise<ExportPart> {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { accept: "application/json, application/x-ndjson" },
  });
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    const code =
      body && typeof body === "object" && "error" in body ? String(body.error) : "request_failed";
    throw new ApiError(response.status, code, body);
  }
  const count = Number(response.headers.get("virga-export-count"));
  return {
    blob: await response.blob(),
    count: Number.isSafeInteger(count) ? count : 0,
    next: nextExportPart(response.headers.get("link")),
  };
}

export const api = {
  me: () => request<Me>("/api/me"),
  accounts: () => request<AccountRow[]>("/api/accounts"),
  summary: (id: string) => request<ScanSummaryView>(account(id)),
  findings(id: string, query: FindingQuery) {
    const params = new URLSearchParams();
    for (const s of query.status) params.append("status", s);
    for (const s of query.severity) params.append("severity", s);
    if (query.cursor) params.set("cursor", query.cursor);
    params.set("limit", "50");
    return request<FindingPage>(`${account(id)}/findings?${params}`);
  },
  finding: (id: string, fingerprint: string) =>
    request<FindingDetail>(`${account(id)}/finding?${new URLSearchParams({ fingerprint })}`),
  neighborhood: (id: string, node: string, depth: number) =>
    request<Neighborhood>(
      `${account(id)}/neighborhood?${new URLSearchParams({ node, depth: String(depth), limit: "150" })}`,
    ),
  scan: (id: string) => send<TriggerResult>("POST", `${account(id)}/scan`, {}),
  onboard: (input: OnboardingInput) =>
    send<{ account: AccountRow; intake: IntakeView }>("POST", "/api/accounts", input),
  remove: (id: string) => send<RemovalView>("DELETE", account(id), { confirm: id }),
  /** The tool audit trail, newest first; admins only. */
  audit: (cursor?: string) =>
    request<ToolCallPage>(
      `/api/audit?${new URLSearchParams(cursor ? { limit: "100", cursor } : { limit: "100" })}`,
    ),
};
