import type {
  AccountRow,
  FindingDetail,
  FindingPage,
  FindingSeverity,
  FindingStatus,
  Neighborhood,
  Profile,
  ScanSummaryView,
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

const post = <T>(path: string, body: unknown) =>
  request<T>(path, {
    method: "POST",
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
  scan: (id: string) => post<TriggerResult>(`${account(id)}/scan`, {}),
  onboard: (input: OnboardingInput) =>
    post<{ account: AccountRow; intake: IntakeView }>("/api/accounts", input),
};
