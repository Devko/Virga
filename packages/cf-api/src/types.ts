export type CfQueryValue = string | number | boolean;
export type CfQuery = Record<string, CfQueryValue | undefined>;

export interface CfMessage {
  code: number;
  message: string;
}

export interface CfResultInfo {
  page?: number;
  per_page?: number;
  count?: number;
  total_count?: number;
  total_pages?: number;
  cursor?: string;
  cursors?: { after?: string; before?: string };
}

/** The standard v4 response envelope. */
export interface CfEnvelope<T = unknown> {
  success: boolean;
  errors: CfMessage[];
  messages?: CfMessage[];
  result: T;
  result_info?: CfResultInfo;
}

/**
 * One raw REST response. Transports return this instead of throwing, so the
 * HTTP status survives an RPC boundary (errors thrown across RPC lose their class).
 */
export interface CfResponse<T = unknown> {
  status: number;
  body: CfEnvelope<T>;
  /** Seconds from `retry-after`, set on 429. */
  retryAfter?: number;
  /** Remaining REST quota from the `Ratelimit` header, if present. */
  rateRemaining?: number;
}

export interface CfGraphqlResponse<T = unknown> {
  status: number;
  data: T | null;
  errors: { message: string; path?: (string | number)[] }[] | null;
}

/**
 * The only way collectors reach Cloudflare. Paths are relative to
 * `https://api.cloudflare.com/client/v4` and start with `/`.
 * Implemented by the broker (real API) and by fixture transports (tests).
 */
export interface CfTransport {
  get(path: string, query?: CfQuery): Promise<CfResponse>;
  graphql(query: string, variables?: Record<string, unknown>): Promise<CfGraphqlResponse>;
}

export interface PageOptions {
  /** Page size for page-based endpoints. Default 50. */
  perPage?: number;
  /** Safety stop. Default 1,000 pages. */
  maxPages?: number;
}

/** Typed convenience layer over a transport. Throws {@link CfApiError} subclasses. */
export interface CfReader {
  /** Returns `result` of a single call. */
  get<T>(path: string, query?: CfQuery): Promise<T>;
  /** Follows page- or cursor-based pagination and concatenates array results. */
  all<T>(path: string, query?: CfQuery, options?: PageOptions): Promise<T[]>;
  /** Runs a GraphQL Analytics query and returns `data`. */
  graphql<T>(query: string, variables?: Record<string, unknown>): Promise<T>;
}
