import { CfApiError, errorFor } from "./errors.ts";
import type { CfQuery, CfReader, CfResponse, CfTransport, PageOptions } from "./types.ts";

function check<T>(path: string, response: CfResponse<T>): CfResponse<T> {
  if (response.status >= 200 && response.status < 300 && response.body?.success !== false) {
    return response;
  }
  throw errorFor(response.status, path, response.body?.errors ?? [], response.retryAfter);
}

/** Builds a {@link CfReader} over a transport. */
export function createReader(transport: CfTransport): CfReader {
  return {
    async get<T>(path: string, query?: CfQuery): Promise<T> {
      return check(path, (await transport.get(path, query)) as CfResponse<T>).body.result;
    },

    async all<T>(path: string, query: CfQuery = {}, options: PageOptions = {}): Promise<T[]> {
      const maxPages = options.maxPages ?? 1000;
      const out: T[] = [];
      let page = 1;
      let cursor: string | undefined;
      for (let n = 0; n < maxPages; n++) {
        const q: CfQuery = cursor
          ? { ...query, cursor, per_page: query.per_page ?? options.perPage ?? 50 }
          : { ...query, page, per_page: query.per_page ?? options.perPage ?? 50 };
        const response = check(path, (await transport.get(path, q)) as CfResponse<T[] | T>);
        const result = response.body.result;
        if (!Array.isArray(result)) {
          throw new CfApiError(response.status, path, [], `expected an array result on ${path}`);
        }
        out.push(...result);
        const info = response.body.result_info;
        const next = info?.cursor ?? info?.cursors?.after;
        if (next) {
          if (result.length === 0 || next === cursor) return out;
          cursor = next;
          continue;
        }
        if (info?.total_pages !== undefined && page < info.total_pages) {
          page++;
          continue;
        }
        return out;
      }
      throw new CfApiError(0, path, [], `more than ${maxPages} pages on ${path}`);
    },

    async graphql<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
      const response = await transport.graphql(query, variables);
      if (response.status === 429) throw errorFor(429, "/graphql", []);
      if (response.errors?.length) {
        const errors = response.errors.map((e) => ({ code: 0, message: e.message }));
        const denied = errors.some((e) => /not authorized|does not have access/i.test(e.message));
        throw errorFor(denied ? 403 : response.status, "/graphql", errors);
      }
      if (response.status >= 300 || response.data === null) {
        throw errorFor(response.status, "/graphql", []);
      }
      return response.data as T;
    },
  };
}
