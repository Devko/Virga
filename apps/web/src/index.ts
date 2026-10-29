import { handleApi } from "./api.ts";
import { authenticate } from "./auth.ts";
import { error, secure } from "./http.ts";
import { handleMcp } from "./mcp.ts";

/**
 * The web Worker: SPA, JSON API under /api and MCP at /mcp. Every request,
 * static assets included (`run_worker_first`), needs a valid Access identity
 * first; anything else gets 403.
 */
export default {
  async fetch(request, env, ctx): Promise<Response> {
    const auth = await authenticate(request, env, ctx);
    if (!auth.ok) {
      console.warn("access: refused", auth.reason);
      return error(403, "forbidden");
    }
    const { pathname } = new URL(request.url);
    if (pathname === "/api" || pathname.startsWith("/api/")) {
      return handleApi(request, env, auth.identity);
    }
    if (pathname === "/mcp") return secure(await handleMcp(request, env, ctx));
    if (request.method !== "GET" && request.method !== "HEAD") {
      return error(405, "method_not_allowed");
    }
    return secure(await env.ASSETS.fetch(request));
  },
} satisfies ExportedHandler<Env>;
