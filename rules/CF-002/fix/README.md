# CF-002 fix proposals

1. Turn on Worker-level Access, which covers routes, Custom Domains, `workers.dev` and preview URLs of the Worker.
2. Close entry points nobody needs: `workers_dev = false` and `preview_urls = false` in the Wrangler configuration, and remove extra routes or domains.
3. Hostname and path apps on the Worker's domains take precedence over Worker-level Access. Remove Bypass and Everyone policies from them, or narrow them to paths that really are public.
4. Validate the Access JWT in the Worker (the `Cf-Access-Jwt-Assertion` header, or `ctx.access`), so a request that did not pass Access is rejected even when an entry point is open.

Templates for Wrangler and Terraform snippets follow in phase 4.
