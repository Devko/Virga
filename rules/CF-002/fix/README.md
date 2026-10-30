# CF-002 fix proposals

1. Turn on Worker-level Access, which covers routes, Custom Domains, `workers.dev` and preview URLs of the Worker.
2. Close entry points nobody needs: `workers_dev = false` and `preview_urls = false` in the Wrangler configuration, and remove extra routes or domains.
3. Hostname and path apps on the Worker's domains take precedence over Worker-level Access. Remove Bypass and Everyone policies from them, or narrow them to paths that really are public.
4. Validate the Access JWT in the Worker (the `Cf-Access-Jwt-Assertion` header, or `ctx.access`), so a request that did not pass Access is rejected even when an entry point is open.

## Templates

[`wrangler.snippet.jsonc`](wrangler.snippet.jsonc) and [`terraform.snippet.tf`](terraform.snippet.tf) are templates, not diffs (A-14): Virga does not see your Wrangler or Terraform files. Copy what applies into your own configuration and adapt:

- the Worker name, hostnames and IDs in angle brackets;
- the routes: keep only those an Access app protects;
- for Worker-level Access (Terraform option 2), the Worker's ID and your own Allow policy.

The test range shows the fix: case `cf002-seeded` has `workers.dev` on next to a Custom Domain behind Access, and `cf002-clean` turns `workers.dev` and preview URLs off, as these templates do ([cf002.tf](../../../infra/test-range/cf002.tf), [cases.yaml](../../../infra/test-range/cases.yaml)).
