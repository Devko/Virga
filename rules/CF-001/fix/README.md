# CF-001 fix proposals

1. Update the vulnerable package to a fixed version and redeploy the Worker.
2. Until then, put Cloudflare Access in front of the Worker (Worker-level Access covers routes, Custom Domains, `workers.dev` and previews), or add a WAF rule that blocks the exploit path.
3. Remove version and preview URLs that serve old versions: `preview_urls = false` in the Wrangler configuration.

Templates for Wrangler and Terraform snippets follow in phase 4.
