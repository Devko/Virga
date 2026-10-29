# Temporary accounts for testing

`wrangler deploy --temporary` creates a Cloudflare account without sign-up. It lives for 60 minutes unless someone claims it. Findings from using one on 2026-10-29:

| Works | Does not work |
| --- | --- |
| Deploying Workers with Durable Objects (SQLite), KV, D1 (one database), Queues, Hyperdrive | Cron triggers (limit 0 on the plan) |
| Read calls to the REST API with the temporary token, including the Workers API (beta) | `workers.dev` from scripts: non-browser clients get a challenge page |
| `Ratelimit` headers on API responses | Workflows, R2, Containers, Access and Zero Trust, zones, account token management |

- Temporary accounts are on the Workers Free plan. Its limits (100,000 rows written per day, 10 ms CPU per request) are far below what Virga needs. The numbers they produce do not represent a paid deployment.
- Wrangler caches the account ID, the token and the claim URL in `~/.config/.wrangler/wrangler-temporary-account.toml`. The claim URL works like a password for the account; keep it out of logs and commits.
- Good use: quick checks against the API surface (field shapes, headers, error codes). Not suitable for spikes that need to invoke a Worker, or for the test range.
