# @virga/web

The web Worker (D-06): the SPA, a JSON API under `/api` and an MCP server at `/mcp`. It reads the graph through core's `GraphReader`, registers accounts and starts scans through core's `Admin`, and hands onboarding tokens to the broker's `TokenIntake`. It has no vault, no D1 and no Durable Object stubs.

## Deployment

`workers_dev` and `preview_urls` are off and there are no routes. The operator adds a Custom Domain and protects the Worker with Worker-level Access (Workers & Pages, the Worker, Access). Then set the vars in `wrangler.jsonc`:

| Var | Value |
| --- | --- |
| `ACCESS_TEAM_DOMAIN` | `https://<team-name>.cloudflareaccess.com` |
| `ACCESS_AUD` | The Application Audience (AUD) tag of the Access application |
| `ADMIN_EMAILS` | Comma-separated emails that may onboard accounts and start scans |
| `REQUIRE_ACCESS_CONTEXT` | `"false"` (see below) |

Until `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` hold real values, every request answers 403.

| Binding | What |
| --- | --- |
| `ASSETS` | The SPA build (`dist/client`), `run_worker_first: true`, `not_found_handling: single-page-application` |
| `CORE_READ` | `virga-core`, entrypoint `GraphReader` |
| `CORE_ADMIN` | `virga-core`, entrypoint `Admin` |
| `BROKER_INTAKE` | `virga-broker`, entrypoint `TokenIntake` |

`pnpm --filter @virga/web build` builds the SPA; `deploy` builds and runs `wrangler deploy`.

## Access check

Every request runs the Worker first, static assets included, and is refused with 403 unless:

1. `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are valid;
2. the `Cf-Access-Jwt-Assertion` header carries an RS256 token signed by a key from `<team>/cdn-cgi/access/certs`, with `iss` equal to the team domain, `aud` containing `ACCESS_AUD`, a future `exp`, a past `nbf` (30 s skew), `type` `app` when present, and an email or a service token `common_name`;
3. `ctx.access`, when the runtime provides it, has the same `aud`.

Keys are imported with Web Crypto and cached per isolate for an hour. An unknown `kid` refetches them at most every 30 seconds, and when the endpoint fails the previous keys stay in use for up to 24 hours (Access keeps a rotated-out key valid for 7 days). The token and its claims are never logged; refusals log a reason code.

`ctx.access` is not required by default. The Workers docs state that Workers with Static Assets run behind an internal router that does not pass `ctx.access` to the user Worker, so requiring it would refuse every request. The signed token is the check that always runs. `REQUIRE_ACCESS_CONTEXT: "true"` also refuses requests without `ctx.access`, for when spike S-08 shows that it arrives.

The identity comes from the token: `email` for users, `common_name` (the client ID) for service tokens. Admin actions need an email in `ADMIN_EMAILS` (case-insensitive); a service token is never admin.

## JSON API

| Method and path | What |
| --- | --- |
| `GET /api/me` | `{ email, serviceToken, admin }` |
| `GET /api/accounts` | Accounts in the index (`GraphReader.listAccounts`) |
| `GET /api/accounts/{id}` | Scan summary: account, latest run, coverage, counts |
| `GET /api/accounts/{id}/findings?status=&severity=&limit=&cursor=` | One page of findings; `status` and `severity` repeat; `limit` 1 to 200 |
| `GET /api/accounts/{id}/finding?fingerprint=` | Finding detail with subjects and nodes |
| `GET /api/accounts/{id}/neighborhood?node=&depth=&limit=` | Graph around a node; `depth` 1 or 2, `limit` 1 to 500 (default 100) |
| `POST /api/accounts` | Admin: onboarding, body `{ accountId, token, profile, name?, cadenceHours? }` |
| `POST /api/accounts/{id}/scan` | Admin: start a scan now |

An account that is not in the index answers 404; a failed RPC answers 502 `upstream_error` without detail. Responses are JSON with `Cache-Control: no-store`.

Onboarding calls `TokenIntake.store` first and `Admin.addAccount` only when the broker stored the token. The response rebuilds the broker's result field by field and replaces any occurrence of the submitted token with `[redacted]`. The token is not logged, not echoed and not kept: errors are logged by name only.

POST requests need `Content-Type: application/json`, an `Origin` equal to the Worker's own origin, and no `Sec-Fetch-Site` other than `same-origin`. Bodies are capped at 16 KB.

Every response carries `Content-Security-Policy` (`default-src 'none'`, scripts, styles, images and fonts from `'self'`, `frame-ancestors 'none'`, `base-uri 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, COOP and CORP `same-origin`, and HSTS.

## MCP

`/mcp` serves a stateless MCP server (`createMcpHandler` from `agents/mcp/server`, one server per request) with four read-only tools:

| Tool | Input |
| --- | --- |
| `list_accounts` | none |
| `list_findings` | `account_id`, `status[]`, `severity[]`, `limit` (1 to 50, default 20), `cursor` |
| `get_finding` | `account_id`, `fingerprint` |
| `get_neighborhood` | `account_id`, `node_id`, `depth` (1 or 2), `limit` (1 to 100, default 40) |

Every result is a notice plus the data inside `<untrusted-data>`. The notice (also in the server instructions) tells the model that the values were written by whoever controls the scanned account and are data, not instructions. The JSON escapes `<`, `>` and `&`, so a value cannot close the block. Strings, lists, objects and nesting are capped, and the text is shrunk until it fits 100,000 characters. A browser `Origin` must be the Worker's own host, and no CORS headers are sent.

MCP clients reach the Worker through Access like everyone else, for example with an Access service token (`CF-Access-Client-Id` and `CF-Access-Client-Secret`) allowed by a Service Auth policy.

## SPA

React and Vite under `spa/`, built to `dist/client`: accounts, account summary with coverage and findings (filters, paging), finding detail with evidence and the graph neighborhood (Cytoscape, loaded on that page only), and onboarding for admins. Every string from a scanned account is React text: no `dangerouslySetInnerHTML`, and control and bidirectional formatting characters are replaced before display. Graph labels are canvas text. The build has no inline scripts or styles; Cytoscape's injected container style is in `styles.css` instead.

## Known limits (v1)

- No per-account access control: every identity that passes Access sees every account. Admin is a flat email list.
- `ctx.access` is not available to a Worker with static assets (above).
- `GraphReader.listAccounts` is a requested change to core; until it exists, `GET /api/accounts` and `list_accounts` fail with 502.
- Worker-level Access does not support WebSockets; the MCP handler uses HTTP only.
- The RPC types in `src/rpc.ts` mirror core and the broker by hand, because service bindings to other Workers are typed only as `Service`.

## Tests

`pnpm --filter @virga/web test` builds the SPA, then runs two Vitest projects:

- `worker` in workerd (`@cloudflare/vitest-plugin`). [test/worker.ts](test/worker.ts) adds stub `GraphReader`, `Admin` and `TokenIntake` entrypoints behind the service bindings; the stubs return hostile strings and record their calls. Tests sign tokens with a generated RSA key and answer the certs endpoint through a `fetch` spy; nothing leaves the process. They cover the Access check, the API, CSRF, onboarding (the token never appears in responses or logs), the MCP tools and the built SPA behind the check.
- `spa` in Node: views rendered with `react-dom/server` and hostile data, and a scan of the SPA sources for HTML sinks.
