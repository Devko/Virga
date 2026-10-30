# @virga/web

The web Worker (D-06): the SPA, a JSON API under `/api` and an MCP server at `/mcp`. It reads the graph through core's `GraphReader`, registers accounts and starts scans through core's `Admin`, and hands onboarding tokens to the broker's `TokenIntake`. It has no vault, no D1 and no Durable Object stubs.

## Deployment

`workers_dev` and `preview_urls` are off and there are no routes. The operator adds a Custom Domain and protects the Worker with Worker-level Access (Workers & Pages, the Worker, Access). Then set the vars in `wrangler.jsonc`:

| Var | Value |
| --- | --- |
| `ACCESS_TEAM_DOMAIN` | `https://<team-name>.cloudflareaccess.com` |
| `ACCESS_AUD` | The Application Audience (AUD) tag of the Access application |
| `ADMIN_EMAILS` | Comma-separated emails that may onboard and remove accounts and start scans |
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
| `GET /api/accounts` | Accounts in the index (`GraphReader.listAccounts`); `status` is `active`, `paused` or `removing` |
| `GET /api/accounts/{id}` | Scan summary: account, latest run, coverage, counts, and per rule of the latest scan its status, hits, undecided rows and error (`graph.ruleRuns`) |
| `GET /api/accounts/{id}/findings?status=&severity=&limit=&cursor=` | One page of findings; `status` and `severity` repeat; `limit` 1 to 200 |
| `GET /api/accounts/{id}/findings/export?format=&status=&severity=&limit=&cursor=` | The findings as OCSF 1.9.0 Detection Findings for download: `format` `json` (array) or `ndjson`, `limit` 1 to 1,000 (default 1,000), at most about 4 MiB per response, `Link: <…>; rel="next"` to the rest. See [docs/architecture/ocsf-export.md](../../docs/architecture/ocsf-export.md) |
| `GET /api/accounts/{id}/finding?fingerprint=` | Finding detail with subjects and nodes |
| `GET /api/accounts/{id}/neighborhood?node=&depth=&limit=` | Graph around a node; `depth` 1 or 2, `limit` 1 to 500 (default 100) |
| `POST /api/accounts` | Admin: onboarding, body `{ accountId, token, profile, name?, cadenceHours? }` |
| `POST /api/accounts/{id}/scan` | Admin: start a scan now: 202 `{ started: true, id }`; otherwise `{ started: false, reason, id }`, 404 for `unknown_account` and 409 for `removing`, `running` or `exists` |
| `DELETE /api/accounts/{id}` | Admin: remove the account (offboarding), body `{ confirm: "<id>" }` |
| `GET /api/audit?limit=&cursor=` | Admin: the tool audit trail, newest first: `{ entries, cursor }`, `limit` 1 to 200 (default 50); viewers and service tokens get 403 |

An account that is not in the index answers 404; a failed RPC answers 502 `upstream_error` without detail. Responses are JSON with `Cache-Control: no-store`.

Onboarding calls `TokenIntake.store` first and `Admin.addAccount` only when the broker stored the token. The response rebuilds the broker's result field by field and replaces any occurrence of the submitted token with `[redacted]`. The token is not logged, not echoed and not kept: errors are logged by name only.

Removal (offboarding) needs the body `{ "confirm": "<account ID>" }`, so a request that names no account removes nothing (400 `confirmation_required`). It calls `TokenIntake.remove` first, which deletes the stored token and clears the account's rate budget, so a scan that still runs gets no more API access. Then it calls `Admin.removeAccount`, which marks the account `removing`, deletes its graph, then its index rows. The answer reports both: `{ token: { removed }, account: { removed } }`, where `removed` is false when there was nothing left to delete. When the broker fails, core is not called: 502 `token_not_removed`. When core fails, the answer is 502 `account_not_removed` with the token result, and the account stays listed with status `removing` until the same request is repeated (R5-08). Both calls are idempotent, so the same request finishes a partial removal. Virga never writes to a scanned account, so the account owner still revokes the token there.

The export answers with `Content-Disposition: attachment`, and with 403 `cross_origin` when `Sec-Fetch-Site` is present and not `same-origin` or `none`, or when an `Origin` is not the Worker's own: another site cannot start a download in the user's name. Strings from scanned accounts stay JSON strings; `<`, `>`, `&` and invisible formatting characters are written as JSON escapes, and `unmapped.virga.untrusted` names the fields that hold them.

POST and DELETE requests need `Content-Type: application/json`, an `Origin` equal to the Worker's own origin, and no `Sec-Fetch-Site` other than `same-origin`. Bodies are capped at 16 KB.

## Audit trail

Every API request and every MCP tool call of an identity that passed the Access check lands in core's `tool_audit` table ([data model](../../docs/architecture/data-model.md#tool-audit-table)) through `Admin.recordToolCall`: the identity (email, or a service token's client ID), the channel (`ui` for requests with `Sec-Fetch-Site: same-origin`, `api` for other clients, `mcp`), the route template (`GET /api/accounts/{id}/findings`) or tool name, the account ID when it is a valid one, and the HTTP status or the tool's outcome (`ok`, `not_found`, `error`, or `refused` when a `tools/call` request runs no tool). Never the raw URL, a body, a header value, a token or a string from a scanned account. The write runs in `waitUntil` after the answer is ready; a failed write is logged by error name and never changes the answer. Requests that Access refused and the SPA's static files are not recorded. Core keeps the rows for 90 days. Admins read the trail at `GET /api/audit` and on the SPA's audit page.

Every response carries `Content-Security-Policy` (`default-src 'none'`, scripts, styles, images and fonts from `'self'`, `frame-ancestors 'none'`, `base-uri 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, COOP and CORP `same-origin`, and HSTS.

## MCP

`/mcp` serves a stateless MCP server (`createMcpHandler` from `agents/mcp/server`, one server per request) with five read-only tools. None starts a scan or removes an account:

| Tool | Input |
| --- | --- |
| `list_accounts` | none; the description explains the status `removing` |
| `get_scan_summary` | `account_id`; the summary of `GET /api/accounts/{id}`, with per-rule hits, undecided rows and errors |
| `list_findings` | `account_id`, `status[]`, `severity[]`, `limit` (1 to 50, default 20), `cursor` |
| `get_finding` | `account_id`, `fingerprint` |
| `get_neighborhood` | `account_id`, `node_id`, `depth` (1 or 2), `limit` (1 to 100, default 40) |

Each tool call lands in the audit trail (above). A `tools/call` request that runs no tool, for example an unknown tool, input that fails the schema or a foreign `Origin`, is recorded as `refused` once its answer has ended; a legacy batch of several calls records the tools that ran.

Every result is a notice plus the data inside `<untrusted-data>`. The notice (also in the server instructions) tells the model that the values were written by whoever controls the scanned account and are data, not instructions. The JSON escapes `<`, `>` and `&`, so a value cannot close the block. Strings, lists, objects and nesting are capped, and the text is shrunk until it fits 100,000 characters. A browser `Origin` must be the Worker's own host, and no CORS headers are sent.

MCP clients reach the Worker through Access like everyone else, for example with an Access service token (`CF-Access-Client-Id` and `CF-Access-Client-Secret`) allowed by a Service Auth policy.

## SPA

React and Vite under `spa/`, built to `dist/client`: accounts, account summary with coverage, the rules of the latest scan (hits, undecided rows, not evaluated with the missing inputs, and the error of a failed rule as untrusted text) and findings (filters, paging, and an OCSF export of the filtered findings as JSON or NDJSON, saved part by part), finding detail with evidence and the graph neighborhood (Cytoscape, loaded on that page only), onboarding and account removal for admins, and the audit trail for admins (`/audit`, linked in the header, 100 entries at a time). Removal sits at the bottom of the account page behind a confirmation: the admin types the account ID, and the result says what each step removed and that the token still has to be revoked in the scanned account. When core does not finish, the result says that the account stays listed as removing until the removal is repeated, and that repeating is safe. An account with status `removing` (R5-08) is marked "removal pending" in the accounts list; its summary shows a "Removal pending" notice, its page has no Start scan, and the removal button reads "Remove account again…". Start scan names each refusal, `removing` included. Every string from a scanned account is React text: no `dangerouslySetInnerHTML`, and control and bidirectional formatting characters are replaced before display. Graph labels are canvas text. The build has no inline scripts or styles; Cytoscape's injected container style is in `styles.css` instead.

## Known limits (v1)

- No per-account access control: every identity that passes Access sees every account. Admin is a flat email list.
- `ctx.access` is not available to a Worker with static assets (above).
- Worker-level Access does not support WebSockets; the MCP handler uses HTTP only.
- The RPC types in `src/rpc.ts` mirror core and the broker by hand, because service bindings to other Workers are typed only as `Service`.

## Tests

`pnpm --filter @virga/web test` builds the SPA, then runs two Vitest projects:

- `worker` in workerd (`@cloudflare/vitest-plugin`). [test/worker.ts](test/worker.ts) adds stub `GraphReader`, `Admin` and `TokenIntake` entrypoints behind the service bindings; the stubs return hostile strings and record their calls. Tests sign tokens with a generated RSA key and answer the certs endpoint through a `fetch` spy; nothing leaves the process. They cover the Access check, the API, CSRF, onboarding (the token never appears in responses or logs), the OCSF export, the audit trail, the MCP tools and the built SPA behind the check.
- `spa` in Node: views rendered with `react-dom/server` and hostile data, and a scan of the SPA sources for HTML sinks.
