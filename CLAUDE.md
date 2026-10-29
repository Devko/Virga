# CLAUDE.md

Guidance for agents working in this repository.

## Project

Virga is an agentless, read-only CNAPP for Cloudflare accounts that runs on Cloudflare itself. It is in the concept phase; no code exists yet.

Read before changing anything:

- `docs/concept/design-spec.md`: the design spec, the source of intent. Do not edit its text; record deviations in `docs/analysis.md` or as decisions
- `docs/analysis.md`: review, verified platform facts, open decisions D-01 to D-15
- `docs/implementation-plan.md`: phases, gates, spikes S-01 to S-08, backlog, topology, layout
- `docs/architecture/data-model.md` and `schema-draft.sql`: graph schema, write path, rule format

## Non-negotiables

- **Never write to a scanned account.** Every Cloudflare API call goes through the credential broker, and the broker allows only explicit read calls (GET, plus POST for GraphQL queries). Do not add a write endpoint, not even "for setup".
- **Tokens stay in the broker.** No other Worker decrypts or calls the API with a token. Tokens never appear in Workflow state, logs, errors or test fixtures.
- **Strings from scanned accounts are untrusted.** Validate them, limit their size, and mark them as untrusted where they reach the UI, the MCP server or logs. Scanner output is untrusted too.
- **Unknown is a result.** Missing permission → `not evaluated`. An undecidable expression → exposure `unknown`. Never report these as passed or as `public`. A rule that is `not evaluated` never resolves a finding.
- **Every rule ships with positive and negative fixtures.**

## Platform facts that shape the code

These were checked on 2026-10-29; the details are in `docs/analysis.md`.

- Durable Object SQL documents only positional `?` parameters and allows at most 100 per statement. Send batches as one JSON parameter and expand them with `json_each`. Use `transactionSync()`, not `BEGIN`/`COMMIT`.
- Workflow step results are at most 1 MiB, so steps write to the graph and return counters. Instance IDs are at most 100 characters and must match `^[a-zA-Z0-9_][a-zA-Z0-9-_]*$`.
- The API allows 1,200 REST requests per 5 minutes per token, and exceeding it blocks the token for 5 minutes. GraphQL has a separate limit of 300 queries per 5 minutes.
- The inventory token profile uses the Workers Metadata Read-Only role. Workers Scripts Read reads code; D1 Read and KV Read reach data.
- Worker versions carry `package_dependencies` (`name`, `packageJsonVersion`, `installedVersion`) in the Workers API (beta). It does not separate dev from production dependencies.
- MCP: `createMcpHandler` from `agents/mcp/server`. `McpAgent` is deprecated.

## Conventions

- English for code, comments and docs.
- Use the decision (D-xx) and spike (S-xx) IDs when work relates to them. Record decisions in `docs/decisions/` (ADR style, one file per decision).
- Commits carry a DCO sign-off (`git commit -s`).
- Toolchain and commands go here once the monorepo is scaffolded (backlog item 1 in the implementation plan).
