# Contributing

Virga is in the concept phase. Until phase 1 starts, the best contributions are reviews of the documents in [`docs/`](docs/), with issues for errors, gaps or platform facts that have changed.

## Developer Certificate of Origin

Every commit must be signed off under the [Developer Certificate of Origin 1.1](https://developercertificate.org/). The sign-off certifies that you wrote the change or have the right to submit it under the project's license:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds the line automatically. Commits without a sign-off cannot be merged.

## Ground rules

- **Read-only, always.** Code must never call a Cloudflare API endpoint that changes state in a scanned account. All API calls go through the credential broker and its allowlist of read calls.
- **Untrusted input.** Every string from a scanned account is untrusted: names, DNS records, policy names, code and scanner output. Validate it, limit its size, and mark it as untrusted wherever it reaches the UI, the MCP server or logs.
- **No secrets in the repository**, in fixtures, or in logs. Fixtures use synthetic or sanitized data.
- **Unknown is a result.** If a collector lacks permission or the evaluator cannot decide, report `not evaluated` or `unknown`. Never report a pass or `public` instead.

## Rules

A rule contribution contains:

- `rules/CF-xxx/rule.sql` with front matter (ID, version, title, severity, kind, required resource classes, parameters) and exactly one `SELECT` or `WITH` statement
- at least one positive and one negative fixture in `rules/CF-xxx/fixtures/`
- a fix proposal in `rules/CF-xxx/fix/`

The format is described in [docs/architecture/data-model.md](docs/architecture/data-model.md#rule-files-proposal).
