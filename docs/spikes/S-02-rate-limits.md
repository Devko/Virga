# S-02: API rate limit headers

- Status: partly answered
- Date: 2026-10-29

## Observed

Every REST response from `api.cloudflare.com` to an account token carried:

```
Ratelimit: "default";r=1199;t=1
Ratelimit-Policy: "default";q=1200;w=300
```

That is a quota of 1,200 requests per 300-second window, the remaining requests (`r`), and the seconds until the window resets (`t`). It matches the documentation.

## Consequences for the rate budget object

- Read `r` and `t` from every response instead of counting requests locally. The quota is shared with the dashboard and any other client using the same token or user.
- Pace by the remaining quota and stop before `r` reaches a safety margin. A 429 blocks the token for five minutes.
- GraphQL sends no `Ratelimit` headers and has its own quota (300 queries per five minutes by default). The rate budget object needs a separate counter for it.

## Open

- Behavior near the limit and how long the block lasts in practice. Measure in the test range account, not in a customer account.
