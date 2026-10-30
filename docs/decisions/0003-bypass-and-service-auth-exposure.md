# 0003: Exposure of Bypass and Service Auth policies

- Status: accepted
- Date: 2026-10-30
- Replaces: item 3 of "Exposure semantics" in the graph contract as written in round 1
- Source: security review finding R2-01 ([report](../reviews/2026-10-30-security-review.md))

## Context

The exposure evaluator decided an app `access` when a Bypass policy's include held anything but `everyone`. A Bypass limited to `0.0.0.0/0`, a country or an IP list therefore counted as protected, and rules such as CF-004 and CF-021 resolved their findings. A false "protected" is the worst failure this tool can have.

## Decision

- **Bypass never requires an identity.**
  - A Bypass whose include holds `everyone`, or only non-identity selectors (`ip`, `geo`, `certificate`, `common_name`, `device_posture`, `service_token`, `any_valid_service_token`), is `public`, with a reason that names the limit. Require rules do not change that.
  - A Bypass with an `other` selector, or with identity selectors that a Bypass cannot evaluate, is `unknown`.
- **Service Auth** (`non_identity`):
  - Includes of `service_token`, `any_valid_service_token`, `certificate` or `common_name` are `service_auth`.
  - Includes of `everyone`, `ip`, `geo` or `other` are `unknown`.
  - An IP include of `0.0.0.0/0` or `::/0` is `public`.

## Consequences

A Bypass for an office network is reported as public. That is a false positive the operator can suppress with a reason; the alternative, a false "protected", cannot be seen at all.

On a tunnel hostname with `access_required`, a Service Auth policy for every address keeps the hostname public next to any Bypass, in any order (review R4-01, round 5). That can be a false positive: a Bypass for everyone without require or exclude rules that is evaluated first takes every request, so Access issues no token and cloudflared refuses the request. The evaluator does not model require and exclude rules or the exact order of Bypass and Service Auth policies, so it errs toward public here too.
