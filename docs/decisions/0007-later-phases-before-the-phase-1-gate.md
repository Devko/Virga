# 0007: Work from later phases before the phase 1 gate

- Status: accepted
- Date: 2026-10-30
- Changes: the phase order in the [implementation plan](../implementation-plan.md)

## Context

The phases are gated: each one starts when the gate of the one before has passed. The phase 0 gate needs spikes S-01 and S-05 to S-08 and a test range account, and the phase 1 gate needs real accounts. Both wait for a paid Cloudflare account, which the owner has not decided on yet. Some work from later phases needs neither: it does not depend on an API shape that nobody has observed, and it can be tested locally.

## Decision

Work from phases 2 and 4 may start before the phase 1 gate, within these limits:

- It relies on no Cloudflare API shape that has not been observed. No new collector for an endpoint without a spike or an observed response, and no container scanner before S-07.
- It runs as work packages with owned paths that do not overlap with running packages.
- The test range Terraform is written now and applied when the account exists.

The gates themselves do not change. No phase is complete, and nothing is released, before its gate and every earlier gate have passed.

## Consequences

- Code from later phases may need changes once the spikes and the test range run. Its docs say what has not been checked against the platform.
- Phase 1 leftovers (OCSF export, tool audit trail, test range, threat model) run next to it and keep priority, because they are on the path to the phase 1 gate.
