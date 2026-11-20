# 0011: The first deploy shares the owner's account

- Status: accepted
- Date: 2026-11-20
- Changes: the "dedicated tool account" prerequisite of the [operator guide](../operator/guide.md#prerequisites), for the owner's own instance until the release

## Context

The operator guide asks for a tool account that runs Virga and nothing else, because the broker holds the read tokens of every scanned account and anyone who can deploy Workers in the tool account can replace the broker and read them. The owner has one account on Workers Paid, which already runs other Workers, and no second account.

## Decision

- Virga's first deploy goes into the owner's existing Workers Paid account. That account is both the tool account and the first scanned account (dogfooding).
- Until a dedicated tool account exists, the instance stores only tokens for accounts the owner controls. No third party's account is onboarded.
- The test range still needs its own account ([test range README](../../infra/test-range/README.md)); it is never applied in this account.
- Before the first release (phase 4 gate), the instance moves to a dedicated account, or the guide is changed with a reason. The release gates run on a dedicated account.

## Consequences

- Every member of the account, and every API token with Workers Edit or Workers Scripts Edit in it (for example a CI token of another project), can deploy a changed broker and read the stored tokens. Since all stored tokens belong to accounts the owner already controls, this gives such a holder read access they could mostly get anyway; it would not be acceptable with third-party tokens.
- Before the deploy, list the account's members and its tokens with Workers write permissions, remove the ones not needed, and require security keys for the members.
- Virga's own scan of this account shows those tokens and members (CF-003, member rules), so the first scan doubles as the review.
- The other Workers share the account's plan limits and bill. Scans add Durable Object, Workflow and D1 usage; check the usage page after the first week.
- Moving later means a new deploy and onboarding every account again with new tokens, because the master key and the vault stay with the old account.
