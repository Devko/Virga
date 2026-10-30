# 0005: A truncated collection makes coverage partial

- Status: accepted
- Date: 2026-10-30
- Changes: "Coverage per class and scan" in the graph contract
- Source: integration of round 6 (R5-06 in the [round 5 verification](../reviews/2026-10-30-verification-round-5.md))

## Context

Since round 6, the `tunnels` collector emits at most 1,000 `tunnel_hostname` nodes per tunnel and marks the tunnel `ingress_truncated`. The exposure evaluator then returns `unknown` for the entry points it did emit.

The entry points past the cap are a different matter. The chunk still succeeds, so `tunnels` coverage is `complete`. The sweep deletes the nodes that an earlier scan emitted past the cap, and CF-004 has no row for them, so their open findings resolve. A rule cannot return an undecided row for a node that is not in the graph. Anyone who can edit the tunnel's ingress could hide an exposed origin behind 1,000 harmless rules and close its finding. That breaks "unknown is a result".

## Decision

A chunk can report that it left resources of its class out (`truncated`, with a reason). A class with such a chunk gets coverage `partial`, even when every chunk was written; collection of the class continues with the next chunk.

So, while any tunnel of the account is truncated:

- the `tunnels` class is not swept, so earlier nodes and their findings stay;
- rules that require `tunnels` (CF-004, CF-010, CF-011) are `not_evaluated` for the account, and no finding of theirs opens or resolves;
- the scan ends `partial`, and the coverage row names the truncated tunnel.

## Consequences

- The response is coarse: one oversized tunnel stops three rules for the whole account. It is visible as `not evaluated` with a reason, never as a pass.
- Nodes that are not swept keep their last props until the tunnel fits the limits again.
- A finer answer (sweep everything but the entry points of truncated tunnels) needs a sweep scope in the graph write path. Revisit it if real accounts hit the limit.
- The same mechanism applies to any later collector that has to cap its output.
