# Spikes

Results of the phase 0 spikes from the [implementation plan](../implementation-plan.md#phase-0-decisions-and-spikes).

| Spike | Topic | Status |
| --- | --- | --- |
| S-01 | Workflows: schedules, instance IDs, limits | Docs checked (see analysis); not run |
| [S-02](S-02-rate-limits.md) | API rate limit headers | Partly answered |
| [S-03](S-03-durable-object-sqlite.md) | Durable Object SQLite: schema, write path, CF-001, cost | Answered locally; production run open |
| [S-04](S-04-worker-dependencies.md) | Worker dependency metadata and source maps | Partly answered; API side open |
| S-05 | Token permission groups and Metadata Read-Only roles | Needs a regular account |
| S-06 | Audit Logs v2 polling | Needs a regular account |
| S-07 | Containers outbound handlers, registry credentials | Needs a Workers Paid account |
| S-08 | Worker-level Access for the UI, auth for MCP | Needs a regular account with Zero Trust |

[Temporary accounts](temporary-accounts.md) help with quick API checks but cannot run most spikes.
