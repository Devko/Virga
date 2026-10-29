# 0002: Scan scheduling

- Status: accepted
- Date: 2026-10-29
- Relates to: D-09 (default cadence), S-01 (Workflows)

## Context

The scan work package had to decide when an account is due, how to tell a hung scan from a running one, and how to name manual scans. The Workflows constraints are in [analysis.md](../analysis.md): instance IDs of at most 100 characters matching `^[a-zA-Z0-9_][a-zA-Z0-9-_]*$`, and duplicate IDs rejected while the earlier instance is retained.

## Decision

- **Dispatch.** A dispatcher Workflow runs on a schedule on its binding, every hour at minute 17 (UTC). It selects due accounts from the index database and creates scan instances with `createBatch`, which skips IDs that already exist.
- **Due rule.** An account is due when at least `cadence_hours` full UTC hours have passed since `last_scan_at`. `last_scan_at` is the start time of the last finished scan, whatever its outcome. The default cadence is 24 hours (D-09).
- **Instance IDs.**
  - Scheduled scans: `scan-<accountId>-<yyyymmddhh>`, so one account gets at most one scheduled scan per hour.
  - Manual scans: `scan-<accountId>-<yyyymmddhhmm>-manual`.
- **One scan at a time per account.** A scan that finds another scan of the same account running does not start. A scan running longer than 12 hours counts as hung: it is marked failed, and the new scan starts.
- **Retries.** API steps retry three times. When the broker answers 429, a step waits the given retry-after, capped at 900 seconds.

## Consequences

The 12-hour threshold is a guess. The design spec estimates 45 to 90 minutes for large accounts, without rate-limit pauses. S-01 and S-02 in a real account set the final values for the threshold, retries and waits.
