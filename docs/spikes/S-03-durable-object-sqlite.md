# S-03: Durable Object SQLite

- Status: answered locally; a run on production infrastructure is still open
- Date: 2026-10-29
- Code: [`spikes/s03-do-sqlite`](../../spikes/s03-do-sqlite), [`apps/core/test`](../../apps/core/test)

## Question

Do the schema, the JSON batch upsert, the history triggers and CF-001 work in Durable Object SQLite? What do a first scan and an unchanged rescan cost in rows written? How long does a rule run take on a graph of about 20,000 nodes?

## Setup

- The synthetic account from [`apps/core/test/synthetic.ts`](../../apps/core/test/synthetic.ts): 6,500 Workers, 20,050 nodes and 50,050 edges, written in 72 batches of up to 1,000 rows.
- The spike Worker runs a first scan, the sweep, CF-001, an unchanged rescan and a second sweep in one Durable Object, and counts `rowsRead` and `rowsWritten` from every SQL cursor.
- It ran in `wrangler dev` (local workerd 1.20261012.1, Wrangler 4.151.0). The same checks run in CI through `@cloudflare/vitest-plugin`.

## Results

| Step | Wall time | Rows written | Rows read |
| --- | --- | --- | --- |
| First scan (70,100 rows) | 1,975 ms | 520,779 | 210,519 |
| Exposure and vulnerabilities | | 13,020 | 13,020 |
| Sweep | | 3 | 220,407 |
| CF-001 | 194 ms | 0 | 265,669 |
| Unchanged rescan | 1,368 ms | 260,353 | 210,519 |

- CF-001 returned 131 hits, exactly the set computed independently in JavaScript.
- All four history triggers exist and fire. The first scan wrote 70,100 `create` history rows; the unchanged rescan wrote none.
- Recursive CTEs, `json_each`, `->>`, partial indexes and `json_group_array(DISTINCT …)` work.
- `sqlite_version()` fails with "not authorized to use function". Durable Object SQLite restricts functions that Node's SQLite allows. Rule fixtures therefore run in workerd as well as in Node (they do, in `apps/core`).
- `:name` and `?1` parameters work locally, but only `?` is documented. The rule compiler keeps emitting `?`.
- Database size after both scans: 42 MB, history included. The 10 GB limit is not a concern; history retention will be (A-13).

## Cost

Durable Object pricing on Workers Paid (checked 2026-10-29): 50 million rows written per month included, then $1.00 per million; 25 billion rows read included, then $0.001 per million; 5 GB-month of storage included, then $0.20 per GB-month.

An unchanged rescan writes about 3.7 rows per graph row. One of them is the `seen_scan` update on every observed row (D-05); the rest is most likely index maintenance. For the synthetic account:

| Cadence | Rows written per month | Cost beyond the included 50 M |
| --- | --- | --- |
| Daily (D-09 default) | about 7.8 M | none, for up to about six such accounts |
| Hourly | about 190 M | about $140 for this account alone |

Reads are cheap at any cadence.

The Workers Free plan allows 100,000 rows written per day. A first scan of this size does not fit, so neither do temporary accounts (see [temporary-accounts.md](temporary-accounts.md)).

## Recommendation

Daily full scans plus event-driven updates (D-09) keep the D-05 write strategy affordable. Before hourly scans are offered, change how scans record which rows they saw: one row per batch with the batch's IDs as a JSON array, instead of an update on every unchanged row. The sweep then compares against those lists. An unchanged rescan would then write about 72 rows instead of 260,353. This changes D-05 and needs a new decision record.

## Open

- Run the spike on production infrastructure in a Workers Paid account (`wrangler deploy` in `spikes/s03-do-sqlite`, then `GET /run?workers=6500`). It measures real latency, and whether CF-001 on large graphs stays well below the 30 s CPU limit per request. Temporary accounts cannot run it (no cron triggers, `workers.dev` behind a challenge, Free plan write limits).
