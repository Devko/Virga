# @virga/core

The core Worker: one `AccountGraph` Durable Object per scanned account, the scan and dispatch Workflows, the account index, and read-only RPC for the web Worker. It has no routes, `workers.dev` and preview URLs are off, and the default `fetch` handler answers 404.

## Bindings

| Binding | What |
| --- | --- |
| `ACCOUNT_GRAPH` | `AccountGraph`, named by account ID |
| `SCAN_WORKFLOW` | `ScanWorkflow` (`virga-scan`), params `{ accountId }` |
| `DISPATCH_WORKFLOW` | `DispatchWorkflow` (`virga-dispatch`), `schedules: ["17 * * * *"]` (UTC) |
| `INDEX` | D1 `virga-index`: `accounts` and `scan_runs` ([migrations/](migrations/)) |
| `BROKER` | Service binding to `virga-broker`, entrypoint `ApiCaller`; the only way to the Cloudflare API |

## Scan

`ScanWorkflow` wires the bindings into `runScan` ([src/scan/run.ts](src/scan/run.ts)); the logic takes its dependencies (step, graph, index, reader, collectors) as arguments so tests run it with a fake step. Every effect is a step, and every step returns counters only: collectors write to the graph object, never into Workflow state.

1. `begin`: checks that the account is in the index, then `AccountGraph.beginScan` (idempotent; refuses while another scan of the account runs, marks one older than 12 hours failed, and refuses after a removal) and a `running` row in `scan_runs`.
2. For each collector, ordered by `after`:
   - `plan:<class>` returns the chunks, the only step result with data (at most 512 KiB).
   - `collect:<class>:<n>` runs `collect` with a reader over `brokerTransport(env.BROKER, accountId)` and writes the output with `AccountGraph.writeChunk` (nodes and edges, signals, and insights only from a single-chunk class).
   - `coverage:<class>`: all chunks ok is `complete`. `NoPermissionError` is `no_permission` without retries. Calls the broker refuses, 404s and invalid output are `error` without retries. Anything else is retried (3 times, waiting out the broker's `retryAfter` on 429) and then `error`, or `partial` if earlier chunks were written. Collection of a class stops at the first failed chunk.
   - A chunk whose output lists `truncated` reasons left resources of its class out, for example a tunnel past 1,000 entry points or 1 MiB of their props (decision 0005). `writeChunk` checks the reasons (at most 100 of at most 1,024 characters) and returns them with the counters. The class is then `partial` even when every chunk was written, collection goes on with the next chunk, and the coverage row's detail reads `truncated (<count>): <reasons>`, at most 1,000 characters of untrusted text. The summary's class entry counts them in `truncated`.
3. `sweep:<class>` for each `complete` class only, so a truncated class keeps the nodes an earlier scan emitted, and their findings stay as they are.
4. `exposure`: `AccountGraph.computeExposure` runs the evaluator, replaces `exposure` and records coverage `exposure`.
5. `rules`: `AccountGraph.evaluateRules` runs the findings lifecycle over `RULES` and sums the runs: evaluated, not evaluated and failed rules, hits (decided rows), undecided rows, and opened and resolved findings. Each run is a `rule_runs` row with `hits`, `undecided` and, for a failed run, `error` (graph migration 2).
6. `finish`: ends the scan in the graph and writes `scan_runs` (status and summary) and `accounts.last_scan_at`.

The scan is `complete` when every class and exposure are complete, `partial` when rules ran on incomplete input, `failed` when rules did not run, and `skipped` when another scan was running or the account is not in the index. Evaluator failures are results, not retried exceptions.

Only the running scan that is current in the graph may write (R2-07). `writeChunk`, `applyBatch`, `recordCoverage`, `sweep`, `computeExposure` and `evaluateRules` throw `StaleScanError` for any other scan: one marked failed as stale, one that ended, or one a newer scan took over. Otherwise a stale instance that retries a chunk would mark live nodes as seen by itself, and the newer scan's sweep would tombstone them. The scan treats the refusal as a step result, not a retry: it stops, leaves the graph as it is, and ends its `scan_runs` row `failed` with the reason in `summary.detail`. `finishScan` returns the status the scan ended with; a scan marked failed as stale stays failed. `finishRun` only ends a `running` row, so an instance that runs again after its scan ended keeps the first result.

## Dispatch

`DispatchWorkflow` runs on its schedule and starts the scans that are due: active accounts whose last scan started at least `cadence_hours` UTC hour slots ago, without a running scan. Each step `dispatch:<n>` selects 100 accounts and calls `createBatch`. Instance IDs are `scan-<accountId>-<yyyymmddhh>`, so a retried step or a second dispatch in the same hour skips existing instances (code 10405) instead of starting a scan twice.

## Entrypoints

`GraphReader` (read-only, for the web Worker): `listAccounts()` (every account in the index by name, then ID, at most 1,000; it reads only the index), `getScanSummary(accountId)`, `listFindings(accountId, { status, severity, limit, cursor })`, `getFinding(accountId, fingerprint)` with `finding_nodes` and the nodes, `getNeighborhood(accountId, nodeId, { depth: 1 | 2, limit })`. An account that is not in the index answers `null`. Values typed `Untrusted` come from the scanned account. Findings are read as of the call: a suppressed finding whose `suppressed_until` is `null` or not after that time is `open`, without suppression fields, in the status filter, the counts and `getFinding`, even while its rule is not evaluated (R3-07). Reads write nothing.

`getScanSummary` returns `{ account, lastRun, graph }`: the index row, the latest `scan_runs` row, and the graph's summary. `graph.ruleRuns` lists, per rule of the latest scan, its status, hits (decided rows), undecided rows, missing inputs and the error text (`Untrusted`, at most 500 characters). A rule that is not evaluated, or an undecided row, is not a pass.

`Admin`: `addAccount({ id, name, cadenceHours, profile })`, which also calls the account's graph object to clear its `removed` marker (`AccountGraph.clearRemoved`), so an account that is added again can be scanned again; `triggerScan(accountId)`, which starts `scan-<accountId>-<yyyymmddhhmm>-manual` unless the account is unknown (`unknown_account`), being removed (`removing`) or has a scan running (`running`), and `removeAccount(accountId)`. `addAccount` on an account that is still `removing` finishes the removal first, so the account starts from nothing.

`removeAccount` runs in an order that never hides an account whose graph is left (R5-08):

1. Mark the account `removing` (`accounts.removing_at`, migration 0002). From here on it is listed with status `removing`.
2. Delete its whole graph (`AccountGraph.deleteAll`: `ctx.storage.deleteAll()`, an empty schema again, and a `removed` key in `meta`).
3. Delete its `accounts` and `scan_runs` rows.

It returns `{ removed }`, true when the account was in the index, and is idempotent: a step that fails leaves the account listed as `removing`, and a retry finishes the removal. From the first step on (R4-03, R5-08):

- The dispatcher (`dueAccounts`) and `triggerScan` start no new scan.
- A scan whose begin step runs after the mark (dispatched, already queued, or a retried begin step) finds the account missing or `removing` in the index and ends `skipped` (detail `account <id> is not in the index or is being removed`), with no write to the graph or the index and no API call.
- While `removed` is set, `AccountGraph.beginScan` refuses with `{ started: false, removed: true }`, in case the removal lands between the index check and the graph call. The index's `beginRun` adds a `running` row only while the account exists and is not `removing`.
- A scan that began before the mark keeps writing until the graph is deleted, is refused at its next write after that, and `finishRun` gives it no row back. If the graph deletion fails, such a scan can still finish into the graph of the `removing` account; a repeat of the removal deletes that data.

Concurrent `addAccount` and `removeAccount` calls for one account are not serialized. In the worst interleaving the graph is left empty without its `removed` marker, the same small window as before R5-08.

Full offboarding also needs the broker: the web Worker calls `TokenIntake.remove(accountId)` first, so a running scan gets no more API access, then `Admin.removeAccount(accountId)`.

## Tests

`pnpm --filter @virga/core test` runs in workerd with `@cloudflare/vitest-plugin`. [test/worker.ts](test/worker.ts) is the test entry module: the Worker's exports plus `FixtureBroker`, which answers `BROKER` calls from fixtures, and `TestScanWorkflow`, the production Workflow with stub collectors. Workflow tests use the plugin's Workflow introspection.
