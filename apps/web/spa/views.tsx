import type {
  AccountRow,
  FindingDetail,
  FindingSeverity,
  FindingView,
  Json,
  NodeView,
  RuleRunStatus,
  RuleRunView,
  ScanSummaryView,
} from "../src/rpc.ts";
import type { IntakeView, RemovalView } from "./api.ts";
import { Link, paths } from "./router.tsx";
import { JsonView, Text, time } from "./text.tsx";

/** Presentational views. Data comes in as props, so tests can render them with hostile values. */

export function Severity({ value }: { value: FindingSeverity }) {
  return <span className={`severity severity-${value}`}>{value}</span>;
}

export function AccountsTable({ accounts }: { accounts: AccountRow[] }) {
  if (accounts.length === 0) return <p className="muted">No accounts yet.</p>;
  return (
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Account ID</th>
          <th>Profile</th>
          <th>Status</th>
          <th>Every</th>
          <th>Last scan</th>
        </tr>
      </thead>
      <tbody>
        {accounts.map((a) => (
          <tr key={a.id}>
            <td>
              <Link to={paths.account(a.id)}>
                <Text value={a.name} max={80} />
              </Link>
            </td>
            <td className="mono">{a.id}</td>
            <td>{a.profile}</td>
            <td>{a.status}</td>
            <td>{a.cadenceHours} h</td>
            <td>{time(a.lastScanAt)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

export function SummaryView({ summary }: { summary: ScanSummaryView }) {
  const { account, lastRun, graph } = summary;
  const open = graph.findings.open ?? {};
  return (
    <section>
      <h1>
        <Text value={account.name} max={120} />
      </h1>
      <p className="muted mono">{account.id}</p>
      <dl className="facts">
        <div>
          <dt>Profile</dt>
          <dd>{account.profile}</dd>
        </div>
        <div>
          <dt>Last scan</dt>
          <dd>
            {lastRun ? `${lastRun.status}, started ${time(lastRun.startedAt)}` : "never scanned"}
          </dd>
        </div>
        <div>
          <dt>Open findings</dt>
          <dd>
            {SEVERITIES.filter((s) => open[s]).map((s) => (
              <span key={s} className="count">
                <Severity value={s} /> {open[s]}
              </span>
            ))}
            {SEVERITIES.every((s) => !open[s]) && "none"}
          </dd>
        </div>
        <div>
          <dt>Exposure</dt>
          <dd>
            {Object.entries(graph.exposure)
              .map(([decision, n]) => `${decision} ${n}`)
              .join(", ") || "—"}
          </dd>
        </div>
      </dl>
      <h2>Coverage of the latest scan</h2>
      <table>
        <thead>
          <tr>
            <th>Class</th>
            <th>Status</th>
            <th>Chunks</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {graph.coverage.map((c) => (
            <tr key={c.resourceClass}>
              <td>{c.resourceClass}</td>
              <td className={`coverage coverage-${c.status}`}>{c.status.replace("_", " ")}</td>
              <td>
                {c.chunksDone}/{c.chunksTotal}
              </td>
              <td>
                <Text value={c.detail} max={160} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>Rules of the latest scan</h2>
      <RuleRunsTable runs={graph.ruleRuns} />
    </section>
  );
}

const RUN_STATUS: Record<RuleRunStatus, string> = {
  evaluated: "evaluated",
  not_evaluated: "not evaluated",
  error: "failed",
};

/** Not evaluated and undecided are results of their own, never counted as passes. */
function ruleTotals(runs: RuleRunView[]): string {
  const count = (status: RuleRunStatus) => runs.filter((r) => r.status === status).length;
  const hits = runs.reduce((n, r) => n + r.hits, 0);
  const undecided = runs.reduce((n, r) => n + r.undecided, 0);
  return (
    `${count("evaluated")} evaluated, ${count("not_evaluated")} not evaluated, ` +
    `${count("error")} failed; ${hits} ${hits === 1 ? "hit" : "hits"}, ${undecided} undecided`
  );
}

function RuleRunsTable({ runs }: { runs: RuleRunView[] }) {
  if (runs.length === 0) return <p className="muted">No rule has run in the latest scan.</p>;
  return (
    <>
      <p>{ruleTotals(runs)}</p>
      <table>
        <thead>
          <tr>
            <th>Rule</th>
            <th>Status</th>
            <th>Hits</th>
            <th>Undecided</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => (
            <tr key={r.ruleId}>
              <td className="mono">{r.ruleId}</td>
              <td className={`rule-run rule-run-${r.status}`}>
                {RUN_STATUS[r.status] ?? r.status}
              </td>
              <td>{r.hits}</td>
              <td>{r.undecided}</td>
              <td>
                {r.status === "error" ? (
                  // The message can quote values from the scanned account.
                  <Text value={r.error} max={160} />
                ) : (
                  r.missing.length > 0 && `missing: ${r.missing.join(", ")}`
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export function FindingsTable({
  accountId,
  findings,
}: {
  accountId: string;
  findings: FindingView[];
}) {
  if (findings.length === 0) return <p className="muted">No findings match.</p>;
  return (
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule</th>
          <th>Finding</th>
          <th>Status</th>
          <th>Last seen</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <tr key={f.fingerprint}>
            <td>
              <Severity value={f.severity} />
            </td>
            <td className="mono">{f.ruleId}</td>
            <td>
              <Link to={paths.finding(accountId, f.fingerprint)}>{f.title}</Link>
              <div className="muted mono">
                <Text value={f.fingerprint} max={100} />
              </div>
            </td>
            <td>{f.status}</td>
            <td>{time(f.lastSeen)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function FindingHeader({ finding }: { finding: FindingDetail }) {
  return (
    <section>
      <h1>{finding.title}</h1>
      <p>
        <Severity value={finding.severity} /> <span className="mono">{finding.ruleId}</span> v
        {finding.ruleVersion} · {finding.status}
      </p>
      <dl className="facts">
        <div>
          <dt>Fingerprint</dt>
          <dd className="mono">
            <Text value={finding.fingerprint} max={200} />
          </dd>
        </div>
        <div>
          <dt>First seen</dt>
          <dd>{time(finding.firstSeen)}</dd>
        </div>
        <div>
          <dt>Last seen</dt>
          <dd>{time(finding.lastSeen)}</dd>
        </div>
        {finding.resolvedAt !== null && (
          <div>
            <dt>Resolved</dt>
            <dd>{time(finding.resolvedAt)}</dd>
          </div>
        )}
        {finding.suppressedUntil !== null && (
          <div>
            <dt>Suppressed until</dt>
            <dd>
              {time(finding.suppressedUntil)} by <Text value={finding.suppressedBy} />:{" "}
              <Text value={finding.suppressReason} max={300} />
            </dd>
          </div>
        )}
        {finding.insightId !== null && (
          <div>
            <dt>Security Insight</dt>
            <dd className="mono">
              <Text value={finding.insightId} />
            </dd>
          </div>
        )}
      </dl>
      <h2>Evidence</h2>
      <JsonView value={finding.evidence as Json} />
    </section>
  );
}

export function NodeDetails({ node }: { node: NodeView }) {
  return (
    <div className="node-details">
      <h3>
        <Text value={node.name ?? node.nativeId} max={120} />
      </h3>
      <p className="muted">
        {node.type} · class {node.class}
        {node.deletedAt !== null && ` · deleted ${time(node.deletedAt)}`}
      </p>
      <p className="mono">
        <Text value={node.id} max={200} />
      </p>
      <JsonView value={node.props as Json} />
    </div>
  );
}

export function IntakeResult({ intake }: { intake: IntakeView }) {
  return (
    <div className={intake.stored ? "notice" : "problem"} role="status">
      <p>
        {intake.stored
          ? "The broker checked and stored the token."
          : intake.retryable
            ? "The check could not finish. Nothing was stored; try again later."
            : "The broker rejected the token. Nothing was stored."}
      </p>
      {intake.reasons.length > 0 && (
        <ul>
          {intake.reasons.map((r) => (
            <li key={r.code + r.message}>
              <span className="mono">{r.code}</span>: <Text value={r.message} max={500} />
            </li>
          ))}
        </ul>
      )}
      {intake.warnings.length > 0 && (
        <>
          <p>Warnings:</p>
          <ul>
            {intake.warnings.map((w) => (
              <li key={w.code + w.message}>
                <span className="mono">{w.code}</span>: <Text value={w.message} max={500} />
              </li>
            ))}
          </ul>
        </>
      )}
      {intake.permissionGroups.length > 0 && (
        <p>
          Permission groups:{" "}
          {intake.permissionGroups.map((g, i) => (
            <span key={g}>
              {i > 0 && ", "}
              <Text value={g} />
            </span>
          ))}
        </p>
      )}
      {intake.expiresOn && (
        <p>
          Token expires <Text value={intake.expiresOn} />.
        </p>
      )}
    </div>
  );
}

/** What a removal did, step by step; a step that is null failed or did not run. */
export function RemovalResult({ result }: { result: RemovalView }) {
  const { token, account } = result;
  const done = token !== null && account !== null;
  return (
    <div className={done ? "notice" : "problem"} role="status">
      <p>
        {token === null
          ? "The broker could not remove the token. Nothing was removed; try again."
          : token.removed
            ? "The broker deleted the stored token and cleared the account's rate budget."
            : "The broker held no token for this account; its rate budget was cleared."}
      </p>
      {token !== null && (
        <p>
          {account === null
            ? "The account could not be removed from the index. Try again: removal is safe to repeat."
            : account.removed
              ? "The account, its scan history and its graph were deleted."
              : "The account was not in the index; its graph was cleared."}
        </p>
      )}
      {done && (
        <p>
          Virga never writes to a scanned account, so it cannot revoke the token there. Delete it in
          that account under Manage account, Account API tokens.
        </p>
      )}
    </div>
  );
}
