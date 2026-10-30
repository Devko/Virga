import { type FormEvent, lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import {
  type AccountRow,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  type FindingSeverity,
  type FindingStatus,
  type FindingView,
  PROFILES,
  type Profile,
  type TriggerResult,
} from "../src/rpc.ts";
import { ApiError, api, type IntakeView, type Me } from "./api.ts";
import { Pending, Problem, useLoad } from "./load.tsx";
import { Link, paths } from "./router.tsx";
import { Text } from "./text.tsx";
import {
  AccountsTable,
  FindingHeader,
  FindingsTable,
  IntakeResult,
  NodeDetails,
  SummaryView,
} from "./views.tsx";

// Cytoscape is most of the bundle and only this page needs it.
const GraphView = lazy(() => import("./graph.tsx").then((m) => ({ default: m.GraphView })));

export function AccountsPage({ me }: { me: Me | undefined }) {
  const accounts = useLoad(() => api.accounts(), []);
  return (
    <>
      <div className="title-row">
        <h1>Accounts</h1>
        {me?.admin && <Link to={paths.onboarding()}>Add account</Link>}
      </div>
      <Pending loaded={accounts}>{(list) => <AccountsTable accounts={list} />}</Pending>
    </>
  );
}

function ScanButton({ accountId, onStarted }: { accountId: string; onStarted: () => void }) {
  const [state, setState] = useState<{ busy: boolean; result?: TriggerResult; error?: Error }>({
    busy: false,
  });
  const start = async () => {
    setState({ busy: true });
    try {
      const result = await api.scan(accountId);
      setState({ busy: false, result });
      onStarted();
    } catch (error) {
      const body = error instanceof ApiError ? (error.body as TriggerResult | null) : null;
      if (body && "started" in body) setState({ busy: false, result: body });
      else setState({ busy: false, error: error instanceof Error ? error : new Error("failed") });
    }
  };
  const message = (r: TriggerResult) =>
    r.started
      ? "Scan started."
      : r.reason === "running"
        ? "A scan is already running."
        : r.reason === "exists"
          ? "A scan was started a moment ago."
          : "The account is not onboarded.";
  return (
    <div className="actions">
      <button type="button" onClick={start} disabled={state.busy}>
        {state.busy ? "Starting…" : "Start scan"}
      </button>
      {state.result && <span role="status">{message(state.result)}</span>}
      {state.error && <Problem error={state.error} />}
    </div>
  );
}

interface FindingList {
  findings: FindingView[];
  cursor: string | null;
  loading: boolean;
  error?: Error;
}

function FindingsSection({ accountId }: { accountId: string }) {
  const [status, setStatus] = useState<FindingStatus[]>(["open"]);
  const [severity, setSeverity] = useState<FindingSeverity[]>([]);
  const [list, setList] = useState<FindingList>({ findings: [], cursor: null, loading: true });
  const request = useRef(0);

  const load = useCallback(
    async (cursor?: string) => {
      const id = ++request.current;
      setList((l) => ({ ...l, loading: true, error: undefined }));
      try {
        const page = await api.findings(accountId, { status, severity, cursor });
        if (id !== request.current) return;
        setList((l) => ({
          findings: cursor ? [...l.findings, ...page.findings] : page.findings,
          cursor: page.cursor,
          loading: false,
        }));
      } catch (error) {
        if (id !== request.current) return;
        setList((l) => ({
          ...l,
          loading: false,
          error: error instanceof Error ? error : new Error("failed"),
        }));
      }
    },
    [accountId, status, severity],
  );
  useEffect(() => {
    void load();
  }, [load]);

  const toggle = <T,>(values: T[], value: T) =>
    values.includes(value) ? values.filter((v) => v !== value) : [...values, value];

  return (
    <section>
      <h2>Findings</h2>
      <fieldset className="filters">
        <legend>Status</legend>
        {FINDING_STATUSES.map((s) => (
          <label key={s}>
            <input
              type="checkbox"
              checked={status.includes(s)}
              onChange={() => setStatus(toggle(status, s))}
            />
            {s}
          </label>
        ))}
      </fieldset>
      <fieldset className="filters">
        <legend>Severity</legend>
        {FINDING_SEVERITIES.map((s) => (
          <label key={s}>
            <input
              type="checkbox"
              checked={severity.includes(s)}
              onChange={() => setSeverity(toggle(severity, s))}
            />
            {s}
          </label>
        ))}
      </fieldset>
      {list.loading && list.findings.length === 0 ? (
        <p className="muted">Loading…</p>
      ) : (
        <FindingsTable accountId={accountId} findings={list.findings} />
      )}
      {list.error && <Problem error={list.error} />}
      {list.cursor && (
        <button
          type="button"
          disabled={list.loading}
          onClick={() => load(list.cursor ?? undefined)}
        >
          {list.loading ? "Loading…" : "Load more"}
        </button>
      )}
    </section>
  );
}

export function AccountPage({ accountId, me }: { accountId: string; me: Me | undefined }) {
  const summary = useLoad(() => api.summary(accountId), [accountId]);
  return (
    <>
      <p>
        <Link to={paths.accounts()}>← Accounts</Link>
      </p>
      <Pending loaded={summary}>{(data) => <SummaryView summary={data} />}</Pending>
      {me?.admin && summary.data && <ScanButton accountId={accountId} onStarted={summary.reload} />}
      <FindingsSection accountId={accountId} />
    </>
  );
}

function Neighborhood({ accountId, nodeId }: { accountId: string; nodeId: string }) {
  const [root, setRoot] = useState(nodeId);
  const [depth, setDepth] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  useEffect(() => {
    setRoot(nodeId);
    setSelected(null);
  }, [nodeId]);
  const graph = useLoad(() => api.neighborhood(accountId, root, depth), [accountId, root, depth]);
  const node = graph.data?.nodes.find((n) => n.id === selected);
  return (
    <section>
      <h2>Graph neighborhood</h2>
      <div className="actions">
        <span>
          Around <Text value={root} max={80} />
        </span>
        <label>
          Hops{" "}
          <select value={depth} onChange={(e) => setDepth(Number(e.target.value))}>
            <option value={1}>1</option>
            <option value={2}>2</option>
          </select>
        </label>
        {root !== nodeId && (
          <button type="button" onClick={() => setRoot(nodeId)}>
            Back to subject
          </button>
        )}
      </div>
      <Pending loaded={graph}>
        {(data) => (
          <div className="graph-layout">
            <Suspense fallback={<p className="muted">Loading the graph…</p>}>
              <GraphView neighborhood={data} onSelect={setSelected} />
            </Suspense>
            <aside>
              {data.truncated && <p className="muted">The neighborhood was cut at 150 nodes.</p>}
              {data.missing.length > 0 && (
                <p className="muted">
                  {data.missing.length} referenced node(s) were not collected (dashed).
                </p>
              )}
              {node ? (
                <>
                  <NodeDetails node={node} />
                  {node.id !== root && (
                    <button type="button" onClick={() => setRoot(node.id)}>
                      Center here
                    </button>
                  )}
                </>
              ) : (
                <p className="muted">Select a node to see its properties.</p>
              )}
            </aside>
          </div>
        )}
      </Pending>
    </section>
  );
}

export function FindingPage({
  accountId,
  fingerprint,
}: {
  accountId: string;
  fingerprint: string;
}) {
  const finding = useLoad(() => api.finding(accountId, fingerprint), [accountId, fingerprint]);
  const [subject, setSubject] = useState<string | null>(null);
  return (
    <>
      <p>
        <Link to={paths.account(accountId)}>← Account</Link>
      </p>
      <Pending loaded={finding}>
        {(data) => {
          const current = subject ?? data.subjects[0]?.nodeId ?? null;
          return (
            <>
              <FindingHeader finding={data} />
              <h2>Subjects</h2>
              <ul className="subjects">
                {data.subjects.map((s) => (
                  <li key={`${s.role}:${s.nodeId}`}>
                    <button
                      type="button"
                      className={s.nodeId === current ? "link selected" : "link"}
                      onClick={() => setSubject(s.nodeId)}
                    >
                      <Text value={s.nodeId} max={100} />
                    </button>{" "}
                    <span className="muted">{s.role}</span>
                  </li>
                ))}
              </ul>
              {current && <Neighborhood accountId={accountId} nodeId={current} />}
            </>
          );
        }}
      </Pending>
    </>
  );
}

const ACCOUNT_ID = /^[0-9a-f]{32}$/;

export function OnboardingPage({ me }: { me: Me | undefined }) {
  const [form, setForm] = useState({
    accountId: "",
    name: "",
    profile: "inventory" as Profile,
    cadenceHours: 24,
  });
  const [token, setToken] = useState("");
  const [state, setState] = useState<{
    busy: boolean;
    intake?: IntakeView;
    added?: AccountRow;
    error?: Error;
  }>({ busy: false });

  if (me && !me.admin) {
    return <p className="problem">Only administrators can add accounts.</p>;
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setState({ busy: true });
    // The token leaves the page in this request only; the field is cleared either way.
    const secret = token;
    setToken("");
    try {
      const { account, intake } = await api.onboard({ ...form, token: secret });
      setState({ busy: false, intake, added: account });
    } catch (error) {
      const body =
        error instanceof ApiError ? (error.body as { intake?: IntakeView } | null) : null;
      setState({
        busy: false,
        intake: body?.intake,
        error: body?.intake ? undefined : error instanceof Error ? error : new Error("failed"),
      });
    }
  };

  const valid = ACCOUNT_ID.test(form.accountId) && token.length > 0;
  return (
    <>
      <p>
        <Link to={paths.accounts()}>← Accounts</Link>
      </p>
      <h1>Add account</h1>
      <p>
        Create an account API token with the read permissions of the chosen profile and an expiry
        within 90 days. The broker checks that it cannot write, then stores it encrypted; it never
        comes back to this page.
      </p>
      <form onSubmit={submit} autoComplete="off">
        <label>
          Account ID
          <input
            value={form.accountId}
            onChange={(e) => setForm({ ...form, accountId: e.target.value.trim().toLowerCase() })}
            pattern="[0-9a-f]{32}"
            required
            spellCheck={false}
            className="mono"
          />
        </label>
        <label>
          Display name
          <input
            value={form.name}
            maxLength={200}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
        </label>
        <label>
          Profile
          <select
            value={form.profile}
            onChange={(e) => setForm({ ...form, profile: e.target.value as Profile })}
          >
            {PROFILES.map((p) => (
              <option key={p} value={p}>
                {p === "inventory" ? "inventory (metadata only)" : "workload (reads code)"}
              </option>
            ))}
          </select>
        </label>
        <label>
          Scan every (hours)
          <input
            type="number"
            min={1}
            max={720}
            value={form.cadenceHours}
            onChange={(e) => setForm({ ...form, cadenceHours: Number(e.target.value) })}
          />
        </label>
        <label>
          API token
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            required
          />
        </label>
        <button type="submit" disabled={!valid || state.busy}>
          {state.busy ? "Checking…" : "Check and store token"}
        </button>
      </form>
      {state.intake && <IntakeResult intake={state.intake} />}
      {state.added && (
        <p role="status">
          Added <Link to={paths.account(state.added.id)}>{state.added.id}</Link>. The next scheduled
          scan picks it up; an administrator can also start one on the account page.
        </p>
      )}
      {state.error && <Problem error={state.error} />}
    </>
  );
}
