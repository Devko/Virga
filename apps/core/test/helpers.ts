import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import type { ExposureRow } from "@virga/graph";
import type { RuleRunSummary } from "@virga/rules";
import type { AccountGraph } from "../src/account-graph.ts";
import type { Evaluators } from "../src/graph/evaluators.ts";
import { dueAccounts, upsertAccount } from "../src/index-db.ts";

/**
 * The message an RPC call rejects with. `expect(rpcPromise).rejects` leaves an
 * unhandled rejection behind in workerd, so tests await the call here.
 */
export async function rejection(call: Promise<unknown>): Promise<string> {
  try {
    await call;
  } catch (error) {
    return String(error);
  }
  throw new Error("expected the call to reject");
}

/** A fresh account ID per test, so tests sharing the D1 index do not see each other. */
export function newAccountId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const graphOf = (accountId: string) =>
  env.ACCOUNT_GRAPH.get(env.ACCOUNT_GRAPH.idFromName(accountId));

export type GraphStub = ReturnType<typeof graphOf>;

export function sql<T = Record<string, unknown>>(
  stub: GraphStub,
  query: string,
  ...params: unknown[]
): Promise<T[]> {
  return runInDurableObject(
    stub,
    (_: AccountGraph, state) => state.storage.sql.exec(query, ...params).toArray() as T[],
  );
}

export interface FakeEvaluators extends Evaluators {
  calls: { exposure: number; rules: string[] };
}

/**
 * Stand-ins for the exposure evaluator and the findings lifecycle, which
 * other work packages build. `exposure` and `rules` may be replaced to throw.
 */
export function fakeEvaluators(
  options: { exposure?: () => ExposureRow[]; rules?: () => RuleRunSummary[] } = {},
): FakeEvaluators {
  const calls = { exposure: 0, rules: [] as string[] };
  return {
    calls,
    ruleSet: [],
    exposure: () => {
      calls.exposure++;
      return options.exposure ? options.exposure() : [];
    },
    rules: (_db, _rules, scanId) => {
      calls.rules.push(scanId);
      return options.rules
        ? options.rules()
        : [
            {
              ruleId: "CF-001",
              status: "not_evaluated",
              hits: 0,
              undecided: 0,
              missing: ["packages", "vulns"],
              opened: 0,
              resolved: 0,
            },
            {
              ruleId: "CF-002",
              status: "evaluated",
              hits: 2,
              undecided: 1,
              missing: [],
              opened: 2,
              resolved: 1,
            },
          ];
    },
  };
}

/** Registers the account in the index and installs fake evaluators in its graph object. */
export async function setupAccount(accountId: string, evaluators = fakeEvaluators()) {
  await upsertAccount(env.INDEX, { id: accountId, name: "Example Account Name" }, 1);
  const stub = graphOf(accountId);
  await runInDurableObject(stub, (graph: AccountGraph) => {
    graph.evaluators = evaluators;
  });
  return { stub, evaluators };
}

export async function scanRun(id: string) {
  return env.INDEX.prepare("SELECT * FROM scan_runs WHERE id = ?")
    .bind(id)
    .first<{ status: string; started_at: number; finished_at: number | null; summary: string }>();
}

export async function lastScanAt(accountId: string) {
  return (
    await env.INDEX.prepare("SELECT last_scan_at FROM accounts WHERE id = ?")
      .bind(accountId)
      .first<{ last_scan_at: number | null }>()
  )?.last_scan_at;
}

/** An account in the index with the given schedule state. */
export async function indexAccount(
  options: { cadenceHours?: number; lastScanAt?: number; status?: "paused" } = {},
): Promise<string> {
  const id = newAccountId();
  await upsertAccount(env.INDEX, { id, name: "Example", cadenceHours: options.cadenceHours }, 1);
  await env.INDEX.prepare("UPDATE accounts SET last_scan_at = ?, status = ? WHERE id = ?")
    .bind(options.lastScanAt ?? null, options.status ?? "active", id)
    .run();
  return id;
}

export async function runningScanRow(accountId: string, startedAt: number) {
  await env.INDEX.prepare(
    "INSERT INTO scan_runs (id, account_id, started_at, status) VALUES (?, ?, ?, 'running')",
  )
    .bind(`running-${accountId}`, accountId, startedAt)
    .run();
}

/**
 * ACCOUNT_GRAPH whose stubs run `hook` before `deleteAll`, to make the
 * deletion fail (the hook throws) or to do something just before it.
 */
export function graphsWith(hook: () => Promise<void>): Env["ACCOUNT_GRAPH"] {
  const graphs = env.ACCOUNT_GRAPH;
  return {
    idFromName: (name: string) => graphs.idFromName(name),
    get(id: DurableObjectId) {
      const stub = graphs.get(id);
      return {
        async deleteAll() {
          await hook();
          return stub.deleteAll();
        },
        clearRemoved: () => stub.clearRemoved(),
      };
    },
  } as unknown as Env["ACCOUNT_GRAPH"];
}

/**
 * The index, except that `hook` runs before every statement whose SQL
 * matches `match`, alone or in a batch: to make it fail (the hook throws) or
 * to do something just before it.
 */
export function indexWith(match: RegExp, hook: () => Promise<void>): D1Database {
  const db = env.INDEX;
  const real = new WeakMap<object, D1PreparedStatement>();
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement => {
    const hooked =
      (method: "run" | "first" | "all" | "raw") =>
      async (...args: unknown[]) => {
        await hook();
        return (statement[method] as (...a: unknown[]) => Promise<unknown>).apply(statement, args);
      };
    const wrapped = {
      bind: (...values: unknown[]) => wrap(statement.bind(...values)),
      run: hooked("run"),
      first: hooked("first"),
      all: hooked("all"),
      raw: hooked("raw"),
    } as unknown as D1PreparedStatement;
    real.set(wrapped, statement);
    return wrapped;
  };
  return {
    prepare: (query: string) => (match.test(query) ? wrap(db.prepare(query)) : db.prepare(query)),
    async batch(statements: D1PreparedStatement[]) {
      if (statements.some((s) => real.has(s))) await hook();
      return db.batch(statements.map((s) => real.get(s) ?? s));
    },
    exec: (query: string) => db.exec(query),
  } as unknown as D1Database;
}

/** Every account due at `at`, following the pages. */
export async function allDue(at: number): Promise<string[]> {
  const out: string[] = [];
  for (;;) {
    const page = await dueAccounts(env.INDEX, at, { after: out.at(-1), limit: 100 });
    out.push(...page);
    if (page.length < 100) return out;
  }
}
