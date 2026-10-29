import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { dueAccounts } from "../src/index-db.ts";
import {
  INSTANCE_EXISTS,
  runDispatch,
  type ScanLauncher,
  type ScanParamsPayload,
} from "../src/scan/dispatch.ts";
import { scanInstanceId } from "../src/scan/ids.ts";
import { fakeStep } from "./fake-step.ts";
import { allDue, indexAccount } from "./helpers.ts";

const AT = Date.UTC(2026, 9, 29, 7, 17);

/** Behaves like createBatch: IDs that exist are reported with code 10405, not created. */
function fakeLauncher() {
  const ids = new Set<string>();
  const calls: { id: string; params: ScanParamsPayload }[][] = [];
  const launcher: ScanLauncher = {
    async createBatch({ instances }) {
      calls.push(instances);
      const created: unknown[] = [];
      const errors: { index: number; id?: string; code: number; message: string }[] = [];
      instances.forEach((instance, index) => {
        if (ids.has(instance.id)) {
          errors.push({ index, id: instance.id, code: INSTANCE_EXISTS, message: "exists" });
        } else {
          ids.add(instance.id);
          created.push({ id: instance.id });
        }
      });
      return { created, errors };
    },
  };
  return { launcher, ids, calls };
}

const fromIndex = (at: number, options: { after?: string; limit: number }) =>
  dueAccounts(env.INDEX, at, options);

describe("runDispatch", () => {
  it("creates one instance per due account in pages of 100, and none twice in an hour", async () => {
    for (let i = 0; i < 120; i++) await indexAccount();
    const due = await allDue(AT);
    expect(due.length).toBeGreaterThan(100);
    const { launcher, ids, calls } = fakeLauncher();

    const first = fakeStep();
    const summary = await runDispatch(
      { step: first.step, dueAccounts: fromIndex, scans: launcher },
      AT,
    );
    expect(summary).toEqual({ due: due.length, created: due.length, existing: 0, failed: 0 });
    expect(first.names()).toEqual(["dispatch:1", "dispatch:2"]);
    expect(calls.map((c) => c.length)).toEqual([100, due.length - 100]);
    expect([...ids].sort()).toEqual(due.map((id) => scanInstanceId(id, AT)).sort());
    expect(calls[0]?.[0]?.params).toEqual({ accountId: due[0] });
    for (const record of first.records) expect(record.bytes).toBeLessThan(256);

    // Later in the same hour, e.g. a retried dispatch: every ID exists already.
    const again = await runDispatch(
      { step: fakeStep().step, dueAccounts: fromIndex, scans: launcher },
      AT + 30 * 60_000,
    );
    expect(again).toEqual({ due: due.length, created: 0, existing: due.length, failed: 0 });
  });

  it("skips malformed account IDs instead of failing the batch", async () => {
    const { launcher } = fakeLauncher();
    const summary = await runDispatch(
      {
        step: fakeStep().step,
        dueAccounts: async () => ["0123456789abcdef0123456789abcdef", "not-an-account"],
        scans: launcher,
      },
      AT,
    );
    expect(summary).toEqual({ due: 2, created: 1, existing: 0, failed: 1 });
  });
});
