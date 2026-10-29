import { isAccountId, scanInstanceId } from "./ids.ts";
import { DISPATCH_BATCH } from "./policy.ts";
import { type ScanStep, STORE_STEP } from "./step.ts";

/** createBatch error codes for IDs that are taken: retained instance, or a repeat in the batch. */
export const INSTANCE_EXISTS = 10405;
export const INSTANCE_REPEATED = 10415;

export interface ScanParamsPayload {
  accountId: string;
}

/** The part of the scan Workflow binding the dispatcher uses. */
export interface ScanLauncher {
  createBatch(options: { instances: { id: string; params: ScanParamsPayload }[] }): Promise<{
    created: unknown[];
    errors: { index: number; id?: string; code: number; message: string }[];
  }>;
}

export interface DispatchDeps {
  step: ScanStep;
  dueAccounts(at: number, options: { after?: string; limit: number }): Promise<string[]>;
  scans: ScanLauncher;
}

export interface DispatchSummary {
  due: number;
  created: number;
  /** Instances that already existed, e.g. from an earlier run of this hour's dispatch. */
  existing: number;
  failed: number;
}

/**
 * Starts the scans that are due at `at` (the cron's scheduled time). One step
 * per page of 100 accounts selects and creates in one go. Instance IDs are
 * fixed per account and hour, so a retried step or a second dispatch in the
 * same hour skips what exists instead of starting a scan twice.
 */
export async function runDispatch(deps: DispatchDeps, at: number): Promise<DispatchSummary> {
  const total: DispatchSummary = { due: 0, created: 0, existing: 0, failed: 0 };
  let after: string | undefined;
  for (let page = 1; ; page++) {
    const cursor = after;
    const result = await deps.step.do(`dispatch:${page}`, STORE_STEP, async () => {
      const accounts = await deps.dueAccounts(at, { after: cursor, limit: DISPATCH_BATCH });
      const counts = { due: accounts.length, created: 0, existing: 0, failed: 0 };
      // One malformed row must not fail the whole batch (createBatch throws on any invalid ID).
      const valid = accounts.filter((id) => isAccountId(id));
      counts.failed = accounts.length - valid.length;
      if (valid.length > 0) {
        const { created, errors } = await deps.scans.createBatch({
          instances: valid.map((accountId) => ({
            id: scanInstanceId(accountId, at),
            params: { accountId },
          })),
        });
        counts.created = created.length;
        for (const e of errors) {
          if (e.code === INSTANCE_EXISTS || e.code === INSTANCE_REPEATED) counts.existing++;
          else counts.failed++;
        }
      }
      return { ...counts, last: accounts.at(-1) ?? null };
    });
    total.due += result.due;
    total.created += result.created;
    total.existing += result.existing;
    total.failed += result.failed;
    if (result.due < DISPATCH_BATCH || result.last === null) return total;
    after = result.last;
  }
}
