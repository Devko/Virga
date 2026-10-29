import type { ScanStep } from "../src/scan/step.ts";

export interface StepRecord {
  name: string;
  attempts: number;
  /** Size of the JSON-serialized result. */
  bytes: number;
  result?: unknown;
  error?: string;
}

const encoder = new TextEncoder();

/**
 * A stand-in for WorkflowStep: runs each callback with the configured
 * number of retries, without delays, and records names, attempts and result
 * sizes. With `replay`, cached results are returned without running the
 * callback, as the Workflow engine does when it replays `run`.
 */
export function fakeStep(replay?: Map<string, unknown>) {
  const records: StepRecord[] = [];
  const results = new Map<string, unknown>();
  const step: ScanStep = {
    async do<T>(
      name: string,
      config: { retries?: { limit: number } },
      callback: () => Promise<T>,
    ): Promise<T> {
      if (results.has(name)) throw new Error(`step name used twice: ${name}`);
      const record: StepRecord = { name, attempts: 0, bytes: 0 };
      records.push(record);
      if (replay?.has(name)) {
        results.set(name, replay.get(name));
        return structuredClone(replay.get(name)) as T;
      }
      const limit = config.retries?.limit ?? 5;
      for (;;) {
        record.attempts++;
        try {
          const result = await callback();
          record.bytes = encoder.encode(JSON.stringify(result) ?? "").length;
          record.result = result;
          results.set(name, result);
          // Step results cross a serialization boundary in the real engine.
          return structuredClone(result);
        } catch (error) {
          if (record.attempts > limit) {
            record.error = String(error);
            throw error;
          }
        }
      }
    },
  };
  return {
    step,
    records,
    results,
    names: () => records.map((r) => r.name),
    record: (name: string) => records.find((r) => r.name === name),
  };
}
