import type { WorkflowStepConfig } from "cloudflare:workers";
import { NoPermissionError, NotAllowedError, NotFoundError } from "@virga/cf-api";
import { describe } from "../errors.ts";

/** The part of `WorkflowStep` the scan uses, so tests can run it with a fake step. */
export interface ScanStep {
  do<T>(name: string, config: WorkflowStepConfig, callback: () => Promise<T>): Promise<T>;
}

/** Adapts a Workflow step. Results are plain JSON objects, so they are serializable. */
export const workflowStep = (step: {
  do(name: string, config: WorkflowStepConfig, callback: () => Promise<never>): Promise<unknown>;
}): ScanStep => ({
  do: <T>(name: string, config: WorkflowStepConfig, callback: () => Promise<T>) =>
    step.do(name, config, callback as () => Promise<never>) as Promise<T>,
});

const DEFAULT_RETRY_AFTER_S = 300;

function retryAfterOf(error: Error): number | null {
  if (error.name !== "RateLimitedError" && !error.message.startsWith("429 ")) return null;
  const value = (error as { retryAfter?: unknown }).retryAfter;
  return typeof value === "number" && value > 0 ? Math.min(value, 900) : DEFAULT_RETRY_AFTER_S;
}

/**
 * Retry delay for steps that call the API. A 429 from the broker means its
 * rate budget is spent, so the step waits as long as the broker says
 * instead of burning retries; other errors back off from 15 s.
 */
export function apiRetryDelay({ ctx, error }: { ctx: { attempt: number }; error: Error }) {
  const seconds = retryAfterOf(error) ?? 15 * 2 ** Math.max(0, ctx.attempt - 1);
  return `${seconds} seconds` as const;
}

/** Steps that call the Cloudflare API. Each retry repeats the calls, so keep the limit low. */
export const API_STEP: WorkflowStepConfig = {
  retries: { limit: 3, delay: apiRetryDelay },
  timeout: "10 minutes",
};

/** Steps that only talk to the graph object or the index. */
export const STORE_STEP: WorkflowStepConfig = {
  retries: { limit: 5, delay: "10 seconds", backoff: "exponential" },
  timeout: "5 minutes",
};

export type Failure = { status: "no_permission" | "error"; detail: string };

/**
 * Errors that a retry cannot fix become a result instead of an exception,
 * so the step does not retry: missing permission, a call the broker refuses
 * (a bug), a missing resource, and invalid collector output. Everything
 * else is rethrown and retried by the step config.
 */
export function settle(error: unknown): Failure {
  if (error instanceof NoPermissionError) {
    return { status: "no_permission", detail: describe(error) };
  }
  if (
    error instanceof NotAllowedError ||
    error instanceof NotFoundError ||
    error instanceof TypeError ||
    error instanceof RangeError
  ) {
    return { status: "error", detail: describe(error) };
  }
  throw error;
}
