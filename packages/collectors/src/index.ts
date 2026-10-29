import { IDENTITY_COLLECTORS } from "./identity/index.ts";
import { PLATFORM_COLLECTORS } from "./platform/index.ts";
import type { Collector } from "./types.ts";

export * from "./types.ts";

/** Every collector, in no particular order; the Workflow orders them by `after`. */
export const COLLECTORS: readonly Collector[] = [...PLATFORM_COLLECTORS, ...IDENTITY_COLLECTORS];
