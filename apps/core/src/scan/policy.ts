/**
 * A scan still `running` after this long is treated as dead: the dispatcher
 * starts a new one and the graph object marks the old one failed. Large
 * accounts take 45 to 90 minutes (design spec), rate-limit pauses included.
 */
export const STALE_SCAN_MS = 12 * 60 * 60 * 1000;

/** Scan instances created per `createBatch` call, the documented maximum. */
export const DISPATCH_BATCH = 100;

/** Errored rule IDs a scan summary lists at most; the count covers all (TM-11). */
export const RULE_ERRORS_LISTED = 20;
