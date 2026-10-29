import type { ExposureRow, SqlRunner } from "@virga/graph";

/**
 * Computes exposure for every live entry point in the graph from the nodes
 * described in docs/architecture/graph-contract.md. Pure read: the caller
 * writes the result with `replaceExposure`.
 *
 * Contract: an entry point whose decision cannot be determined gets
 * `unknown`, never `public`.
 */
export function evaluateExposure(_db: SqlRunner): ExposureRow[] {
  throw new Error("evaluateExposure: implemented by the exposure work package");
}
