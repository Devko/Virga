/**
 * CVSS v3.0 and v3.1 base scores from a vector string, as the FIRST
 * specifications define them (https://www.first.org/cvss/v3.1/specification-document).
 * Temporal and environmental metrics are checked but do not change the base
 * score. A vector that breaks the format gives null.
 */

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

/** Privileges Required depends on Scope. */
const PR = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.5 },
} as const;

/** Allowed values per metric. Base metrics are required; the others are optional. */
const METRICS: ReadonlyMap<string, readonly string[]> = new Map([
  ["AV", ["N", "A", "L", "P"]],
  ["AC", ["L", "H"]],
  ["PR", ["N", "L", "H"]],
  ["UI", ["N", "R"]],
  ["S", ["U", "C"]],
  ["C", ["H", "L", "N"]],
  ["I", ["H", "L", "N"]],
  ["A", ["H", "L", "N"]],
  ["E", ["X", "U", "P", "F", "H"]],
  ["RL", ["X", "O", "T", "W", "U"]],
  ["RC", ["X", "U", "R", "C"]],
  ["CR", ["X", "L", "M", "H"]],
  ["IR", ["X", "L", "M", "H"]],
  ["AR", ["X", "L", "M", "H"]],
  ["MAV", ["X", "N", "A", "L", "P"]],
  ["MAC", ["X", "L", "H"]],
  ["MPR", ["X", "N", "L", "H"]],
  ["MUI", ["X", "N", "R"]],
  ["MS", ["X", "U", "C"]],
  ["MC", ["X", "H", "L", "N"]],
  ["MI", ["X", "H", "L", "N"]],
  ["MA", ["X", "H", "L", "N"]],
]);

const BASE = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] as const;

/** Roundup as CVSS v3.1 defines it, free of floating point artifacts. */
export function roundUp31(value: number): number {
  const scaled = Math.round(value * 100_000);
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10;
}

/** Roundup as CVSS v3.0 defines it: the smallest one-decimal number not below the value. */
export function roundUp30(value: number): number {
  return Math.ceil(value * 10) / 10;
}

/** The base score of a `CVSS:3.0/` or `CVSS:3.1/` vector, or null if the vector is not valid. */
export function cvss3BaseScore(vector: string): number | null {
  if (typeof vector !== "string") return null;
  const prefix = /^CVSS:3\.([01])\//.exec(vector);
  if (!prefix) return null;
  const values = new Map<string, string>();
  for (const part of vector.slice(prefix[0].length).split("/")) {
    const colon = part.indexOf(":");
    if (colon === -1) return null;
    const metric = part.slice(0, colon);
    const value = part.slice(colon + 1);
    if (!METRICS.get(metric)?.includes(value) || values.has(metric)) return null;
    values.set(metric, value);
  }
  if (!BASE.every((metric) => values.has(metric))) return null;
  const get = (metric: (typeof BASE)[number]) => values.get(metric) as string;

  const scope = get("S") as "U" | "C";
  const cia = (metric: "C" | "I" | "A") => WEIGHTS.CIA[get(metric) as "H" | "L" | "N"];
  const iss = 1 - (1 - cia("C")) * (1 - cia("I")) * (1 - cia("A"));
  const impact = scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const exploitability =
    8.22 *
    WEIGHTS.AV[get("AV") as "N" | "A" | "L" | "P"] *
    WEIGHTS.AC[get("AC") as "L" | "H"] *
    PR[scope][get("PR") as "N" | "L" | "H"] *
    WEIGHTS.UI[get("UI") as "N" | "R"];
  if (impact <= 0) return 0;
  const roundUp = prefix[1] === "1" ? roundUp31 : roundUp30;
  const raw = scope === "U" ? impact + exploitability : 1.08 * (impact + exploitability);
  return roundUp(Math.min(raw, 10));
}

/** Qualitative rating of a CVSS v3 score: 0 none, 1 low, 2 medium, 3 high, 4 critical. */
export function rankOfScore(score: number): 0 | 1 | 2 | 3 | 4 {
  if (score === 0) return 0;
  if (score < 4) return 1;
  if (score < 7) return 2;
  if (score < 9) return 3;
  return 4;
}
