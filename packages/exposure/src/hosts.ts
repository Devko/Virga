/**
 * A host pattern in Access terms: lowercase labels, each literal or with one
 * `*` that matches within that label only, so `*.example.com` covers
 * `a.example.com` but neither `example.com` nor `a.b.example.com`.
 * developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/
 */
export interface HostPattern {
  labels: string[];
  /**
   * The leading `*` label stands for one or more labels, as in Workers routes
   * and tunnel hostnames. Access apps never set it, so no Access pattern
   * covers such a pattern: the hosts below the depth it names stay uncovered.
   */
  multiLevel: boolean;
}

export type HostRelation = "covers" | "inside" | "disjoint";

const LABEL = /^[a-z0-9_-]*\*?[a-z0-9_-]*$/;
const MAX_HOST = 253;

/** Parses a host or Access host pattern; null if it is not one. */
export function parseHost(value: unknown, multiLevel = false): HostPattern | null {
  if (typeof value !== "string") return null;
  const host = value.trim().toLowerCase().replace(/\.$/, "").replace(/:\d+$/, "");
  if (host === "" || host.length > MAX_HOST) return null;
  const labels = host.split(".");
  if (!labels.every((l) => l !== "" && LABEL.test(l))) return null;
  if (multiLevel && labels[0] !== "*") return null;
  return { labels, multiLevel };
}

export const hostText = (host: HostPattern): string =>
  `${host.labels.join(".")}${host.multiLevel ? " (any depth)" : ""}`;

export const isWildcard = (host: HostPattern): boolean =>
  host.multiLevel || host.labels.some((l) => l.includes("*"));

/** Exact hosts beat wildcards; among wildcards, more literal characters win. */
export function hostSpecificity(host: HostPattern): number {
  const literal = host.labels.join(".").replaceAll("*", "").length;
  return isWildcard(host) ? literal : 10_000 + literal;
}

function glob(label: string): [string, string] | null {
  const star = label.indexOf("*");
  return star < 0 ? null : [label.slice(0, star), label.slice(star + 1)];
}

/** Whether every value of label `b` matches label `a`. */
function coversLabel(a: string, b: string): boolean {
  const ga = glob(a);
  if (!ga) return a === b;
  const gb = glob(b);
  if (!gb)
    return b.length >= ga[0].length + ga[1].length && b.startsWith(ga[0]) && b.endsWith(ga[1]);
  return gb[0].startsWith(ga[0]) && gb[1].endsWith(ga[1]);
}

function intersectsLabel(a: string, b: string): boolean {
  const ga = glob(a);
  const gb = glob(b);
  if (!ga) return coversLabel(b, a);
  if (!gb) return coversLabel(a, b);
  const prefixes = ga[0].startsWith(gb[0]) || gb[0].startsWith(ga[0]);
  const suffixes = ga[1].endsWith(gb[1]) || gb[1].endsWith(ga[1]);
  return prefixes && suffixes;
}

/**
 * How the hosts of an Access pattern `app` relate to the hosts of `key`:
 * `covers` all of them, lies `inside` (some of its hosts are in `key`), or is
 * `disjoint`. A pattern of fixed depth lies at most inside one that matches
 * any depth.
 */
export function relateHost(app: HostPattern, key: HostPattern): HostRelation {
  const a = app.labels;
  const k = key.labels;
  if (a.length === k.length) {
    if (a.every((label, i) => coversLabel(label, k[i] ?? ""))) {
      return key.multiLevel && !app.multiLevel ? "inside" : "covers";
    }
    if (a.every((label, i) => intersectsLabel(label, k[i] ?? ""))) return "inside";
    return "disjoint";
  }
  if (key.multiLevel && a.length > k.length) {
    const tail = a.slice(a.length - k.length + 1);
    if (tail.every((label, i) => intersectsLabel(label, k[i + 1] ?? ""))) return "inside";
  }
  return "disjoint";
}

/**
 * Loose test for targets the evaluator cannot interpret: true unless neither
 * host, with everything up to its last wildcard removed, ends with the other.
 */
export function mayShareHost(candidate: string, key: HostPattern): boolean {
  const base = (text: string) => text.slice(text.lastIndexOf("*") + 1).replace(/^\./, "");
  const a = base(candidate);
  const b = base(key.labels.join("."));
  return a.endsWith(b) || b.endsWith(a);
}
