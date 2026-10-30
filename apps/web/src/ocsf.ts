import type { FindingSeverity, FindingStatus, FindingView } from "./rpc.ts";

/**
 * Findings as OCSF Detection Finding records (class 2004, category
 * Findings), schema 1.9.0. Every field comes from the findings read
 * (`GraphReader.listFindings`) or is a constant of the class; the mapping
 * is documented in docs/architecture/ocsf-export.md.
 */

export const OCSF_VERSION = "1.9.0";

/** Evidence larger than this, as exported JSON, is left out of the record. */
export const MAX_EVIDENCE_BYTES = 64 * 1024;

/**
 * Paths whose values were read from the scanned account, where present.
 * Each record lists them in `unmapped.virga.untrusted`.
 */
export const UNTRUSTED_PATHS = [
  "finding_info.uid",
  "resources[].uid",
  "evidences[].data",
  "unmapped.virga.insight_id",
] as const;

const SEVERITY: Record<FindingSeverity, { id: number; caption: string }> = {
  critical: { id: 5, caption: "Critical" },
  high: { id: 4, caption: "High" },
  medium: { id: 3, caption: "Medium" },
  low: { id: 2, caption: "Low" },
  info: { id: 1, caption: "Informational" },
};

const STATUS: Record<FindingStatus, { id: number; caption: string }> = {
  open: { id: 1, caption: "New" },
  suppressed: { id: 3, caption: "Suppressed" },
  resolved: { id: 4, caption: "Resolved" },
};

const ACTIVITY = {
  create: { id: 1, caption: "Create" },
  update: { id: 2, caption: "Update" },
  close: { id: 3, caption: "Close" },
} as const;

const CLASS = { uid: 2004, name: "Detection Finding" } as const;
const CATEGORY = { uid: 2, name: "Findings" } as const;
// `type_id` 99 (Other): OCSF has no account type for Cloudflare.
const ACCOUNT_TYPE = { id: 99, caption: "Cloudflare Account" } as const;
// Node IDs are `<type>:<native ID>`; the type comes from Virga's registry.
const NODE_TYPE = /^([a-z][a-z0-9_]{0,63}):/;

const hex = (code: number) => `\\u${code.toString(16).padStart(4, "0")}`;

/**
 * Characters that JSON leaves as they are but that should not appear raw in
 * a file someone opens in an editor, a terminal or a browser, as inclusive
 * code point ranges: `&`, `<`, `>`, DEL and C1 controls, the line and
 * paragraph separators, and every format character (general category Cf)
 * and default-ignorable code point (Default_Ignorable_Code_Point) of
 * Unicode 17. Those include the soft hyphen, zero-width and bidi controls,
 * U+034F, the Hangul fillers, variation selectors and tags, which a viewer
 * draws as nothing or uses to reorder text. JSON.stringify already escapes
 * C0 controls and lone surrogates. A test checks the list against the
 * runtime's Unicode properties.
 */
export const EXPORT_ESCAPED: readonly (readonly [number, number])[] = [
  [0x26, 0x26],
  [0x3c, 0x3c],
  [0x3e, 0x3e],
  [0x7f, 0x9f],
  [0xad, 0xad],
  [0x34f, 0x34f],
  [0x600, 0x605],
  [0x61c, 0x61c],
  [0x6dd, 0x6dd],
  [0x70f, 0x70f],
  [0x890, 0x891],
  [0x8e2, 0x8e2],
  [0x115f, 0x1160],
  [0x17b4, 0x17b5],
  [0x180b, 0x180f],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x206f],
  [0x3164, 0x3164],
  [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff],
  [0xffa0, 0xffa0],
  [0xfff0, 0xfffb],
  [0x110bd, 0x110bd],
  [0x110cd, 0x110cd],
  [0x13430, 0x1343f],
  [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a],
  [0xe0000, 0xe0fff],
];
const point = (code: number) => `\\u{${code.toString(16)}}`;
const ESCAPE = new RegExp(
  `[${EXPORT_ESCAPED.map(([from, to]) => (from === to ? point(from) : `${point(from)}-${point(to)}`)).join("")}]`,
  "gu",
);

/** A character as JSON `\u` escapes: two, a surrogate pair, above U+FFFF. */
function escaped(c: string): string {
  let out = "";
  for (let i = 0; i < c.length; i++) out += hex(c.charCodeAt(i));
  return out;
}

/**
 * JSON with the characters above as `\u` escapes. They occur only inside
 * strings, so the value parses back unchanged: strings from scanned
 * accounts stay data, and none can close a tag, or hide or reorder the
 * text around it.
 */
export function exportJson(value: unknown): string {
  return JSON.stringify(value).replace(ESCAPE, escaped);
}

const utf8 = new TextEncoder();
export const byteLength = (text: string): number => utf8.encode(text).length;

function activityOf(f: FindingView) {
  if (f.status === "resolved") return ACTIVITY.close;
  return f.lastSeen > f.firstSeen ? ACTIVITY.update : ACTIVITY.create;
}

/**
 * One finding of `accountId` as an OCSF Detection Finding. Evidence larger
 * than MAX_EVIDENCE_BYTES is left out, and the record says so: OCSF 1.9's
 * `metadata.is_truncated`, and `metadata.untruncated_size`, which OCSF
 * defines as the size of the whole event before truncation in kilobytes:
 * the record with its evidence, as exported, in KiB rounded up.
 */
export function detectionFinding(f: FindingView, accountId: string): Record<string, unknown> {
  const whole = record(f, accountId, null);
  if (byteLength(exportJson(f.evidence ?? {})) <= MAX_EVIDENCE_BYTES) return whole;
  return record(f, accountId, Math.ceil(byteLength(exportJson(whole)) / 1024));
}

/** The record; with `untruncatedSize` (KiB), without its evidence. */
function record(
  f: FindingView,
  accountId: string,
  untruncatedSize: number | null,
): Record<string, unknown> {
  const severity = SEVERITY[f.severity] ?? { id: 0, caption: "Unknown" };
  const status = STATUS[f.status] ?? { id: 0, caption: "Unknown" };
  const activity = activityOf(f);
  const omitted = untruncatedSize !== null;
  const nodeType = f.subject === null ? undefined : NODE_TYPE.exec(f.subject)?.[1];

  const virga: Record<string, unknown> = { untrusted: UNTRUSTED_PATHS };
  if (f.insightId !== null) virga.insight_id = f.insightId;
  if (f.resolvedAt !== null) virga.resolved_time = f.resolvedAt;
  if (f.suppressedUntil !== null) virga.suppressed_until = f.suppressedUntil;
  if (omitted) virga.evidence_omitted = "larger than the export's limit; read the finding";

  return {
    metadata: {
      version: OCSF_VERSION,
      product: { name: "Virga", vendor_name: "Virga" },
      profiles: ["cloud"],
      ...(omitted ? { is_truncated: true, untruncated_size: untruncatedSize } : {}),
    },
    category_uid: CATEGORY.uid,
    category_name: CATEGORY.name,
    class_uid: CLASS.uid,
    class_name: CLASS.name,
    activity_id: activity.id,
    activity_name: activity.caption,
    type_uid: CLASS.uid * 100 + activity.id,
    type_name: `${CLASS.name}: ${activity.caption}`,
    severity_id: severity.id,
    severity: severity.caption,
    status_id: status.id,
    status: status.caption,
    status_code: f.status,
    time: f.firstSeen,
    message: f.title,
    is_alert: f.status === "open",
    finding_info: {
      uid: f.fingerprint,
      title: f.title,
      analytic: {
        uid: f.ruleId,
        name: f.title,
        type_id: 1,
        type: "Rule",
        version: String(f.ruleVersion),
      },
      created_time: f.firstSeen,
      first_seen_time: f.firstSeen,
      last_seen_time: f.lastSeen,
      modified_time: Math.max(f.lastSeen, f.resolvedAt ?? 0),
    },
    cloud: {
      provider: "Cloudflare",
      account: { uid: accountId, type_id: ACCOUNT_TYPE.id, type: ACCOUNT_TYPE.caption },
    },
    ...(f.subject === null
      ? {}
      : {
          resources: [
            { uid: f.subject, ...(nodeType ? { type: nodeType } : {}), role_id: 1, role: "Target" },
          ],
        }),
    ...(omitted ? {} : { evidences: [{ data: f.evidence ?? {} }] }),
    unmapped: { virga },
  };
}
