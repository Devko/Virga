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
 * a file someone opens in an editor, a terminal or a browser: `&`, `<`,
 * `>`, DEL and C1 controls, the soft hyphen, and the invisible formatting,
 * direction and separator characters. JSON.stringify already escapes C0
 * controls and lone surrogates.
 */
const ESCAPED: readonly [number, number][] = [
  [0x26, 0x26],
  [0x3c, 0x3c],
  [0x3e, 0x3e],
  [0x7f, 0x9f],
  [0xad, 0xad],
  [0x061c, 0x061c],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x206f],
  [0xfeff, 0xfeff],
  [0xfff9, 0xfffb],
];
const ESCAPE = new RegExp(
  `[${ESCAPED.map(([from, to]) => (from === to ? hex(from) : `${hex(from)}-${hex(to)}`)).join("")}]`,
  "g",
);

/**
 * JSON with the characters above as `\u` escapes. They occur only inside
 * strings, so the value parses back unchanged: strings from scanned
 * accounts stay data, and none can close a tag or reorder the text around it.
 */
export function exportJson(value: unknown): string {
  return JSON.stringify(value).replace(ESCAPE, (c) => hex(c.charCodeAt(0)));
}

const utf8 = new TextEncoder();
export const byteLength = (text: string): number => utf8.encode(text).length;

function activityOf(f: FindingView) {
  if (f.status === "resolved") return ACTIVITY.close;
  return f.lastSeen > f.firstSeen ? ACTIVITY.update : ACTIVITY.create;
}

/** One finding of `accountId` as an OCSF Detection Finding. */
export function detectionFinding(f: FindingView, accountId: string): Record<string, unknown> {
  const severity = SEVERITY[f.severity] ?? { id: 0, caption: "Unknown" };
  const status = STATUS[f.status] ?? { id: 0, caption: "Unknown" };
  const activity = activityOf(f);
  const evidence = exportJson(f.evidence ?? {});
  const evidenceBytes = byteLength(evidence);
  const omitted = evidenceBytes > MAX_EVIDENCE_BYTES;
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
      ...(omitted ? { is_truncated: true, untruncated_size: Math.ceil(evidenceBytes / 1024) } : {}),
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
