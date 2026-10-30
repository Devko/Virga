# OCSF export

Status: implemented in [`apps/web/src/ocsf.ts`](../../apps/web/src/ocsf.ts) (mapping) and [`apps/web/src/export.ts`](../../apps/web/src/export.ts) (endpoint). It closes the OCSF part of phase 1 backlog item 13 and follows principle 5 of the [design spec](../concept/design-spec.md) ("Findings as OCSF").

## Schema

- **OCSF 1.9.0**, the current release on [schema.ocsf.io](https://schema.ocsf.io/1.9.0/classes/detection_finding) when this was written (2026-10-30). Every record names it in `metadata.version`.
- Class **Detection Finding** (`class_uid` 2004), category **Findings** (`category_uid` 2), profile `cloud` (`metadata.profiles`).
- One record per finding, a snapshot of the finding as the findings read returns it at the time of the request, not an event stream.

## Endpoint

`GET /api/accounts/{id}/findings/export?format=&status=&severity=&limit=&cursor=`

| Parameter | Values |
| --- | --- |
| `format` | `json` (default): one JSON array, `application/json`. `ndjson`: one record per line, `application/x-ndjson` |
| `status`, `severity` | As for `GET /api/accounts/{id}/findings`, repeatable |
| `limit` | Findings in this response, 1 to 1,000; default 1,000 |
| `cursor` | From the previous response's `Link` header |

- **Identity.** The same checks as the findings read: any identity that passes the Access check, viewer or admin. An account that is not in the index answers 404.
- **Another site.** A download changes nothing, so it needs no CSRF token, but another site must not start one in the user's name. A request whose `Sec-Fetch-Site` is present and not `same-origin` or `none`, or whose `Origin` is not the Worker's own, answers 403 `cross_origin`. The SPA, an address the user typed and clients without fetch metadata (curl, a SIEM collector) get the export.
- **Headers.** `Content-Disposition: attachment; filename="virga-findings-<id>.ocsf.json"` (or `.ocsf.ndjson`), `Cache-Control: no-store`, `Virga-Export-Count` (records in this response), and the security headers of every API response (`X-Content-Type-Options: nosniff`, the CSP).
- **Size bound and paging.** The Worker reads core in chunks of 50 findings. It stops after `limit` findings, or after the chunk in which the records reach 4 MiB. Evidence larger than 64 KiB is left out of its record (below), so one response is at most about 4 MiB plus one chunk of 50 records of at most about 68 KiB each. When findings are left, the response carries `Link: </api/accounts/{id}/findings/export?…&cursor=…>; rel="next"`, which keeps the format, filters and limit; following the links until there is none returns every finding once. The cursor is core's findings cursor.

The SPA's findings view has an export control: it takes the view's status and severity filters and a format, saves the first part, and offers the next part while the response links to one.

## Mapping

Every field comes from `GraphReader.listFindings` (`FindingView`) or is a constant of the class. The account ID comes from the request path, which core checks against the index.

| OCSF field | Value | Source |
| --- | --- | --- |
| `metadata.version` | `1.9.0` | constant |
| `metadata.product` | `{ name: "Virga", vendor_name: "Virga" }` | constant |
| `metadata.profiles` | `["cloud"]` | constant |
| `metadata.is_truncated`, `metadata.untruncated_size` | `true` and the evidence size in KB, only when the evidence was left out | `evidence` |
| `category_uid`, `category_name` | 2, `Findings` | constant |
| `class_uid`, `class_name` | 2004, `Detection Finding` | constant |
| `activity_id`, `activity_name` | 3 `Close` when `resolved`; else 2 `Update` when `lastSeen > firstSeen`; else 1 `Create` | `status`, `firstSeen`, `lastSeen` |
| `type_uid`, `type_name` | `200400 + activity_id`, `Detection Finding: <activity>` | derived |
| `severity_id`, `severity` | critical 5 `Critical`, high 4 `High`, medium 3 `Medium`, low 2 `Low`, info 1 `Informational` | `severity` |
| `status_id`, `status` | open 1 `New`, suppressed 3 `Suppressed`, resolved 4 `Resolved` | `status` |
| `status_code` | `open`, `suppressed` or `resolved` | `status` |
| `is_alert` | true for `open` only | `status` |
| `time` | When the finding was first seen: OCSF 1.9 defines `time` as the finding's creation time | `firstSeen` |
| `message` | The rule title | `title` |
| `finding_info.uid` | The fingerprint (untrusted) | `fingerprint` |
| `finding_info.title` | The rule title | `title` |
| `finding_info.analytic` | `{ uid: <rule ID>, name: <title>, type_id: 1, type: "Rule", version: "<rule version>" }` | `ruleId`, `title`, `ruleVersion` |
| `finding_info.created_time`, `first_seen_time` | | `firstSeen` |
| `finding_info.last_seen_time` | | `lastSeen` |
| `finding_info.modified_time` | The later of `lastSeen` and `resolvedAt` | `lastSeen`, `resolvedAt` |
| `cloud.provider` | `Cloudflare` | constant |
| `cloud.account` | `{ uid: <account ID>, type_id: 99, type: "Cloudflare Account" }`; OCSF has no account type for Cloudflare | path |
| `resources` | `[{ uid: <subject node ID>, type: <node type>, role_id: 1, role: "Target" }]`; left out without a subject. `type` is the node ID's prefix when it is a node type (`^[a-z][a-z0-9_]*$`) | `subject` |
| `evidences` | `[{ data: <evidence> }]`; left out when the evidence is larger than 64 KiB | `evidence` |
| `unmapped.virga.untrusted` | The paths below | constant |
| `unmapped.virga.insight_id` | The Security Insight the finding enriches (untrusted), when there is one | `insightId` |
| `unmapped.virga.resolved_time` | When the finding was resolved, when it is | `resolvedAt` |
| `unmapped.virga.suppressed_until` | When a suppression ends, while it lasts | `suppressedUntil` |
| `unmapped.virga.evidence_omitted` | A note, when the evidence was left out | `evidence` |

Times are Unix epoch milliseconds, as OCSF's `timestamp_t`.

`subject` is the node the finding is about: the rule's `subject_id`, stored in `finding_nodes` with role `subject`. The findings read returns it for this export (core `FindingView.subject`). Other node roles of a finding (for example `entry` or `data`) are in `GET /api/accounts/{id}/finding` only.

## Untrusted strings

Fingerprints, node IDs, evidence and insight IDs hold text from the scanned account. OCSF has no field for that, so each record lists the paths in `unmapped.virga.untrusted`:

```json
["finding_info.uid", "resources[].uid", "evidences[].data", "unmapped.virga.insight_id"]
```

A consumer treats the values at these paths, where present, as data written by whoever controls the account: never as markup, links or instructions.

The values stay JSON strings. On top of JSON's own escaping (C0 controls, `"` and `\`, lone surrogates), the export writes exactly these characters as `\u` escapes, a character above U+FFFF as its surrogate pair (`EXPORT_ESCAPED` in `ocsf.ts`):

- `&`, `<` and `>`;
- DEL and the C1 controls, U+007F to U+009F;
- the line and paragraph separators, U+2028 and U+2029;
- every format character (general category Cf) and every default-ignorable code point (property Default_Ignorable_Code_Point) of Unicode 17: U+00AD, U+034F, U+0600 to U+0605, U+061C, U+06DD, U+070F, U+0890 to U+0891, U+08E2, U+115F to U+1160, U+17B4 to U+17B5, U+180B to U+180F, U+200B to U+200F, U+202A to U+202E, U+2060 to U+206F, U+3164, U+FE00 to U+FE0F, U+FEFF, U+FFA0, U+FFF0 to U+FFFB, U+110BD, U+110CD, U+13430 to U+1343F, U+1BCA0 to U+1BCA3, U+1D173 to U+1D17A, and U+E0000 to U+E0FFF. These are the soft hyphen, the combining grapheme joiner, the Hangul fillers, the zero-width, joining and bidi controls, the variation selectors, the tags, and the other characters that a viewer draws as nothing or that change how the text around them is ordered or joined.

They occur only inside strings, so every value parses back unchanged. A test sweeps every code point: the export escapes this set and nothing else outside ASCII, and the set holds every Cf and default-ignorable character of the runtime's Unicode tables, so newer tables fail the test until the list grows. The file therefore holds no markup and none of these characters raw. Everything else stays raw: spaces other than U+0020 (such as U+00A0, U+2000 to U+200A, U+202F, U+205F, U+3000), which show as space, and characters that look like others, so a value can still look like a different one. A line feed appears only between NDJSON records.

## Not yet

- **Schema validation.** The records are not validated against the OCSF schema; that is phase 4 ("OCSF export validated against the schema"). Tests check the mapping field by field.
- **Artifact store.** The design spec lists OCSF exports among the R2 artifacts. Phase 1 has no R2 bucket, so the export is served from the API on request and stored nowhere.
- **Delivery.** No scheduled export and no push to a SIEM or Security Lake; a collector polls the endpoint and follows the links.
- **Fields.** No `cloud.account.name` (the findings read does not return the account name), no `remediation` (fix proposals are phase 4), no `vulnerabilities` (phase 2), no `observables`, no `metadata.uid` or `metadata.product.version`, and only the subject in `resources`.
- **Consistency.** The parts of a multi-part export are separate reads. A scan that finishes between two parts can move a finding between them, so it may appear twice or not at all; core's cursor keeps the order by severity, then fingerprint.
