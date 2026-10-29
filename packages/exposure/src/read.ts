import type { SqlRunner } from "@virga/graph";

export type Props = Record<string, unknown>;

export interface GraphNode {
  id: string;
  type: string;
  nativeId: string;
  name: string | null;
  props: Props;
}

export interface GraphEdge {
  src: string;
  dst: string;
  props: Props;
}

export const ENTRY_TYPES = [
  "worker_route",
  "worker_custom_domain",
  "workers_dev",
  "worker_preview_url",
  "pages_domain",
  "pages_preview",
  "r2_public_domain",
  "tunnel_hostname",
] as const;

export type EntryType = (typeof ENTRY_TYPES)[number];

export const isObject = (value: unknown): value is Props =>
  value !== null && typeof value === "object" && !Array.isArray(value);

export const str = (value: unknown): string | null =>
  typeof value === "string" && value !== "" ? value : null;

function parseProps(json: unknown): Props {
  if (typeof json !== "string") return {};
  try {
    const value: unknown = JSON.parse(json);
    return isObject(value) ? value : {};
  } catch {
    return {};
  }
}

interface NodeRow extends Record<string, string | null> {
  id: string;
  type: string;
  native_id: string;
  name: string | null;
  props: string;
}

function nodes(db: SqlRunner, types: readonly string[]): GraphNode[] {
  const rows = db.query<NodeRow>(
    `SELECT id, type, native_id, name, props FROM nodes
     WHERE deleted_at IS NULL AND type IN (${types.map(() => "?").join(", ")})
     ORDER BY id`,
    ...types,
  );
  return rows.map((r) => ({
    id: r.id,
    type: r.type,
    nativeId: r.native_id,
    name: r.name,
    props: parseProps(r.props),
  }));
}

function edges(db: SqlRunner, type: string): GraphEdge[] {
  return db
    .query<{ src: string; dst: string; props: string }>(
      "SELECT src, dst, props FROM edges WHERE deleted_at IS NULL AND type = ? ORDER BY id",
      type,
    )
    .map((r) => ({ src: r.src, dst: r.dst, props: parseProps(r.props) }));
}

export interface ScriptRow {
  id: string;
  nativeId: string;
  workerId: string | null;
  workersDev: boolean | null;
  previewUrls: boolean | null;
}

/** Everything the evaluator reads, loaded once. Live rows only. */
export interface GraphInput {
  /** `access` coverage in the current scan, or null if there is no current scan. */
  accessCoverage: { scanId: string; status: string | null } | null;
  entries: GraphNode[];
  routesTo: Map<string, string[]>;
  scripts: Map<string, ScriptRow>;
  /** Worker version node ID to `script_node_id`. */
  versionScripts: Map<string, string>;
  zoneNames: Map<string, string>;
  apps: GraphNode[];
  policies: Map<string, GraphNode>;
  groups: Map<string, GraphNode>;
  /** Access app ID to `ALLOWS` edges pointing at it. */
  allows: Map<string, GraphEdge[]>;
}

const bool = (value: unknown): boolean | null => (typeof value === "boolean" ? value : null);

function push<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

export function readGraph(db: SqlRunner): GraphInput {
  const scanId = db.query<{ value: string }>("SELECT value FROM meta WHERE key = 'current_scan'")[0]
    ?.value;
  const accessCoverage =
    scanId === undefined
      ? null
      : {
          scanId,
          status:
            db.query<{ status: string }>(
              "SELECT status FROM coverage WHERE scan_id = ? AND resource_class = 'access'",
              scanId,
            )[0]?.status ?? null,
        };

  const routesTo = new Map<string, string[]>();
  for (const e of edges(db, "ROUTES_TO")) push(routesTo, e.src, e.dst);

  const scripts = new Map<string, ScriptRow>();
  for (const n of nodes(db, ["worker_script"])) {
    scripts.set(n.id, {
      id: n.id,
      nativeId: n.nativeId,
      workerId: str(n.props.worker_id),
      workersDev: bool(n.props.workers_dev),
      previewUrls: bool(n.props.preview_urls),
    });
  }

  // Version props can be large; only the script reference is needed.
  const versionScripts = new Map<string, string>();
  for (const r of db.query<{ id: string; script: string | null }>(
    `SELECT id, json_extract(props, '$.script_node_id') AS script FROM nodes
     WHERE deleted_at IS NULL AND type = 'worker_version'`,
  )) {
    if (typeof r.script === "string") versionScripts.set(r.id, r.script);
  }

  const zoneNames = new Map<string, string>();
  for (const z of nodes(db, ["zone"])) {
    const name = str(z.name)?.toLowerCase();
    if (name) zoneNames.set(z.nativeId, name);
  }

  const allows = new Map<string, GraphEdge[]>();
  for (const e of edges(db, "ALLOWS")) push(allows, e.dst, e);

  const byId = (list: GraphNode[]) => new Map(list.map((n) => [n.id, n]));
  return {
    accessCoverage,
    entries: nodes(db, ENTRY_TYPES),
    routesTo,
    scripts,
    versionScripts,
    zoneNames,
    apps: nodes(db, ["access_app"]),
    policies: byId(nodes(db, ["access_policy"])),
    groups: byId(nodes(db, ["access_group"])),
    allows,
  };
}
