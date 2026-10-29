/** Node types, grouped as in docs/architecture/data-model.md. */
export const NODE_TYPES = [
  // context
  "account",
  "zone",
  "dns_record",
  // entry points
  "worker_route",
  "worker_custom_domain",
  "workers_dev",
  "worker_preview_url",
  "r2_public_domain",
  "tunnel_hostname",
  "pages_domain",
  "pages_preview",
  "spectrum_app",
  // edge controls
  "waf_ruleset",
  "access_app",
  "access_policy",
  "access_group",
  "gateway_policy",
  // workloads
  "worker_script",
  "worker_version",
  "pages_project",
  "container_app",
  "container_image",
  // packages
  "package",
  // data stores
  "r2_bucket",
  "d1_database",
  "kv_namespace",
  "do_namespace",
  "queue",
  "hyperdrive_config",
  "secrets_store_secret",
  "vectorize_index",
  // identities
  "member",
  "account_token",
  "service_token",
  "zt_user",
  "idp_group",
  "identity_provider",
  "everyone",
  // devices
  "device_profile",
  "posture_rule",
  // private networks
  "cidr_route",
  "hostname_route",
  "virtual_network",
  "tunnel",
  "mesh_node",
  "infra_target",
] as const;

export type NodeType = (typeof NODE_TYPES)[number];

export const EDGE_TYPES = [
  "ROUTES_TO",
  "PROTECTED_BY",
  "BINDS",
  "DEPLOYS",
  "CONTAINS",
  "RUNS",
  "EGRESS",
  "CAN",
  "SELECTS",
  "ALLOWS",
  "REQUIRES",
  "PRECEDES",
  "ROUTES",
  "IN",
  "INCLUDES",
  "EXCLUDES",
] as const;

export type EdgeType = (typeof EDGE_TYPES)[number];

export const EXPOSURE_DECISIONS = [
  "public",
  "access",
  "service_auth",
  "private",
  "blocked",
  "unknown",
] as const;

export type ExposureDecision = (typeof EXPOSURE_DECISIONS)[number];

/** Ordinal confidence: 0 low, 1 medium, 2 high. */
export type Confidence = 0 | 1 | 2;

export type CoverageStatus = "complete" | "partial" | "no_permission" | "error" | "skipped";

export type JsonObject = { [key: string]: unknown };

export interface NodeInput {
  type: NodeType;
  nativeId: string;
  name?: string | null;
  props?: JsonObject;
}

export interface EdgeInput {
  type: EdgeType;
  src: string;
  dst: string;
  key?: string;
  props?: JsonObject;
}

/** One collector chunk: all rows belong to one resource class and one scan. */
export interface Batch {
  scanId: string;
  resourceClass: string;
  nodes: NodeInput[];
  edges: EdgeInput[];
}

/** Defensive limits for strings that come from scanned accounts. */
export const LIMITS = {
  nativeId: 512,
  name: 1024,
  propsBytes: 64 * 1024,
  /** Upper bound for one JSON batch parameter; Durable Objects allow 2 MB per string. */
  batchBytes: 1_500_000,
} as const;

export const nodeId = (type: NodeType, nativeId: string): string => `${type}:${nativeId}`;

export const edgeId = (type: EdgeType, src: string, dst: string, key = ""): string =>
  `${type}:${src}->${dst}${key ? `#${key}` : ""}`;
