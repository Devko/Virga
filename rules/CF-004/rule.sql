-- ---
-- id: CF-004
-- version: 2
-- title: Published tunnel hostname reachable without Access
-- severity: high
-- kind: posture
-- requires: [tunnels, access, exposure]
-- enriches: null
-- ---
-- A public hostname in the remotely managed ingress of a Cloudflare Tunnel
-- that the exposure evaluator decides `public` on at least one path prefix.
-- Critical when the origin is not HTTP: SSH, RDP, SMB, arbitrary TCP, or the
-- bastion mode, which lets cloudflared reach any local address. `http_status`
-- origins answer with a fixed status code and expose nothing. `unknown`
-- exposure is never public: a hostname with an unknown path prefix and no
-- public one would qualify if that prefix were public, so its row is
-- undecided (decided = 0) and lists the unknown prefixes instead. Access is
-- required for the same reason as in CF-021. One finding per tunnel hostname.
--
-- The spec has this rule reference the Security Insight "Unprotected
-- Cloudflare Tunnels" instead of duplicating it. `enriches` stays null for
-- now: the insights table types insights by API issue_type, a category such
-- as `exposed_infrastructure`, and the API reference documents no
-- issue_class for that insight.
WITH hostname AS (
  SELECT h.id AS hostname_id,
         h.props ->> '$.origin_scheme' AS scheme,
         h.props ->> '$.service'       AS service,
         r.dst                         AS tunnel_id
  FROM nodes h
  LEFT JOIN edges r ON r.src = h.id AND r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
  WHERE h.type = 'tunnel_hostname' AND h.deleted_at IS NULL
    AND COALESCE(h.props ->> '$.origin_scheme', '') <> 'http_status'
),
exposed AS (
  SELECT h.hostname_id, h.scheme, h.service, h.tunnel_id, x.path_prefix, x.decision,
         x.confidence,
         max(x.decision = 'public') OVER (PARTITION BY h.hostname_id) AS decided
  FROM hostname h
  JOIN exposure x ON x.entry_id = h.hostname_id AND x.decision IN ('public', 'unknown')
)
SELECT
  'CF-004'                                   AS rule_id,
  'CF-004:' || hostname_id                   AS fingerprint,
  CASE
    WHEN scheme IN ('ssh', 'rdp', 'smb', 'tcp') OR service = 'bastion' THEN 'critical'
    ELSE 'high'
  END                                        AS severity,
  hostname_id                                AS subject_id,
  max(decided)                               AS decided,
  scheme                                     AS origin_scheme,
  json_group_array(DISTINCT path_prefix)     AS public_paths,
  json_group_array(DISTINCT tunnel_id) FILTER (WHERE tunnel_id IS NOT NULL) AS tunnels,
  min(confidence)                            AS exposure_confidence
FROM exposed
-- the public prefixes decide a hostname; the unknown ones only when there is none
WHERE decision = 'public' OR decided = 0
GROUP BY hostname_id
