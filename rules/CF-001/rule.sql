-- ---
-- id: CF-001
-- version: 1
-- title: Public Worker with an exploitable critical vulnerability and access to data
-- severity: critical
-- kind: toxic
-- requires: [workers, routes, packages, vulns, storage, exposure]
-- params:
--   sev_min: 4   # 4 = critical
--   min_conf: 1  # 1 = medium
-- enriches: null
-- ---
-- A Worker version qualifies when a public entry point serves it, it contains a
-- package with an open critical or known-exploited vulnerability detected with
-- at least :min_conf confidence, and it reaches a data store or Secrets Store
-- secret directly or through one service binding. Traffic raises severity; it is
-- not a condition. The WAF virtual patch modifier runs after the query (D-13).
WITH
public_entry AS (
  SELECT x.entry_id, COALESCE(n.name, n.native_id) AS host, x.confidence
  FROM exposure x
  JOIN nodes n ON n.id = x.entry_id AND n.deleted_at IS NULL
  WHERE x.decision = 'public'
),
served AS (
  -- route, Custom Domain, workers.dev -> versions with traffic in the deployment
  SELECT r.src AS entry_id, s.id AS script_id, d.dst AS version_id
  FROM edges r
  JOIN nodes s ON s.id = r.dst AND s.type = 'worker_script' AND s.deleted_at IS NULL
  JOIN edges d ON d.src = s.id AND d.type = 'DEPLOYS' AND d.deleted_at IS NULL
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
    AND COALESCE(json_extract(d.props, '$.percentage'), 100) > 0
  UNION
  -- version and preview URLs point straight at a (possibly old) version
  SELECT r.src, json_extract(v.props, '$.script_node_id'), v.id
  FROM edges r
  JOIN nodes v ON v.id = r.dst AND v.type = 'worker_version' AND v.deleted_at IS NULL
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
),
vuln AS (
  SELECT c.src AS version_id, vu.vuln_id, vu.kev
  FROM edges c
  JOIN nodes p ON p.id = c.dst AND p.type = 'package' AND p.deleted_at IS NULL
  JOIN vulns vu ON vu.package_id = p.id
  WHERE c.type = 'CONTAINS' AND c.deleted_at IS NULL
    AND COALESCE(json_extract(c.props, '$.confidence'), 0) >= :min_conf
    AND vu.status = 'open'
    AND (vu.severity_rank >= :sev_min OR vu.kev = 1)
),
store_types(store_type) AS (
  VALUES ('r2_bucket'), ('d1_database'), ('kv_namespace'), ('do_namespace'),
         ('hyperdrive_config'), ('secrets_store_secret')
),
data_access AS (
  -- direct binding of the version
  SELECT b.src AS version_id, b.dst AS store_id
  FROM edges b
  JOIN nodes t ON t.id = b.dst AND t.deleted_at IS NULL
  WHERE b.type = 'BINDS' AND b.deleted_at IS NULL
    AND t.type IN (SELECT store_type FROM store_types)
  UNION
  -- one hop through a service binding to a version of the target with traffic
  SELECT b1.src, b2.dst
  FROM edges b1
  JOIN nodes s2 ON s2.id = b1.dst AND s2.type = 'worker_script' AND s2.deleted_at IS NULL
  JOIN edges d2 ON d2.src = s2.id AND d2.type = 'DEPLOYS' AND d2.deleted_at IS NULL
                AND COALESCE(json_extract(d2.props, '$.percentage'), 100) > 0
  JOIN edges b2 ON b2.src = d2.dst AND b2.type = 'BINDS' AND b2.deleted_at IS NULL
  JOIN nodes t2 ON t2.id = b2.dst AND t2.deleted_at IS NULL
  WHERE b1.type = 'BINDS' AND b1.deleted_at IS NULL
    AND t2.type IN (SELECT store_type FROM store_types)
)
SELECT
  'CF-001'                                 AS rule_id,
  'CF-001:' || sv.script_id                AS fingerprint,
  CASE
    WHEN max(vu.kev) = 1 THEN 'critical'
    WHEN COALESCE(max(sg.value), 0) > 0 THEN 'critical'
    ELSE 'high'
  END                                      AS severity,
  sv.script_id                             AS subject_id,
  sv.script_id                             AS worker,
  json_group_array(DISTINCT sv.version_id) AS versions,
  json_group_array(DISTINCT pe.host)       AS entry_points,
  json_group_array(DISTINCT vu.vuln_id)    AS vulnerabilities,
  json_group_array(DISTINCT da.store_id)   AS data_stores,
  min(pe.confidence)                       AS exposure_confidence
FROM public_entry pe
JOIN served sv      ON sv.entry_id = pe.entry_id
JOIN vuln vu        ON vu.version_id = sv.version_id
JOIN data_access da ON da.version_id = sv.version_id
LEFT JOIN signals sg ON sg.node_id = sv.script_id AND sg.name = 'invocations_30d'
GROUP BY sv.script_id
