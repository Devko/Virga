-- ---
-- id: CF-009
-- version: 2
-- title: Idle Worker with bindings to production data
-- severity: low
-- kind: posture
-- requires: [workers, storage, pages, traffic, exposure, access]
-- params:
--   min_age_days: 30  # a younger Worker cannot have been idle for 30 days
--   now_ms: 0         # evaluation time in epoch ms; 0 means the start of the current scan
-- enriches: null
-- ---
-- A Worker qualifies when
-- 1. it had no invocations in 30 days across all triggers: the traffic signal
--    `invocations_30d` is 0 or absent (the GraphQL dataset aggregates
--    invocations, so a script without any has no row, and the traffic class
--    is complete),
-- 2. it was created at least :min_age_days days before the evaluation time,
-- 3. a version with a traffic share in its deployment binds a data store that
--    is in production use: another Worker with invocations binds it too, or
--    the production environment of a Pages project does, and
-- 4. no entry point of the Worker is decided `public`. Public Workers fall
--    under CF-001 and CF-006 instead. An entry point with exposure `unknown`
--    may be public, so a Worker that meets 1 to 3 and has one is undecided
--    (decided = 0).
--
-- Gap: the graph has no marker for production data. "Also bound by a live
-- workload" stands in for it, so a store that only the idle Worker uses is
-- not reported.
WITH
clock(now_ms) AS (
  SELECT CASE WHEN :now_ms > 0 THEN :now_ms ELSE COALESCE(
    (SELECT s.started_at FROM scans s JOIN meta m ON m.key = 'current_scan' AND m.value = s.id),
    0) END
),
store_type(type) AS (
  VALUES ('r2_bucket'), ('d1_database'), ('kv_namespace'), ('do_namespace'),
         ('hyperdrive_config'), ('secrets_store_secret')
),
script AS (
  SELECT s.id AS script_id,
         COALESCE(sg.value, 0) AS invocations,
         unixepoch(s.props ->> '$.created_on') * 1000 AS created_ms
  FROM nodes s
  LEFT JOIN signals sg ON sg.node_id = s.id AND sg.name = 'invocations_30d'
  WHERE s.type = 'worker_script' AND s.deleted_at IS NULL
),
binding AS (
  -- data stores of the versions that serve traffic
  SELECT d.src AS script_id, b.dst AS store_id
  FROM edges d
  JOIN nodes v ON v.id = d.dst AND v.type = 'worker_version' AND v.deleted_at IS NULL
  JOIN edges b ON b.src = v.id AND b.type = 'BINDS' AND b.deleted_at IS NULL
  JOIN nodes t ON t.id = b.dst AND t.deleted_at IS NULL
  WHERE d.type = 'DEPLOYS' AND d.deleted_at IS NULL
    AND COALESCE(d.props ->> '$.percentage', 100) > 0
    AND t.type IN (SELECT type FROM store_type)
),
production_use AS (
  SELECT b.store_id, b.script_id AS user_id
  FROM binding b
  JOIN script s ON s.script_id = b.script_id AND s.invocations > 0
  UNION
  SELECT pb.dst, pb.src
  FROM edges pb
  JOIN nodes p ON p.id = pb.src AND p.type = 'pages_project' AND p.deleted_at IS NULL
  JOIN nodes t ON t.id = pb.dst AND t.deleted_at IS NULL
  WHERE pb.type = 'BINDS' AND pb.deleted_at IS NULL
    AND pb.props ->> '$.environment' = 'production'
    AND t.type IN (SELECT type FROM store_type)
),
exposed_script AS (
  -- route, Custom Domain, workers.dev
  SELECT r.dst AS script_id, x.decision
  FROM edges r
  JOIN nodes e ON e.id = r.src AND e.deleted_at IS NULL
  JOIN nodes s ON s.id = r.dst AND s.type = 'worker_script'
  JOIN exposure x ON x.entry_id = r.src AND x.decision IN ('public', 'unknown')
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
  UNION
  -- version URLs
  SELECT v.props ->> '$.script_node_id', x.decision
  FROM edges r
  JOIN nodes e ON e.id = r.src AND e.deleted_at IS NULL
  JOIN nodes v ON v.id = r.dst AND v.type = 'worker_version'
  JOIN exposure x ON x.entry_id = r.src AND x.decision IN ('public', 'unknown')
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
)
SELECT
  'CF-009'                                AS rule_id,
  'CF-009:' || s.script_id                AS fingerprint,
  'low'                                   AS severity,
  s.script_id                             AS subject_id,
  NOT EXISTS (SELECT 1 FROM exposed_script es
              WHERE es.script_id = s.script_id AND es.decision = 'unknown')
                                          AS decided,
  json_group_array(DISTINCT b.store_id)   AS data_stores,
  json_group_array(DISTINCT pu.user_id)   AS shared_with
FROM script s
CROSS JOIN clock c
JOIN binding b         ON b.script_id = s.script_id
JOIN production_use pu ON pu.store_id = b.store_id AND pu.user_id <> s.script_id
WHERE s.invocations = 0
  AND s.created_ms <= c.now_ms - :min_age_days * 86400000
  AND NOT EXISTS (SELECT 1 FROM exposed_script es
                  WHERE es.script_id = s.script_id AND es.decision = 'public')
GROUP BY s.script_id
