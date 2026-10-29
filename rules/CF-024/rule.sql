-- ---
-- id: CF-024
-- version: 1
-- title: Secret in a plain-text variable instead of a secret binding
-- severity: medium
-- kind: posture
-- requires: [workers]
-- enriches: null
-- ---
-- A collected Worker version (deployed, or reachable through a version URL)
-- has a plain-text variable whose value the workers collector judged to look
-- like a secret: a Cloudflare token or key prefix, an AWS access key, a
-- private key, or a high-entropy string. Plain-text values are readable by
-- anyone who can read the Worker's settings, unlike secret bindings. The value
-- never enters the graph; the evidence names the variables, the matched
-- patterns and the versions. One finding per Worker.
--
-- Pages projects have plain-text variables too, but the graph contract does
-- not carry them yet.
WITH leaked AS (
  SELECT v.props ->> '$.script_node_id'  AS script_id,
         v.id                            AS version_id,
         var.value ->> '$.name'          AS variable,
         var.value ->> '$.secret_pattern' AS pattern
  FROM nodes v, json_each(v.props, '$.plain_text_vars') AS var
  WHERE v.type = 'worker_version' AND v.deleted_at IS NULL
    AND var.value ->> '$.looks_secret' = 1
)
SELECT
  'CF-024'                                AS rule_id,
  'CF-024:' || l.script_id                AS fingerprint,
  'medium'                                AS severity,
  l.script_id                             AS subject_id,
  json_group_array(DISTINCT l.variable)   AS variables,
  json_group_array(DISTINCT l.pattern) FILTER (WHERE l.pattern IS NOT NULL) AS patterns,
  json_group_array(DISTINCT l.version_id) AS versions
FROM leaked l
JOIN nodes s ON s.id = l.script_id AND s.type = 'worker_script' AND s.deleted_at IS NULL
GROUP BY l.script_id
