-- ---
-- id: CF-024
-- version: 2
-- title: Secret in a plain-text variable instead of a secret binding
-- severity: medium
-- kind: posture
-- requires: [workers, pages]
-- enriches: null
-- ---
-- A plain-text variable whose value the collector judged to look like a
-- secret: a Cloudflare token or key prefix, an AWS access key, a private key,
-- or a high-entropy string. Plain-text values are readable by anyone who can
-- read the settings, unlike secret bindings. Values never enter the graph;
-- the evidence names the variables and the matched patterns.
--
-- - Workers: a collected Worker version (deployed, or reachable through a
--   version URL) holds the variable. One finding per Worker; `variables`
--   lists the names and `versions` the versions.
-- - Pages (version 2): the preview or production environment of a project
--   holds the variable. One finding per project; `variables` lists
--   `{ environment, name, kind, secret_pattern }` and `versions` is null.
--
-- A value the collector could not inspect (`looks_secret` null: the API
-- returned none) is unknown, not clean. A subject with such a variable and
-- none that looks like a secret is undecided (decided = 0), listing the
-- uninspected variables.
--
-- Requires both classes. The rule answers one question for the account, so
-- a run that could not read Workers or Pages is `not_evaluated` as a whole
-- instead of `evaluated` with half of the variables unread. Worker and Pages
-- findings stay separate (own fingerprints and subjects, and a change on one
-- side never opens or resolves a finding on the other), but without complete
-- `pages` coverage no Worker finding opens or resolves either. A separate
-- rule ID for Pages would remove that coupling. See
-- docs/decisions/0004-cf-024-scope.md; revisited after S-05.
WITH
worker_var AS (
  SELECT v.props ->> '$.script_node_id'   AS subject_id,
         v.id                             AS version_id,
         var.value ->> '$.name'           AS variable,
         var.value ->> '$.secret_pattern' AS pattern,
         var.value ->> '$.looks_secret'   AS looks_secret
  FROM nodes v, json_each(v.props, '$.plain_text_vars') AS var
  WHERE v.type = 'worker_version' AND v.deleted_at IS NULL
    AND (var.value ->> '$.looks_secret' = 1 OR var.value ->> '$.looks_secret' IS NULL)
),
worker_candidate AS (
  SELECT w.*, max(w.looks_secret IS 1) OVER (PARTITION BY w.subject_id) AS decided
  FROM worker_var w
  JOIN nodes s ON s.id = w.subject_id AND s.type = 'worker_script' AND s.deleted_at IS NULL
),
pages_candidate AS (
  SELECT p.id                             AS subject_id,
         var.value ->> '$.environment'    AS environment,
         var.value ->> '$.name'           AS variable,
         var.value ->> '$.kind'           AS kind,
         var.value ->> '$.secret_pattern' AS pattern,
         var.value ->> '$.looks_secret'   AS looks_secret,
         max(var.value ->> '$.looks_secret' IS 1) OVER (PARTITION BY p.id) AS decided
  FROM nodes p, json_each(p.props, '$.plain_text_vars') AS var
  WHERE p.type = 'pages_project' AND p.deleted_at IS NULL
    AND (var.value ->> '$.looks_secret' = 1 OR var.value ->> '$.looks_secret' IS NULL)
)
SELECT
  'CF-024'                                AS rule_id,
  'CF-024:' || subject_id                 AS fingerprint,
  'medium'                                AS severity,
  subject_id                              AS subject_id,
  decided                                 AS decided,
  json_group_array(DISTINCT variable)     AS variables,
  json_group_array(DISTINCT pattern) FILTER (WHERE pattern IS NOT NULL) AS patterns,
  json_group_array(DISTINCT version_id)   AS versions
FROM worker_candidate
WHERE looks_secret IS 1 OR NOT decided
GROUP BY subject_id
UNION ALL
SELECT
  'CF-024',
  'CF-024:' || subject_id,
  'medium',
  subject_id,
  decided,
  json_group_array(json_object('environment', environment, 'name', variable, 'kind', kind,
                               'secret_pattern', pattern)),
  json_group_array(DISTINCT pattern) FILTER (WHERE pattern IS NOT NULL),
  NULL
FROM pages_candidate
WHERE looks_secret IS 1 OR NOT decided
GROUP BY subject_id
