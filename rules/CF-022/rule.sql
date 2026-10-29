-- ---
-- id: CF-022
-- version: 2
-- title: Pages project with public preview deployments and bindings to production
-- severity: medium
-- kind: posture
-- requires: [pages, access, exposure]
-- enriches: null
-- ---
-- Preview deployments run the code of any branch. A project qualifies when the
-- exposure evaluator decides its preview wildcard (`*.<project>.pages.dev`)
-- `public` on any path prefix, and its preview environment binds a resource
-- that its production environment binds too: a data store, queue, or a
-- Worker through a service binding. Comparing binding targets needs only the
-- Pages edges, so the target nodes are not read. `unknown` exposure is never
-- public: a project that would qualify if an unknown prefix of its preview
-- wildcard were public is undecided (decided = 0). Access is required for the
-- same reason as in CF-021. One finding per project.
WITH
preview AS (
  SELECT r.dst AS project_id, e.name AS host, x.confidence, x.decision = 'public' AS decided,
         max(x.decision = 'public') OVER (PARTITION BY r.dst) AS project_decided
  FROM nodes e
  JOIN edges r ON r.src = e.id AND r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
  JOIN nodes p ON p.id = r.dst AND p.type = 'pages_project' AND p.deleted_at IS NULL
  JOIN exposure x ON x.entry_id = e.id AND x.decision IN ('public', 'unknown')
  WHERE e.type = 'pages_preview' AND e.deleted_at IS NULL
),
shared AS (
  -- keys are `<environment>:<binding name>`
  SELECT pv.src AS project_id, pv.dst AS target_id,
         substr(pv.key, length('preview:') + 1) AS binding
  FROM edges pv
  JOIN edges pr ON pr.src = pv.src AND pr.dst = pv.dst AND pr.type = 'BINDS'
               AND pr.deleted_at IS NULL AND pr.props ->> '$.environment' = 'production'
  WHERE pv.type = 'BINDS' AND pv.deleted_at IS NULL
    AND pv.props ->> '$.environment' = 'preview'
)
SELECT
  'CF-022'                                AS rule_id,
  'CF-022:' || pv.project_id              AS fingerprint,
  'medium'                                AS severity,
  pv.project_id                           AS subject_id,
  max(pv.decided)                         AS decided,
  json_group_array(DISTINCT pv.host)      AS previews,
  json_group_array(DISTINCT sh.binding)   AS preview_bindings,
  json_group_array(DISTINCT sh.target_id) AS production_targets,
  min(pv.confidence)                      AS exposure_confidence
FROM preview pv
JOIN shared sh ON sh.project_id = pv.project_id
-- public prefixes decide a project; the unknown ones only when there is none
WHERE pv.decided = 1 OR pv.project_decided = 0
GROUP BY pv.project_id
