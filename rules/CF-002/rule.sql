-- ---
-- id: CF-002
-- version: 2
-- title: Worker protected by Access on one entry point and reachable around it on another
-- severity: high
-- kind: toxic
-- requires: [workers, access, exposure]
-- enriches: null
-- ---
-- Two ways for one Worker's protected code to be reached without Access:
--
-- 1. A path that the exposure evaluator decides `access` or `service_auth` on
--    one entry point is decided `public` on another: workers.dev, a version
--    URL, an extra route or Custom Domain. Each entry point is judged by the
--    exposure row with the longest prefix that covers the path, so a host
--    that protects /admin everywhere is not reported. `unknown` is never
--    public or protected: when it stands on either side, the path would be
--    such a gap if the unknown went one way, so the pair is undecided.
-- 2. The Worker has Worker-level Access, but an Access app with a hostname
--    target on one of its entry points carries a Bypass policy or an Allow
--    policy that includes Everyone. Hostname and path apps take precedence
--    over Worker-level Access. Host matching is exact, or a `*.` wildcard
--    that covers one label, as Access does.
--
-- One finding per Worker. A Worker with only undecided pairs returns an
-- undecided row (decided = 0) that lists them; one decided pair or override
-- decides it. A route that only serves part of a host (for example
-- example.com/api/*) is compared on the whole host; the graph does not split
-- exposure by route path.
WITH
entry AS (
  -- route, Custom Domain, workers.dev -> script
  SELECT r.src AS entry_id, r.dst AS script_id, e.type, e.native_id, e.props
  FROM edges r
  JOIN nodes e ON e.id = r.src AND e.deleted_at IS NULL
  JOIN nodes s ON s.id = r.dst AND s.type = 'worker_script' AND s.deleted_at IS NULL
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
  UNION
  -- version URL -> the version's script
  SELECT r.src, v.props ->> '$.script_node_id', e.type, e.native_id, e.props
  FROM edges r
  JOIN nodes e ON e.id = r.src AND e.deleted_at IS NULL
  JOIN nodes v ON v.id = r.dst AND v.type = 'worker_version' AND v.deleted_at IS NULL
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
),
decision AS (
  SELECT en.script_id, x.entry_id, x.path_prefix, rtrim(x.path_prefix, '/') AS prefix,
         x.decision, x.confidence
  FROM entry en
  JOIN exposure x ON x.entry_id = en.entry_id
),
point AS (
  SELECT DISTINCT script_id, path_prefix AS path, rtrim(path_prefix, '/') AS norm
  FROM decision
),
-- For every path any entry point of the Worker decides, the row of each entry
-- point that decides it.
judged AS (
  SELECT pt.script_id, pt.path, d.entry_id, d.decision, d.confidence,
         row_number() OVER (
           PARTITION BY pt.script_id, pt.path, d.entry_id ORDER BY length(d.prefix) DESC
         ) AS pos
  FROM point pt
  JOIN decision d ON d.script_id = pt.script_id
   AND (d.prefix = '' OR pt.norm = d.prefix
        OR substr(pt.norm, 1, length(d.prefix) + 1) = d.prefix || '/')
),
around_access AS (
  SELECT a.script_id, a.path, a.entry_id AS protected_entry, b.entry_id AS public_entry,
         min(a.confidence, b.confidence) AS confidence,
         a.decision <> 'unknown' AND b.decision <> 'unknown' AS decided
  FROM judged a
  JOIN judged b ON b.script_id = a.script_id AND b.path = a.path AND b.entry_id <> a.entry_id
  WHERE a.pos = 1 AND b.pos = 1
    AND a.decision IN ('access', 'service_auth', 'unknown') AND b.decision IN ('public', 'unknown')
),
worker_access AS (
  SELECT a.id AS app_id, 'worker_script:' || (t.value ->> '$.script') AS script_id
  FROM nodes a, json_each(a.props, '$.targets') t
  WHERE a.type = 'access_app' AND a.deleted_at IS NULL
    AND t.value ->> '$.kind' = 'worker'
),
open_host_target AS (
  -- hostname targets of apps with a Bypass policy or an Allow policy for Everyone
  SELECT a.id AS app_id, lower(t.value ->> '$.host') AS host
  FROM nodes a, json_each(a.props, '$.targets') t
  WHERE a.type = 'access_app' AND a.deleted_at IS NULL
    AND t.value ->> '$.kind' = 'hostname'
    AND EXISTS (
      SELECT 1
      FROM edges al
      JOIN nodes p ON p.id = al.src AND p.type = 'access_policy' AND p.deleted_at IS NULL
      WHERE al.dst = a.id AND al.type = 'ALLOWS' AND al.deleted_at IS NULL
        AND (p.props ->> '$.decision' = 'bypass'
             OR (p.props ->> '$.decision' = 'allow'
                 AND EXISTS (SELECT 1 FROM json_each(p.props, '$.include') i
                             WHERE i.value ->> '$.kind' = 'everyone')))
    )
),
entry_host AS (
  SELECT entry_id, script_id,
         lower(CASE type
           WHEN 'worker_route' THEN substr(route, 1, instr(route || '/', '/') - 1)
           WHEN 'worker_custom_domain' THEN props ->> '$.hostname'
           ELSE native_id
         END) AS host
  FROM (
    SELECT en.*,
           CASE
             WHEN en.props ->> '$.pattern' LIKE 'https://%' THEN substr(en.props ->> '$.pattern', 9)
             WHEN en.props ->> '$.pattern' LIKE 'http://%' THEN substr(en.props ->> '$.pattern', 8)
             ELSE en.props ->> '$.pattern'
           END AS route
    FROM entry en
  )
),
overridden AS (
  SELECT eh.script_id, eh.entry_id, ht.app_id
  FROM entry_host eh
  JOIN worker_access wa ON wa.script_id = eh.script_id
  JOIN open_host_target ht ON ht.app_id <> wa.app_id
   AND (ht.host = eh.host
        OR (substr(ht.host, 1, 2) = '*.'
            AND length(eh.host) > length(ht.host) - 1
            AND substr(eh.host, 1 - length(ht.host)) = substr(ht.host, 2)
            AND instr(substr(eh.host, 1, length(eh.host) - length(ht.host) + 1), '.') = 0))
),
hit AS (
  SELECT script_id, path, protected_entry, public_entry, NULL AS overridden_entry,
         NULL AS app_id, confidence, decided
  FROM around_access
  UNION ALL
  SELECT script_id, NULL, NULL, NULL, entry_id, app_id, NULL, 1
  FROM overridden
),
deciding AS (
  SELECT h.*, max(h.decided) OVER (PARTITION BY h.script_id) AS script_decided
  FROM hit h
)
SELECT
  'CF-002'                  AS rule_id,
  'CF-002:' || script_id    AS fingerprint,
  'high'                    AS severity,
  script_id                 AS subject_id,
  max(decided)              AS decided,
  json_group_array(DISTINCT protected_entry) FILTER (WHERE protected_entry IS NOT NULL)
                            AS protected_entry_points,
  json_group_array(DISTINCT public_entry) FILTER (WHERE public_entry IS NOT NULL)
                            AS public_entry_points,
  json_group_array(DISTINCT path) FILTER (WHERE path IS NOT NULL)
                            AS paths,
  json_group_array(DISTINCT overridden_entry) FILTER (WHERE overridden_entry IS NOT NULL)
                            AS overridden_entry_points,
  json_group_array(DISTINCT app_id) FILTER (WHERE app_id IS NOT NULL)
                            AS overriding_apps,
  min(confidence)           AS exposure_confidence
FROM deciding
-- decided pairs and overrides make up a decided row; undecided pairs only without them
WHERE decided = 1 OR script_decided = 0
GROUP BY script_id
