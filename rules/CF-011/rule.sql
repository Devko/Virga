-- ---
-- id: CF-011
-- version: 2
-- title: Bypass policy on an app that reaches data or a tunnel
-- severity: high
-- kind: toxic
-- requires: [access, workers, pages, storage, tunnels]
-- enriches: null
-- ---
-- Bypass policies run before all others, enforce nothing and are not logged,
-- whoever they include. A Bypass policy qualifies when one of its apps covers
-- a whole host, or a whole Worker through Worker-level Access, and that
-- target
-- - serves a Worker version with a data store binding (routes, Custom
--   Domains and workers.dev serve the versions with a traffic share, version
--   URLs their version, Worker-level Access all of them or only the previews),
-- - serves a Pages environment with a data store binding, or
-- - is a tunnel hostname.
-- A hostname target covers the whole host when its path is empty, `/` or
-- `/*`. Apps whose hostname targets all carry a narrower path are left out:
-- a path app for the truly public paths is the remedy this rule proposes.
-- Hostname targets match entry points exactly, or through a `*.` wildcard
-- that covers one label, as Access does. One finding per policy.
--
-- These are the public targets; private destinations follow in phase 3.
WITH
store_type(type) AS (
  VALUES ('r2_bucket'), ('d1_database'), ('kv_namespace'), ('do_namespace'),
         ('hyperdrive_config'), ('secrets_store_secret')
),
bypass_policy AS (
  SELECT p.id AS policy_id, p.props
  FROM nodes p
  WHERE p.type = 'access_policy' AND p.deleted_at IS NULL
    AND p.props ->> '$.decision' = 'bypass'
),
target AS (
  SELECT a.id AS app_id,
         t.value ->> '$.kind'                      AS kind,
         lower(t.value ->> '$.host')               AS host,
         COALESCE(t.value ->> '$.path', '')        AS path,
         'worker_script:' || (t.value ->> '$.script') AS script_id,
         COALESCE(t.value ->> '$.scope', 'all')    AS scope
  FROM nodes a, json_each(a.props, '$.targets') t
  WHERE a.type = 'access_app' AND a.deleted_at IS NULL
),
entry AS (
  SELECT id AS entry_id, type,
         lower(CASE type
           WHEN 'worker_route' THEN substr(route, 1, instr(route || '/', '/') - 1)
           WHEN 'worker_custom_domain' THEN props ->> '$.hostname'
           WHEN 'tunnel_hostname' THEN props ->> '$.hostname'
           ELSE native_id
         END) AS host
  FROM (
    SELECT n.*,
           CASE
             WHEN n.props ->> '$.pattern' LIKE 'https://%' THEN substr(n.props ->> '$.pattern', 9)
             WHEN n.props ->> '$.pattern' LIKE 'http://%' THEN substr(n.props ->> '$.pattern', 8)
             ELSE n.props ->> '$.pattern'
           END AS route
    FROM nodes n
    WHERE n.deleted_at IS NULL
      AND n.type IN ('worker_route', 'worker_custom_domain', 'workers_dev', 'worker_preview_url',
                     'pages_domain', 'pages_preview', 'tunnel_hostname')
  )
),
app_entry AS (
  SELECT tg.app_id, en.entry_id
  FROM target tg
  JOIN entry en ON tg.kind = 'hostname' AND tg.path IN ('', '/', '/*')
   AND (tg.host = en.host
        OR (substr(tg.host, 1, 2) = '*.'
            AND length(en.host) > length(tg.host) - 1
            AND substr(en.host, 1 - length(tg.host)) = substr(tg.host, 2)
            AND instr(substr(en.host, 1, length(en.host) - length(tg.host) + 1), '.') = 0))
),
version_store AS (
  SELECT b.src AS version_id, b.dst AS store_id
  FROM edges b
  JOIN nodes v ON v.id = b.src AND v.type = 'worker_version' AND v.deleted_at IS NULL
  JOIN nodes t ON t.id = b.dst AND t.deleted_at IS NULL
  WHERE b.type = 'BINDS' AND b.deleted_at IS NULL
    AND t.type IN (SELECT type FROM store_type)
),
script_version AS (
  -- versions with a traffic share, and versions behind version URLs
  SELECT d.src AS script_id, d.dst AS version_id, 'deployment' AS via
  FROM edges d
  WHERE d.type = 'DEPLOYS' AND d.deleted_at IS NULL
    AND COALESCE(d.props ->> '$.percentage', 100) > 0
  UNION
  SELECT v.props ->> '$.script_node_id', v.id, 'preview'
  FROM edges r
  JOIN nodes p ON p.id = r.src AND p.type = 'worker_preview_url' AND p.deleted_at IS NULL
  JOIN nodes v ON v.id = r.dst AND v.type = 'worker_version' AND v.deleted_at IS NULL
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
),
entry_store AS (
  -- route, Custom Domain, workers.dev -> versions with a traffic share
  SELECT r.src AS entry_id, vs.store_id
  FROM edges r
  JOIN script_version sv ON sv.script_id = r.dst AND sv.via = 'deployment'
  JOIN version_store vs ON vs.version_id = sv.version_id
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
  UNION
  -- version URL -> its version
  SELECT r.src, vs.store_id
  FROM edges r
  JOIN version_store vs ON vs.version_id = r.dst
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
  UNION
  -- Pages domain or preview -> bindings of the environment it serves
  SELECT r.src, b.dst
  FROM edges r
  JOIN edges b ON b.src = r.dst AND b.type = 'BINDS' AND b.deleted_at IS NULL
              AND b.props ->> '$.environment' = r.props ->> '$.environment'
  JOIN nodes t ON t.id = b.dst AND t.deleted_at IS NULL
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
    AND t.type IN (SELECT type FROM store_type)
),
reach AS (
  SELECT ae.app_id, ae.entry_id, es.store_id, NULL AS tunnel_hostname
  FROM app_entry ae
  JOIN entry_store es ON es.entry_id = ae.entry_id
  UNION ALL
  SELECT ae.app_id, ae.entry_id, NULL, ae.entry_id
  FROM app_entry ae
  JOIN nodes h ON h.id = ae.entry_id AND h.type = 'tunnel_hostname'
  UNION ALL
  -- Worker-level Access
  SELECT tg.app_id, NULL, vs.store_id, NULL
  FROM target tg
  JOIN script_version sv ON sv.script_id = tg.script_id
   AND (tg.scope = 'all' OR sv.via = 'preview')
  JOIN version_store vs ON vs.version_id = sv.version_id
  WHERE tg.kind = 'worker'
)
SELECT
  'CF-011'                                   AS rule_id,
  'CF-011:' || bp.policy_id                  AS fingerprint,
  'high'                                     AS severity,
  bp.policy_id                               AS subject_id,
  (SELECT json_group_array(DISTINCT COALESCE(i.value ->> '$.kind', 'other'))
   FROM json_each(bp.props, '$.include') i)  AS includes,
  json_group_array(DISTINCT rc.app_id)       AS apps,
  json_group_array(DISTINCT rc.entry_id) FILTER (WHERE rc.entry_id IS NOT NULL)
                                             AS entry_points,
  json_group_array(DISTINCT rc.store_id) FILTER (WHERE rc.store_id IS NOT NULL)
                                             AS data_stores,
  json_group_array(DISTINCT rc.tunnel_hostname) FILTER (WHERE rc.tunnel_hostname IS NOT NULL)
                                             AS tunnel_hostnames
FROM bypass_policy bp
JOIN edges al ON al.src = bp.policy_id AND al.type = 'ALLOWS' AND al.deleted_at IS NULL
JOIN reach rc ON rc.app_id = al.dst
GROUP BY bp.policy_id
