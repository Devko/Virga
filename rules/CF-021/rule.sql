-- ---
-- id: CF-021
-- version: 1
-- title: R2 bucket public through r2.dev or a custom domain without Access
-- severity: high
-- kind: posture
-- requires: [storage, access, exposure]
-- enriches: null
-- ---
-- A bucket is public when its managed r2.dev domain is enabled, which Access
-- cannot protect, or when the exposure evaluator decides one of its enabled
-- custom domains `public` on any path prefix. `unknown` never counts. Access
-- is required because without its coverage every custom domain is `unknown`,
-- and an evaluated run would then resolve findings it cannot judge. One
-- finding per bucket.
WITH
domain AS (
  SELECT d.id AS domain_id, d.name AS host, d.props ->> '$.kind' AS kind, r.dst AS bucket_id
  FROM nodes d
  JOIN edges r ON r.src = d.id AND r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
  JOIN nodes b ON b.id = r.dst AND b.type = 'r2_bucket' AND b.deleted_at IS NULL
  WHERE d.type = 'r2_public_domain' AND d.deleted_at IS NULL
    AND d.props ->> '$.enabled' = 1
),
public_domain AS (
  SELECT domain_id, host, kind, bucket_id, NULL AS confidence
  FROM domain
  WHERE kind = 'r2_dev'
  UNION
  SELECT dm.domain_id, dm.host, dm.kind, dm.bucket_id, x.confidence
  FROM domain dm
  JOIN exposure x ON x.entry_id = dm.domain_id AND x.decision = 'public'
  WHERE dm.kind = 'custom'
)
SELECT
  'CF-021'                                 AS rule_id,
  'CF-021:' || bucket_id                   AS fingerprint,
  'high'                                   AS severity,
  bucket_id                                AS subject_id,
  json_group_array(DISTINCT host)          AS domains,
  json_group_array(DISTINCT domain_id)     AS domain_ids,
  max(kind = 'r2_dev')                     AS r2_dev_enabled,
  min(confidence)                          AS exposure_confidence
FROM public_domain
GROUP BY bucket_id
