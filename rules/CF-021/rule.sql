-- ---
-- id: CF-021
-- version: 3
-- title: R2 bucket public through r2.dev or a custom domain without Access
-- severity: high
-- kind: posture
-- requires: [storage, access, exposure]
-- enriches: null
-- ---
-- A bucket is public when its managed r2.dev domain is enabled, which Access
-- cannot protect, or when the exposure evaluator decides one of its enabled
-- custom domains `public` on any path prefix. `unknown` is never public: a
-- bucket whose enabled custom domains include one with an unknown prefix,
-- and that is not public otherwise, is undecided (decided = 0), and its row
-- lists those domains. Access is required, as for every rule that reads
-- exposure: without its coverage every custom domain is `unknown`. One
-- finding per bucket.
--
-- A domain counts unless `enabled` is exactly false. One whose enabled state
-- is unknown (null, missing or not a boolean), r2.dev or custom, would make
-- the bucket public if it were enabled, so it can only make the row
-- undecided; the evaluator decides such a domain `unknown` as well (R4-02).
WITH
domain AS (
  SELECT d.id AS domain_id, d.name AS host, d.props ->> '$.kind' AS kind, r.dst AS bucket_id,
         json_type(d.props, '$.enabled') IS 'true' AS enabled
  FROM nodes d
  JOIN edges r ON r.src = d.id AND r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
  JOIN nodes b ON b.id = r.dst AND b.type = 'r2_bucket' AND b.deleted_at IS NULL
  WHERE d.type = 'r2_public_domain' AND d.deleted_at IS NULL
    AND json_type(d.props, '$.enabled') IS NOT 'false'
),
exposed_domain AS (
  SELECT domain_id, host, kind, bucket_id, NULL AS confidence, enabled AS decided
  FROM domain
  WHERE kind = 'r2_dev'
  UNION
  SELECT dm.domain_id, dm.host, dm.kind, dm.bucket_id, x.confidence,
         x.decision = 'public' AND dm.enabled
  FROM domain dm
  JOIN exposure x ON x.entry_id = dm.domain_id AND x.decision IN ('public', 'unknown')
  WHERE dm.kind = 'custom'
),
deciding AS (
  SELECT d.*, max(d.decided) OVER (PARTITION BY d.bucket_id) AS bucket_decided
  FROM exposed_domain d
)
SELECT
  'CF-021'                                 AS rule_id,
  'CF-021:' || bucket_id                   AS fingerprint,
  'high'                                   AS severity,
  bucket_id                                AS subject_id,
  max(decided)                             AS decided,
  json_group_array(DISTINCT host)          AS domains,
  json_group_array(DISTINCT domain_id)     AS domain_ids,
  max(kind = 'r2_dev')                     AS r2_dev_enabled,
  min(confidence)                          AS exposure_confidence
FROM deciding
-- public domains decide a bucket; the unknown ones only when there is none
WHERE decided = 1 OR bucket_decided = 0
GROUP BY bucket_id
