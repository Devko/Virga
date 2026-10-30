-- ---
-- id: CF-003
-- version: 2
-- title: Long-lived account token with a high-risk write permission and no IP restriction
-- severity: high
-- kind: posture
-- requires: [tokens]
-- params:
--   max_days: 90         # tokens expiring later than this count as long-lived
--   unused_days: 90      # unused this long raises the severity
--   now_ms: 0            # evaluation time in epoch ms; 0 means the start of the current scan
--   min_ipv4_prefix: 8   # shortest IPv4 prefix that still limits where a token works
--   min_ipv6_prefix: 32  # the same for IPv6
-- enriches: null
-- ---
-- An active account token qualifies when
-- 1. an allow policy grants a write or edit permission group for Workers
--    scripts or routes, DNS, Access, account settings, API tokens, Logs,
--    Secrets Store, or Zero Trust (including Tunnel and the Cloudflare One
--    networks and connectors),
-- 2. it never expires, or expires more than :max_days days after the
--    evaluation time, and
-- 3. no IP condition limits where it may be used from. Only an `in` list
--    restricts; a `not_in` list alone still admits the rest of the internet.
--    An `in` list limits the token only when no entry is wider than
--    min_ipv4_prefix (/8) for IPv4 or min_ipv6_prefix (/32) for IPv6; a
--    single address counts as /32 or /128. So 0.0.0.0/0 and ::/0 limit
--    nothing, and neither do 0.0.0.0/1 plus 128.0.0.0/1. An IPv4-mapped
--    entry (::ffff:a.b.c.d/n) is read as an IPv4 range of n - 96 bits. An
--    entry that does not parse as an address with a prefix limits nothing.
--    `wide_allowed_ips` lists the entries that limit nothing (R2-08).
-- Critical when the token was not used for :unused_days days (or never, and
-- was issued that long ago), or when a risky grant covers all zones of the
-- account. A token without a `last_used_on` signal counts as never used: the
-- API omits the field for unused tokens, and the tokens class is complete.
--
-- Permission groups are matched by name. The API reference calls names
-- cosmetic and recommends IDs, but documents no ID list. Dashboard names end
-- in "Edit" and API names in "Write", so both forms match.
WITH
clock(now_ms) AS (
  SELECT CASE WHEN :now_ms > 0 THEN :now_ms ELSE COALESCE(
    (SELECT s.started_at FROM scans s JOIN meta m ON m.key = 'current_scan' AND m.value = s.id),
    0) END
),
risky_group(name) AS (
  VALUES ('Workers Scripts'), ('Workers Routes'), ('DNS'), ('Account Settings'),
         ('Account API Tokens'), ('API Tokens'), ('Logs'), ('Secrets Store'), ('Zero Trust'),
         ('Cloudflare Tunnel'), ('Cloudflare One Networks'), ('Cloudflare One Connectors'),
         ('Cloudflare One Connector: cloudflared'), ('Cloudflare One Connector: WARP')
),
risky_name(name) AS (
  SELECT name || ' Write' FROM risky_group
  UNION ALL
  SELECT name || ' Edit' FROM risky_group
),
allow_entry AS (
  -- entries of each `in` list, split into address and prefix length
  SELECT token_id, entry, address,
         CASE
           WHEN bits IS NULL THEN NULL
           WHEN bits <> '' AND bits NOT GLOB '*[^0-9]*' AND length(bits) <= 3
             THEN CAST(bits AS INTEGER)
           ELSE -1
         END AS bits
  FROM (
    SELECT token_id, entry,
           CASE WHEN instr(s, '/') > 0 THEN substr(s, 1, instr(s, '/') - 1) ELSE s END AS address,
           CASE WHEN instr(s, '/') > 0 THEN substr(s, instr(s, '/') + 1) END AS bits
    FROM (
      SELECT t.id AS token_id, e.value AS entry,
             CASE e.type WHEN 'text' THEN lower(trim(e.value)) ELSE '' END AS s
      FROM nodes t, json_each(t.props, '$.ip_condition.in') e
      WHERE t.type = 'account_token' AND t.deleted_at IS NULL
        AND json_type(t.props, '$.ip_condition.in') = 'array'
    )
  )
),
allow_range AS (
  SELECT token_id, entry,
         CASE
           WHEN address NOT GLOB '*[^0-9.]*' AND address GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
             THEN COALESCE(bits, 32) BETWEEN :min_ipv4_prefix AND 32
           WHEN address GLOB '::ffff:*' AND address NOT GLOB '*[^0-9a-f:.]*'
             THEN COALESCE(bits, 128) - 96 BETWEEN :min_ipv4_prefix AND 32
           WHEN instr(address, ':') > 0 AND address NOT GLOB '*[^0-9a-f:.]*'
             THEN COALESCE(bits, 128) BETWEEN :min_ipv6_prefix AND 128
           ELSE 0
         END AS limits
  FROM allow_entry
),
ip_limited AS (
  SELECT token_id FROM allow_range GROUP BY token_id HAVING min(limits) = 1
),
token AS (
  SELECT t.id, t.props,
         unixepoch(t.props ->> '$.expires_on') * 1000 AS expires_ms,
         unixepoch(t.props ->> '$.issued_on') * 1000  AS issued_ms
  FROM nodes t
  WHERE t.type = 'account_token' AND t.deleted_at IS NULL
    AND t.props ->> '$.status' = 'active'
    AND t.id NOT IN (SELECT token_id FROM ip_limited)
),
long_lived AS (
  SELECT tk.*
  FROM token tk, clock c
  WHERE tk.props ->> '$.expires_on' IS NULL
     OR tk.expires_ms > c.now_ms + :max_days * 86400000
),
risky_grant AS (
  SELECT ll.id AS token_id,
         pg.value ->> '$.name' AS permission,
         EXISTS (
           SELECT 1 FROM json_tree(pol.value, '$.resources') r
           WHERE r.key = 'com.cloudflare.api.account.zone.*'
         ) AS all_zones
  FROM long_lived ll,
       json_each(ll.props, '$.policies') pol,
       json_each(pol.value, '$.permission_groups') pg
  WHERE pol.value ->> '$.effect' = 'allow'
    AND (
      pg.value ->> '$.name' IN (SELECT name FROM risky_name)
      OR (pg.value ->> '$.name' LIKE 'Access: %'
          AND (pg.value ->> '$.name' LIKE '% Write' OR pg.value ->> '$.name' LIKE '% Edit'))
    )
)
SELECT
  'CF-003'                                    AS rule_id,
  'CF-003:' || rg.token_id                    AS fingerprint,
  CASE
    WHEN max(rg.all_zones) = 1 THEN 'critical'
    WHEN COALESCE(sg.value, ll.issued_ms) < c.now_ms - :unused_days * 86400000 THEN 'critical'
    ELSE 'high'
  END                                         AS severity,
  rg.token_id                                 AS subject_id,
  json_group_array(DISTINCT rg.permission)    AS permissions,
  ll.props ->> '$.expires_on'                 AS expires_on,
  sg.value                                    AS last_used_ms,
  max(rg.all_zones)                           AS all_zones,
  (SELECT json_group_array(ar.entry) FROM allow_range ar
   WHERE ar.token_id = rg.token_id AND NOT ar.limits)
                                              AS wide_allowed_ips
FROM risky_grant rg
JOIN long_lived ll ON ll.id = rg.token_id
LEFT JOIN signals sg ON sg.node_id = rg.token_id AND sg.name = 'last_used_on'
CROSS JOIN clock c
GROUP BY rg.token_id
