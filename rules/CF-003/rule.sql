-- ---
-- id: CF-003
-- version: 3
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
--    nothing, and neither do 0.0.0.0/1 plus 128.0.0.0/1. An IPv6 entry
--    inside the IPv4-mapped block ::ffff:0:0/96 is read as an IPv4 range of
--    n - 96 bits, and one whose range holds that whole block, such as ::/64,
--    admits every IPv4 client. Both hold for every spelling of IPv6, not
--    only the canonical one the tokens collector writes (R4-06). An entry
--    that does not parse as an address with a prefix limits nothing: IPv4
--    needs four decimal octets up to 255 without leading zeros, IPv6 eight
--    groups of up to four hex digits, at most one `::`, and an optional
--    dotted IPv4 part at the end. `wide_allowed_ips` lists the entries that
--    limit nothing as stored (R2-08).
-- Critical when the token was not used for :unused_days days (or never, and
-- was issued that long ago), or when a risky grant covers all zones of the
-- account. A token without a `last_used_on` signal counts as never used: the
-- API omits the field for unused tokens, and the tokens class is complete.
--
-- Permission groups are matched by name. The API reference calls names
-- cosmetic and recommends IDs, but documents no ID list. Dashboard names end
-- in "Edit" and API names in "Write", so both forms match.
--
-- The address CTEs are MATERIALIZED: inlined into each other they compile
-- to more than 20,000 operations, which Durable Object SQLite refuses.
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
allow_entry AS MATERIALIZED (
  -- entries of each `in` list: the address, its prefix length (the full
  -- length when absent, -1 when it is no number) and the dotted quad it ends
  -- with, which is the whole of an IPv4 address
  SELECT token_id, entry_key, entry, address,
         substr(address, length(rtrim(address, '0123456789.')) + 1) AS tail,
         CASE
           WHEN bits IS NULL THEN CASE WHEN instr(address, ':') > 0 THEN 128 ELSE 32 END
           WHEN bits <> '' AND bits NOT GLOB '*[^0-9]*' AND length(bits) <= 3
             THEN CAST(bits AS INTEGER)
           ELSE -1
         END AS prefix
  FROM (
    SELECT token_id, entry_key, entry,
           CASE WHEN instr(s, '/') > 0 THEN substr(s, 1, instr(s, '/') - 1) ELSE s END AS address,
           CASE WHEN instr(s, '/') > 0 THEN substr(s, instr(s, '/') + 1) END AS bits
    FROM (
      SELECT t.id AS token_id, e.key AS entry_key, e.value AS entry,
             CASE e.type WHEN 'text' THEN lower(trim(e.value)) ELSE '' END AS s
      FROM nodes t, json_each(t.props, '$.ip_condition.in') e
      WHERE t.type = 'account_token' AND t.deleted_at IS NULL
        AND json_type(t.props, '$.ip_condition.in') = 'array'
    )
  )
),
quad AS MATERIALIZED (
  -- that dotted quad as a 32-bit number, or NULL when it is not four octets;
  -- it holds only digits and dots, so the JSON array is always valid
  SELECT a.token_id, a.entry_key,
         CASE
           WHEN count(*) = 4 AND min(o.value GLOB '[0-9]' OR o.value GLOB '[1-9][0-9]'
                                     OR (o.value GLOB '[12][0-9][0-9]' AND CAST(o.value AS INTEGER) <= 255))
             THEN sum(CAST(o.value AS INTEGER) << (24 - 8 * o.key))
         END AS v4
  FROM allow_entry a, json_each('["' || replace(a.tail, '.', '","') || '"]') o
  WHERE instr(a.tail, '.') > 0
  GROUP BY a.token_id, a.entry_key
),
v6_text AS MATERIALIZED (
  -- an IPv6 address with its IPv4 part as two hex groups, split at `::`;
  -- NULL when it holds any other character
  SELECT token_id, entry_key, h,
         CASE WHEN instr(h, '::') > 0 THEN substr(h, 1, instr(h, '::') - 1) ELSE h END AS head,
         CASE WHEN instr(h, '::') > 0 THEN substr(h, instr(h, '::') + 2) ELSE '' END AS rest
  FROM (
    SELECT token_id, entry_key, CASE WHEN h NOT GLOB '*[^0-9a-f:]*' THEN h END AS h
    FROM (
      SELECT a.token_id, a.entry_key,
             CASE
               WHEN instr(a.tail, '.') = 0 THEN a.address
               -- the IPv4 part follows a colon, or a hex digit would join it
               WHEN q.v4 IS NOT NULL AND a.address GLOB ('*:' || a.tail)
                 THEN substr(a.address, 1, length(a.address) - length(a.tail))
                      || printf('%x:%x', q.v4 >> 16, q.v4 & 65535)
             END AS h
      FROM allow_entry a
      LEFT JOIN quad q ON q.token_id = a.token_id AND q.entry_key = a.entry_key
      WHERE instr(a.address, ':') > 0
    )
  )
),
v6_group AS MATERIALIZED (
  -- one row per address, then one per group: those before `::` count from
  -- the start, those after it from the end
  SELECT token_id, entry_key, h, NULL AS pos, NULL AS hex FROM v6_text
  UNION ALL
  SELECT x.token_id, x.entry_key, x.h, g.key, g.value
  FROM v6_text x,
       json_each(CASE WHEN x.head <> '' THEN '["' || replace(x.head, ':', '","') || '"]' END) g
  UNION ALL
  SELECT x.token_id, x.entry_key, x.h,
         8 - (length(x.rest) - length(replace(x.rest, ':', '')) + 1) + g.key, g.value
  FROM v6_text x,
       json_each(CASE WHEN x.rest <> '' THEN '["' || replace(x.rest, ':', '","') || '"]' END) g
),
v6 AS MATERIALIZED (
  -- whether the groups make an address, and the first six of them
  SELECT token_id, entry_key,
         max(h) IS NOT NULL AND count(value) = count(hex)
           AND CASE WHEN instr(max(h), '::') > 0 THEN count(hex) <= 7 ELSE count(hex) = 8 END
           AS valid,
         COALESCE(max(CASE pos WHEN 0 THEN value END), 0) AS g0,
         COALESCE(max(CASE pos WHEN 1 THEN value END), 0) AS g1,
         COALESCE(max(CASE pos WHEN 2 THEN value END), 0) AS g2,
         COALESCE(max(CASE pos WHEN 3 THEN value END), 0) AS g3,
         COALESCE(max(CASE pos WHEN 4 THEN value END), 0) AS g4,
         COALESCE(max(CASE pos WHEN 5 THEN value END), 0) AS g5
  FROM (
    SELECT token_id, entry_key, h, pos, hex,
           CASE WHEN length(hex) BETWEEN 1 AND 4 THEN
             (instr('0123456789abcdef', substr(h4, 1, 1)) - 1) * 4096
             + (instr('0123456789abcdef', substr(h4, 2, 1)) - 1) * 256
             + (instr('0123456789abcdef', substr(h4, 3, 1)) - 1) * 16
             + (instr('0123456789abcdef', substr(h4, 4, 1)) - 1)
           END AS value
    FROM (SELECT *, substr('000' || hex, -4) AS h4 FROM v6_group)
  )
  GROUP BY token_id, entry_key
),
allow_range AS MATERIALIZED (
  SELECT a.token_id, a.entry,
         CASE
           WHEN instr(a.address, ':') = 0
             THEN a.tail = a.address AND q.v4 IS NOT NULL
                  AND a.prefix BETWEEN :min_ipv4_prefix AND 32
           WHEN NOT COALESCE(v.valid, 0) OR a.prefix NOT BETWEEN 0 AND 128 THEN 0
           -- the range holds all of ::ffff:0:0/96 (80 zero bits, then 16 one
           -- bits) when its first `prefix` bits are those of that block
           WHEN a.prefix <= 96
            AND (v.g0 >> (16 - max(0, min(16, a.prefix)))) = 0
            AND (v.g1 >> (16 - max(0, min(16, a.prefix - 16)))) = 0
            AND (v.g2 >> (16 - max(0, min(16, a.prefix - 32)))) = 0
            AND (v.g3 >> (16 - max(0, min(16, a.prefix - 48)))) = 0
            AND (v.g4 >> (16 - max(0, min(16, a.prefix - 64)))) = 0
            AND ((65535 - v.g5) >> (16 - max(0, min(16, a.prefix - 80)))) = 0
             THEN 0
           WHEN v.g0 = 0 AND v.g1 = 0 AND v.g2 = 0 AND v.g3 = 0 AND v.g4 = 0 AND v.g5 = 65535
             THEN a.prefix - 96 BETWEEN :min_ipv4_prefix AND 32
           ELSE a.prefix BETWEEN :min_ipv6_prefix AND 128
         END AS limits
  FROM allow_entry a
  LEFT JOIN quad q ON q.token_id = a.token_id AND q.entry_key = a.entry_key
  LEFT JOIN v6 v ON v.token_id = a.token_id AND v.entry_key = a.entry_key
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
