-- ---
-- id: CF-007
-- version: 1
-- title: Unproxied DNS record exposes the origin of a proxied host
-- severity: medium
-- kind: posture
-- requires: [dns, access]
-- enriches: null
-- ---
-- An unproxied A or AAAA record points to the same address as a proxied
-- record of the account, so anyone can reach that origin directly and skip
-- the proxy and everything on it. High when an Access application covers the
-- proxied host. One finding per unproxied record.
--
-- Addresses that cannot be a reachable origin are left out:
-- - Cloudflare's own ranges (https://www.cloudflare.com/ips-v4 and /ips-v6,
--   2026-10-29),
-- - the Cloudflare Mesh and device range 100.96.0.0/12,
-- - the placeholders for originless setups, 192.0.2.0 and 100::,
-- - private, loopback, link-local and unspecified addresses.
--
-- Gaps:
-- - The spec also raises the severity when WAF rules protect the proxied
--   host. The graph has no rulesets yet, so only Access counts.
-- - The ranges above are reference data inside the query; CIDR containment
--   belongs in a derived input once one exists (A-06).
-- - IPv6 addresses are compared as text, so two spellings of one address do
--   not match, and IPv6 ranges are checked on the first 32 bits.
WITH
record AS (
  SELECT n.id, n.name,
         n.props ->> '$.type'                 AS rtype,
         lower(trim(n.props ->> '$.content')) AS ip,
         n.props ->> '$.proxied'              AS proxied
  FROM nodes n
  WHERE n.type = 'dns_record' AND n.deleted_at IS NULL
    AND n.props ->> '$.type' IN ('A', 'AAAA')
),
-- IPv4 as an integer, through a JSON array: '[a,b,c,d]' is valid JSON only
-- for plain decimal octets without leading zeros.
v4_text(ip, arr) AS (
  SELECT DISTINCT ip, '[' || replace(ip, '.', ',') || ']'
  FROM record
  WHERE rtype = 'A' AND ip NOT GLOB '*[^0-9.]*'
),
v4 AS (
  SELECT ip,
         (arr ->> '$[0]') * 16777216 + (arr ->> '$[1]') * 65536
           + (arr ->> '$[2]') * 256 + (arr ->> '$[3]') AS num
  FROM (SELECT ip, CASE WHEN json_valid(arr) THEN arr END AS arr FROM v4_text)
  WHERE json_array_length(arr) = 4
    AND NOT EXISTS (
      SELECT 1 FROM json_each(arr) o WHERE o.type <> 'integer' OR o.value > 255
    )
),
v4_range(cidr) AS (
  VALUES
    -- Cloudflare
    ('173.245.48.0/20'), ('103.21.244.0/22'), ('103.22.200.0/22'), ('103.31.4.0/22'),
    ('141.101.64.0/18'), ('108.162.192.0/18'), ('190.93.240.0/20'), ('188.114.96.0/20'),
    ('197.234.240.0/22'), ('198.41.128.0/17'), ('162.158.0.0/15'), ('104.16.0.0/13'),
    ('104.24.0.0/14'), ('172.64.0.0/13'), ('131.0.72.0/22'),
    -- Cloudflare Mesh and Cloudflare One Client devices
    ('100.96.0.0/12'),
    -- originless placeholder 192.0.2.0 (RFC 5737)
    ('192.0.2.0/24'),
    -- private, loopback, link-local, "this network"
    ('10.0.0.0/8'), ('172.16.0.0/12'), ('192.168.0.0/16'), ('127.0.0.0/8'),
    ('169.254.0.0/16'), ('0.0.0.0/8')
),
v4_bounds AS (
  SELECT lo, lo + (1 << (32 - len)) - 1 AS hi
  FROM (
    SELECT CAST(substr(cidr, instr(cidr, '/') + 1) AS INTEGER) AS len,
           (arr ->> '$[0]') * 16777216 + (arr ->> '$[1]') * 65536
             + (arr ->> '$[2]') * 256 + (arr ->> '$[3]') AS lo
    FROM (
      SELECT cidr, '[' || replace(substr(cidr, 1, instr(cidr, '/') - 1), '.', ',') || ']' AS arr
      FROM v4_range
    )
  )
),
-- First 32 bits of an IPv6 address as 8 hex digits.
v6_groups AS (
  SELECT ip,
         CASE WHEN ip LIKE '::%' THEN '0' ELSE substr(ip, 1, instr(ip, ':') - 1) END AS g1,
         CASE
           WHEN ip LIKE '::%' OR rest LIKE ':%' THEN '0'
           ELSE substr(rest, 1, instr(rest || ':', ':') - 1)
         END AS g2
  FROM (
    SELECT DISTINCT ip, substr(ip, instr(ip, ':') + 1) AS rest
    FROM record
    WHERE rtype = 'AAAA' AND instr(ip, ':') > 0 AND ip NOT GLOB '*[^0-9a-f:.]*'
  )
),
v6 AS (
  SELECT ip, substr('0000' || g1, -4) || substr('0000' || g2, -4) AS head
  FROM v6_groups
  WHERE length(g1) <= 4 AND length(g2) BETWEEN 1 AND 4
),
v6_range(lo, hi) AS (
  VALUES
    -- Cloudflare
    ('2400cb00', '2400cb00'), ('26064700', '26064700'), ('2803f800', '2803f800'),
    ('2405b500', '2405b500'), ('24058100', '24058100'), ('2a0698c0', '2a0698c7'),
    ('2c0ff248', '2c0ff248'),
    -- originless placeholder 100:: (discard prefix 100::/64)
    ('01000000', '01000000'),
    -- unique local fc00::/7, link-local fe80::/10
    ('fc000000', 'fdffffff'), ('fe800000', 'febfffff'),
    -- unspecified, loopback, IPv4-mapped
    ('00000000', '00000000')
),
origin_ip AS (
  SELECT ip FROM v4
  WHERE NOT EXISTS (SELECT 1 FROM v4_bounds b WHERE v4.num BETWEEN b.lo AND b.hi)
  UNION
  SELECT ip FROM v6
  WHERE NOT EXISTS (SELECT 1 FROM v6_range r WHERE v6.head BETWEEN r.lo AND r.hi)
),
exposed AS (
  SELECT u.id AS record_id, u.ip, p.id AS proxied_id, lower(p.name) AS proxied_host
  FROM record u
  JOIN record p ON p.ip = u.ip AND p.rtype = u.rtype AND p.id <> u.id AND p.proxied = 1
  WHERE u.proxied = 0
    AND u.ip IN (SELECT ip FROM origin_ip)
),
-- Access apps with a hostname target on the proxied host: exact, or a
-- wildcard that covers exactly one label.
access_target AS (
  SELECT a.id AS app_id, lower(t.value ->> '$.host') AS host
  FROM nodes a, json_each(a.props, '$.targets') t
  WHERE a.type = 'access_app' AND a.deleted_at IS NULL
    AND t.value ->> '$.kind' = 'hostname'
),
protected AS (
  SELECT DISTINCT e.proxied_host, at.app_id
  FROM exposed e
  JOIN access_target at ON at.host = e.proxied_host
    OR (substr(at.host, 1, 2) = '*.'
        AND length(e.proxied_host) > length(at.host) - 1
        AND substr(e.proxied_host, 1 - length(at.host)) = substr(at.host, 2)
        AND instr(substr(e.proxied_host, 1, length(e.proxied_host) - length(at.host) + 1), '.') = 0)
)
SELECT
  'CF-007'                                   AS rule_id,
  'CF-007:' || e.record_id                   AS fingerprint,
  CASE WHEN count(pr.app_id) > 0 THEN 'high' ELSE 'medium' END AS severity,
  e.record_id                                AS subject_id,
  e.ip                                       AS address,
  json_group_array(DISTINCT e.proxied_id)    AS proxied_records,
  json_group_array(DISTINCT e.proxied_host)  AS proxied_hosts,
  json_group_array(DISTINCT pr.app_id) FILTER (WHERE pr.app_id IS NOT NULL) AS access_apps
FROM exposed e
LEFT JOIN protected pr ON pr.proxied_host = e.proxied_host
GROUP BY e.record_id
