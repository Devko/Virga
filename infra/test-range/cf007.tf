# CF-007: unproxied DNS record exposes the origin of a proxied host.
#
# Seeded (cf007-seeded): a proxied A record and an unproxied A record point to
# the same address. The unproxied record is the rule's subject. No Access app
# covers the proxied host, so the hit is medium.
#
# Clean (cf007-clean): the same pair with both records proxied, the first fix
# in rules/CF-007/fix/. Nothing publishes the address.
#
# Safety: the addresses are from TEST-NET-3 (203.0.113.0/24, RFC 5737), a
# documentation range that is never routed on the internet, so there is no
# origin behind them. A request to a proxied name ends with a connection
# error at Cloudflare's edge. CF-007 leaves out 192.0.2.0/24, the originless
# placeholder, but not TEST-NET-3, so this range still counts as an origin.

locals {
  cf007_seeded_address = "203.0.113.10"
  cf007_clean_address  = "203.0.113.20"
}

resource "cloudflare_dns_record" "cf007_seeded_proxied" {
  zone_id = var.zone_id
  name    = "${local.p}-cf007-seeded-www.${var.zone_name}"
  type    = "A"
  content = local.cf007_seeded_address
  proxied = true
  ttl     = 1
  comment = "Virga test range: CF-007 seeded case, proxied host"
}

resource "cloudflare_dns_record" "cf007_seeded_origin" {
  zone_id = var.zone_id
  name    = "${local.p}-cf007-seeded-origin.${var.zone_name}"
  type    = "A"
  content = local.cf007_seeded_address
  proxied = false # the misconfiguration: publishes the proxied host's origin
  ttl     = 1
  comment = "Virga test range: CF-007 seeded case, unproxied origin record"
}

resource "cloudflare_dns_record" "cf007_clean_proxied" {
  zone_id = var.zone_id
  name    = "${local.p}-cf007-clean-www.${var.zone_name}"
  type    = "A"
  content = local.cf007_clean_address
  proxied = true
  ttl     = 1
  comment = "Virga test range: CF-007 clean counterpart, proxied host"
}

resource "cloudflare_dns_record" "cf007_clean_origin" {
  zone_id = var.zone_id
  name    = "${local.p}-cf007-clean-origin.${var.zone_name}"
  type    = "A"
  content = local.cf007_clean_address
  proxied = true
  ttl     = 1
  comment = "Virga test range: CF-007 clean counterpart, the origin record proxied"
}
