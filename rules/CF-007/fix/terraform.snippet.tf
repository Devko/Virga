# CF-007 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: proxying the record turns case cf007-seeded into cf007-clean
# (infra/test-range/cf007.tf).

# The record that published the origin: proxy it, or delete its resource if
# nothing needs the name. Change the origin address as well; the old one is
# known and may sit in DNS history.
resource "cloudflare_dns_record" "origin" {
  zone_id = var.zone_id
  name    = "<RECORD_NAME>"
  type    = "A"
  content = "<NEW_ORIGIN_ADDRESS>"
  proxied = true
  ttl     = 1 # automatic, as proxied records require
}

# Then let only Cloudflare reach the origin: connect it with Cloudflare Tunnel
# and close its inbound ports, or require Authenticated Origin Pulls and allow
# only Cloudflare's address ranges in the origin's firewall.
