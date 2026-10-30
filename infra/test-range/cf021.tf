# CF-021: R2 bucket public through r2.dev or a custom domain without Access.
#
# Seeded (cf021-seeded): a bucket with its managed r2.dev domain on. Access
# cannot protect r2.dev, so the bucket is public whatever else is set.
#
# Clean (cf021-clean): a bucket with r2.dev off and a custom domain behind an
# Access app with an Allow policy for one address, the fix in
# rules/CF-021/fix/.
#
# Safety: both buckets stay empty; nothing in the range writes objects, and
# nobody may upload any. r2.dev answers every key with a not-found error.

locals {
  cf021_clean_host = "${local.p}-cf021-clean.${var.zone_name}"
}

resource "cloudflare_r2_bucket" "cf021_seeded" {
  account_id = local.account_id
  name       = "${local.p}-cf021-seeded"
}

resource "cloudflare_r2_managed_domain" "cf021_seeded" {
  account_id  = local.account_id
  bucket_name = cloudflare_r2_bucket.cf021_seeded.name
  enabled     = true # the misconfiguration: public through r2.dev
}

resource "cloudflare_r2_bucket" "cf021_clean" {
  account_id = local.account_id
  name       = "${local.p}-cf021-clean"
}

resource "cloudflare_r2_managed_domain" "cf021_clean" {
  account_id  = local.account_id
  bucket_name = cloudflare_r2_bucket.cf021_clean.name
  enabled     = false
}

resource "cloudflare_zero_trust_access_application" "cf021_clean" {
  account_id   = local.account_id
  name         = local.cf021_clean_host
  type         = "self_hosted"
  domain       = local.cf021_clean_host
  destinations = [{ type = "public", uri = local.cf021_clean_host }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.allow_named_email.id, precedence = 1 }]
}

resource "cloudflare_r2_custom_domain" "cf021_clean" {
  account_id  = local.account_id
  bucket_name = cloudflare_r2_bucket.cf021_clean.name
  domain      = local.cf021_clean_host
  zone_id     = local.zone_id
  enabled     = true
  min_tls     = "1.2"

  # Access first, so the domain is never public, not even during apply.
  depends_on = [cloudflare_zero_trust_access_application.cf021_clean]
}
