# CF-021 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: these resources turn case cf021-seeded into cf021-clean
# (infra/test-range/cf021.tf). The range's Allow policy admits one address.

# r2.dev off: it is rate-limited, meant for development, and Access cannot
# protect it.
resource "cloudflare_r2_managed_domain" "bucket" {
  account_id  = var.account_id
  bucket_name = "<BUCKET_NAME>"
  enabled     = false
}

# A custom domain behind Access. Without a reason to serve the bucket on a
# domain, remove the domain instead.
resource "cloudflare_zero_trust_access_policy" "bucket_readers" {
  account_id = var.account_id
  name       = "<CUSTOM_DOMAIN> readers"
  decision   = "allow"
  include    = [{ email_domain = { domain = "<YOUR_EMAIL_DOMAIN>" } }]
}

resource "cloudflare_zero_trust_access_application" "bucket_domain" {
  account_id   = var.account_id
  name         = "<CUSTOM_DOMAIN>"
  type         = "self_hosted"
  domain       = "<CUSTOM_DOMAIN>"
  destinations = [{ type = "public", uri = "<CUSTOM_DOMAIN>" }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.bucket_readers.id, precedence = 1 }]
}

resource "cloudflare_r2_custom_domain" "bucket" {
  account_id  = var.account_id
  bucket_name = "<BUCKET_NAME>"
  domain      = "<CUSTOM_DOMAIN>"
  zone_id     = "<ZONE_ID>"
  enabled     = true
  min_tls     = "1.2"

  # Access first, so the domain is never public, not even during apply.
  depends_on = [cloudflare_zero_trust_access_application.bucket_domain]
}
