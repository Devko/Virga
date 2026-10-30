# CF-010 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: the narrow include turns case cf010-seeded into cf010-clean
# (infra/test-range/cf010.tf). The range admits one named address.

resource "cloudflare_zero_trust_access_policy" "app_users" {
  account_id = var.account_id
  name       = "<APP_NAME> users"
  decision   = "allow"
  # Instead of `everyone = {}` or `login_method` with the One-time PIN IdP:
  # the people who need the app. IdP groups (`group = { id }`) are better than
  # an email domain.
  include = [{ email_domain = { domain = "<YOUR_EMAIL_DOMAIN>" } }]
}

resource "cloudflare_zero_trust_access_application" "app" {
  account_id   = var.account_id
  name         = "<APP_NAME>"
  type         = "self_hosted"
  domain       = "<HOSTNAME>"
  destinations = [{ type = "public", uri = "<HOSTNAME>" }]
  # Only the corporate IdP, so nobody signs in with a One-time PIN.
  allowed_idps = ["<CORPORATE_IDP_ID>"]
  policies     = [{ id = cloudflare_zero_trust_access_policy.app_users.id, precedence = 1 }]
}

# Machines: Service Auth with a named service token instead of a broad Allow.
resource "cloudflare_zero_trust_access_service_token" "job" {
  account_id = var.account_id
  name       = "<JOB_NAME>"
  duration   = "8760h"
}

resource "cloudflare_zero_trust_access_policy" "job" {
  account_id = var.account_id
  name       = "<JOB_NAME> service token"
  decision   = "non_identity"
  include    = [{ service_token = { token_id = cloudflare_zero_trust_access_service_token.job.id } }]
}
