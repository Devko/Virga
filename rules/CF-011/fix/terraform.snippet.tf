# CF-011 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: these resources turn case cf011-seeded into cf011-clean
# (infra/test-range/cf011.tf). The range's Allow policy admits one address.

# The app on the whole host: an Allow policy, no Bypass.
resource "cloudflare_zero_trust_access_policy" "host_users" {
  account_id = var.account_id
  name       = "<HOSTNAME> users"
  decision   = "allow"
  include    = [{ email_domain = { domain = "<YOUR_EMAIL_DOMAIN>" } }]
}

resource "cloudflare_zero_trust_access_application" "host" {
  account_id   = var.account_id
  name         = "<HOSTNAME>"
  type         = "self_hosted"
  domain       = "<HOSTNAME>"
  destinations = [{ type = "public", uri = "<HOSTNAME>" }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.host_users.id, precedence = 1 }]
}

# Paths that really are public get a path app of their own; it is the only
# place for a Bypass policy.
resource "cloudflare_zero_trust_access_policy" "public_paths" {
  account_id = var.account_id
  name       = "<HOSTNAME><PUBLIC_PATH> public"
  decision   = "bypass"
  include    = [{ everyone = {} }]
}

resource "cloudflare_zero_trust_access_application" "public_paths" {
  account_id   = var.account_id
  name         = "<HOSTNAME><PUBLIC_PATH>"
  type         = "self_hosted"
  domain       = "<HOSTNAME><PUBLIC_PATH>" # for example example.com/assets
  destinations = [{ type = "public", uri = "<HOSTNAME><PUBLIC_PATH>" }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.public_paths.id, precedence = 1 }]
}

# Machines: Service Auth with a named service token. Unlike Bypass, it
# authenticates the caller and is logged. Add it to the host app's policies.
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
