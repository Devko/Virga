# CF-022 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: option 1 turns case cf022-seeded into cf022-clean
# (infra/test-range/cf022.tf).

# Option 1: previews get resources of their own.
resource "cloudflare_d1_database" "preview" {
  account_id = var.account_id
  name       = "<PROJECT_NAME>-preview"
}

resource "cloudflare_pages_project" "project" {
  account_id        = var.account_id
  name              = "<PROJECT_NAME>"
  production_branch = "<PRODUCTION_BRANCH>"

  deployment_configs = {
    preview = {
      d1_databases = { DB = { id = cloudflare_d1_database.preview.id } }
    }
    production = {
      d1_databases = { DB = { id = "<PRODUCTION_DATABASE_ID>" } }
    }
  }
}

# Option 2: previews behind Access. The wildcard covers every preview URL of
# the project; use the project's subdomain, which can differ from its name.
resource "cloudflare_zero_trust_access_policy" "preview_viewers" {
  account_id = var.account_id
  name       = "<PROJECT_NAME> previews"
  decision   = "allow"
  include    = [{ email_domain = { domain = "<YOUR_EMAIL_DOMAIN>" } }]
}

resource "cloudflare_zero_trust_access_application" "previews" {
  account_id   = var.account_id
  name         = "<PROJECT_NAME> previews"
  type         = "self_hosted"
  domain       = "*.<PROJECT_SUBDOMAIN>.pages.dev"
  destinations = [{ type = "public", uri = "*.<PROJECT_SUBDOMAIN>.pages.dev" }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.preview_viewers.id, precedence = 1 }]
}
