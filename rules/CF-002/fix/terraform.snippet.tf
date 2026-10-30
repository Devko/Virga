# CF-002 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: option 1 turns case cf002-seeded into cf002-clean
# (infra/test-range/cf002.tf).

# Option 1: close the entry points nobody needs. Keep only the routes and
# Custom Domains that an Access app protects.
resource "cloudflare_workers_script_subdomain" "worker" {
  account_id       = var.account_id
  script_name      = "<WORKER_NAME>"
  enabled          = false # no <WORKER_NAME>.<subdomain>.workers.dev
  previews_enabled = false # no version or alias preview URLs
}

# Option 2: Worker-level Access. It covers the Worker's routes, Custom Domains,
# workers.dev and preview URLs. Hostname and path apps on those hosts still
# take precedence, so give them no Bypass policy and no Allow for Everyone.
resource "cloudflare_zero_trust_access_application" "worker" {
  account_id = var.account_id
  name       = "<WORKER_NAME>"
  type       = "self_hosted"
  # The Worker's ID from the Workers API (GET /accounts/{account_id}/workers/workers),
  # or cloudflare_worker.<name>.id if Terraform manages the Worker with that resource.
  destinations = [{ type = "worker", worker_id = "<WORKER_ID>" }]
  policies     = [{ id = "<ALLOW_POLICY_ID>", precedence = 1 }]
}
