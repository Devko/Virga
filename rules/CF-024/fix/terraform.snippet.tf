# CF-024 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: secret_text instead of plain_text turns cases
# cf024-worker-seeded and cf024-pages-seeded into cf024-worker-clean and
# cf024-pages-clean (infra/test-range/cf024.tf).
#
# Rotate the value first; the old one stays in older versions and deployments.

# The new value from the environment (TF_VAR_api_token) or a secret manager,
# never from a file. Terraform keeps it in its state.
variable "api_token" {
  type      = string
  sensitive = true
}

# Workers: a secret_text binding instead of plain_text.
resource "cloudflare_workers_script" "worker" {
  account_id         = var.account_id
  script_name        = "<WORKER_NAME>"
  content            = file("<PATH_TO_BUNDLE>/index.js")
  main_module        = "index.js"
  compatibility_date = "<YYYY-MM-DD>"
  bindings = [
    { type = "secret_text", name = "<VARIABLE_NAME>", text = var.api_token }, # was type = "plain_text"
    { type = "plain_text", name = "LOG_LEVEL", text = "info" },               # values that are no secret may stay
  ]
  # To keep the value out of Terraform's state, drop the secret_text binding
  # above, set the secret with `wrangler secret put <VARIABLE_NAME>`, and let
  # uploads keep it:
  # keep_bindings = ["secret_text"]
}

# Pages: a secret_text variable in the environment the evidence names.
resource "cloudflare_pages_project" "project" {
  account_id        = var.account_id
  name              = "<PROJECT_NAME>"
  production_branch = "<PRODUCTION_BRANCH>"

  deployment_configs = {
    production = {
      env_vars = {
        "<VARIABLE_NAME>" = { type = "secret_text", value = var.api_token } # was type = "plain_text"
      }
    }
  }
}
