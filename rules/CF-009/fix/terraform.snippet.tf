# CF-009 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: the binding to a store of its own turns case cf009-seeded into
# cf009-clean (infra/test-range/cf009.tf).
#
# If nobody needs the Worker, delete it instead: remove its
# cloudflare_workers_script resource and everything that refers to it
# (routes, Custom Domains, cron triggers, queue consumers), then apply.

# Keep the Worker, without the binding to the store that production uses.
resource "cloudflare_workers_script" "idle" {
  account_id         = var.account_id
  script_name        = "<WORKER_NAME>"
  content            = file("<PATH_TO_BUNDLE>/index.js")
  main_module        = "index.js"
  compatibility_date = "<YYYY-MM-DD>"
  bindings = [
    # Removed: { type = "kv_namespace", name = "<BINDING>", namespace_id = "<PRODUCTION_NAMESPACE_ID>" }
    { type = "kv_namespace", name = "<BINDING>", namespace_id = cloudflare_workers_kv_namespace.own.id },
  ]
}

# A store of its own, if the Worker still needs one.
resource "cloudflare_workers_kv_namespace" "own" {
  account_id = var.account_id
  title      = "<WORKER_NAME>-own"
}
