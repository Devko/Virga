# CF-009: idle Worker with bindings to production data.
#
# Seeded (cf009-seeded): an idle Worker, without any trigger or entry point,
# binds a KV namespace that a live Worker (cf009-live) binds too. The live
# Worker runs on an hourly cron trigger. Every run is an invocation in the
# 30-day traffic window (GraphQL workersInvocationsAdaptive), so the
# namespace counts as in production use.
#
# Clean (cf009-clean): an idle Worker that binds only a namespace of its own,
# the fix in rules/CF-009/fix/ (remove the binding to the store that
# production uses).
#
# Traffic and time, which Terraform cannot create directly:
# - The cron trigger stands in for traffic: no manual step is needed, but the
#   first scan must come after the first cron run (at the next full hour).
# - CF-009 counts a Worker only once it is 30 days old (param min_age_days).
#   The seeded case is quiet until then and hits from day 30 after apply.
#
# Safety: the namespaces stay empty. No Worker here has an entry point, the
# code never reads a binding, and the cron handler does nothing.

locals {
  cf009_seeded_name = "${local.p}-cf009-seeded"
  cf009_live_name   = "${local.p}-cf009-live"
  cf009_clean_name  = "${local.p}-cf009-clean"
}

resource "cloudflare_workers_kv_namespace" "cf009_shared" {
  account_id = var.account_id
  title      = "${local.p}-cf009-shared"
}

resource "cloudflare_workers_kv_namespace" "cf009_clean_own" {
  account_id = var.account_id
  title      = "${local.p}-cf009-clean-own"
}

# Seeded: idle, and bound to the namespace that the live Worker uses.

resource "cloudflare_workers_script" "cf009_seeded" {
  account_id         = var.account_id
  script_name        = local.cf009_seeded_name
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
  bindings = [{
    type         = "kv_namespace"
    name         = "DATA"
    namespace_id = cloudflare_workers_kv_namespace.cf009_shared.id
  }]
}

resource "cloudflare_workers_script_subdomain" "cf009_seeded" {
  account_id       = var.account_id
  script_name      = cloudflare_workers_script.cf009_seeded.script_name
  enabled          = false
  previews_enabled = false
}

# Live: invoked every hour by its cron trigger, bound to the same namespace.

resource "cloudflare_workers_script" "cf009_live" {
  account_id         = var.account_id
  script_name        = local.cf009_live_name
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
  bindings = [{
    type         = "kv_namespace"
    name         = "DATA"
    namespace_id = cloudflare_workers_kv_namespace.cf009_shared.id
  }]
}

resource "cloudflare_workers_script_subdomain" "cf009_live" {
  account_id       = var.account_id
  script_name      = cloudflare_workers_script.cf009_live.script_name
  enabled          = false
  previews_enabled = false
}

resource "cloudflare_workers_cron_trigger" "cf009_live" {
  account_id  = var.account_id
  script_name = cloudflare_workers_script.cf009_live.script_name
  schedules   = [{ cron = "0 * * * *" }]
}

# Clean: idle, and bound only to a namespace of its own.

resource "cloudflare_workers_script" "cf009_clean" {
  account_id         = var.account_id
  script_name        = local.cf009_clean_name
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
  bindings = [{
    type         = "kv_namespace"
    name         = "DATA"
    namespace_id = cloudflare_workers_kv_namespace.cf009_clean_own.id
  }]
}

resource "cloudflare_workers_script_subdomain" "cf009_clean" {
  account_id       = var.account_id
  script_name      = cloudflare_workers_script.cf009_clean.script_name
  enabled          = false
  previews_enabled = false
}
