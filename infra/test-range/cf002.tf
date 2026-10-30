# CF-002: Worker protected by Access on one entry point and reachable around
# it on another.
#
# Seeded (cf002-seeded): a Worker whose Custom Domain sits behind an Access
# app, while its workers.dev URL is on and has no Access. The exposure
# evaluator decides `/` `access` on the Custom Domain and `public` on
# workers.dev, which is the pair the rule reports.
#
# Clean (cf002-clean): the same Worker with workers.dev and preview URLs off,
# the fix in rules/CF-002/fix/. Its only entry point is the protected Custom
# Domain.
#
# Safety: both Workers run worker/dummy.mjs and have no bindings, so the
# public workers.dev URL serves a fixed text and nothing else.

locals {
  cf002_seeded_name = "${local.p}-cf002-seeded"
  cf002_seeded_host = "${local.p}-cf002-seeded.${var.zone_name}"
  cf002_clean_name  = "${local.p}-cf002-clean"
  cf002_clean_host  = "${local.p}-cf002-clean.${var.zone_name}"
}

# Seeded ---------------------------------------------------------------------

resource "cloudflare_workers_script" "cf002_seeded" {
  account_id         = local.account_id
  script_name        = local.cf002_seeded_name
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
}

resource "cloudflare_workers_script_subdomain" "cf002_seeded" {
  account_id       = local.account_id
  script_name      = cloudflare_workers_script.cf002_seeded.script_name
  enabled          = true # the misconfiguration: workers.dev, without Access
  previews_enabled = false
}

resource "cloudflare_zero_trust_access_application" "cf002_seeded" {
  account_id   = local.account_id
  name         = local.cf002_seeded_host
  type         = "self_hosted"
  domain       = local.cf002_seeded_host
  destinations = [{ type = "public", uri = local.cf002_seeded_host }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.allow_named_email.id, precedence = 1 }]
}

resource "cloudflare_workers_custom_domain" "cf002_seeded" {
  account_id = local.account_id
  zone_id    = local.zone_id
  hostname   = local.cf002_seeded_host
  service    = cloudflare_workers_script.cf002_seeded.script_name

  # Access first, so the Custom Domain is never public, not even during apply.
  depends_on = [cloudflare_zero_trust_access_application.cf002_seeded]
}

# Clean ----------------------------------------------------------------------

resource "cloudflare_workers_script" "cf002_clean" {
  account_id         = local.account_id
  script_name        = local.cf002_clean_name
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
}

resource "cloudflare_workers_script_subdomain" "cf002_clean" {
  account_id       = local.account_id
  script_name      = cloudflare_workers_script.cf002_clean.script_name
  enabled          = false
  previews_enabled = false
}

resource "cloudflare_zero_trust_access_application" "cf002_clean" {
  account_id   = local.account_id
  name         = local.cf002_clean_host
  type         = "self_hosted"
  domain       = local.cf002_clean_host
  destinations = [{ type = "public", uri = local.cf002_clean_host }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.allow_named_email.id, precedence = 1 }]
}

resource "cloudflare_workers_custom_domain" "cf002_clean" {
  account_id = local.account_id
  zone_id    = local.zone_id
  hostname   = local.cf002_clean_host
  service    = cloudflare_workers_script.cf002_clean.script_name

  depends_on = [cloudflare_zero_trust_access_application.cf002_clean]
}
