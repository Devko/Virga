# CF-010: Access policy admits everyone to an app that reaches data or a
# tunnel.
#
# Seeded (cf010-seeded): an Allow policy that includes Everyone, on the Access
# app of a Worker's Custom Domain. The Worker binds a KV namespace. The policy
# is the rule's subject; the hit is critical.
#
# Clean (cf010-clean): the same setup with an Allow policy for one named
# address instead of Everyone, the fix in rules/CF-010/fix/.
#
# Safety: anyone who signs in to the seeded app (for example with a One-time
# PIN, if the account allows it) reaches a Worker that serves a fixed text and
# never reads the namespace, which stays empty.

locals {
  cf010_seeded_name = "${local.p}-cf010-seeded"
  cf010_seeded_host = "${local.p}-cf010-seeded.${var.zone_name}"
  cf010_clean_name  = "${local.p}-cf010-clean"
  cf010_clean_host  = "${local.p}-cf010-clean.${var.zone_name}"
}

# Seeded ---------------------------------------------------------------------

resource "cloudflare_workers_kv_namespace" "cf010_seeded" {
  account_id = local.account_id
  title      = "${local.p}-cf010-seeded"
}

resource "cloudflare_workers_script" "cf010_seeded" {
  account_id         = local.account_id
  script_name        = local.cf010_seeded_name
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
  bindings = [{
    type         = "kv_namespace"
    name         = "DATA"
    namespace_id = cloudflare_workers_kv_namespace.cf010_seeded.id
  }]
}

resource "cloudflare_workers_script_subdomain" "cf010_seeded" {
  account_id       = local.account_id
  script_name      = cloudflare_workers_script.cf010_seeded.script_name
  enabled          = false
  previews_enabled = false
}

resource "cloudflare_zero_trust_access_policy" "cf010_seeded" {
  account_id = local.account_id
  name       = "${local.p}-cf010-seeded-allow-everyone"
  decision   = "allow"
  include    = [{ everyone = {} }] # the misconfiguration
}

resource "cloudflare_zero_trust_access_application" "cf010_seeded" {
  account_id   = local.account_id
  name         = local.cf010_seeded_host
  type         = "self_hosted"
  domain       = local.cf010_seeded_host
  destinations = [{ type = "public", uri = local.cf010_seeded_host }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.cf010_seeded.id, precedence = 1 }]
}

resource "cloudflare_workers_custom_domain" "cf010_seeded" {
  account_id = local.account_id
  zone_id    = local.zone_id
  hostname   = local.cf010_seeded_host
  service    = cloudflare_workers_script.cf010_seeded.script_name

  depends_on = [cloudflare_zero_trust_access_application.cf010_seeded]
}

# Clean ----------------------------------------------------------------------

resource "cloudflare_workers_kv_namespace" "cf010_clean" {
  account_id = local.account_id
  title      = "${local.p}-cf010-clean"
}

resource "cloudflare_workers_script" "cf010_clean" {
  account_id         = local.account_id
  script_name        = local.cf010_clean_name
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
  bindings = [{
    type         = "kv_namespace"
    name         = "DATA"
    namespace_id = cloudflare_workers_kv_namespace.cf010_clean.id
  }]
}

resource "cloudflare_workers_script_subdomain" "cf010_clean" {
  account_id       = local.account_id
  script_name      = cloudflare_workers_script.cf010_clean.script_name
  enabled          = false
  previews_enabled = false
}

resource "cloudflare_zero_trust_access_policy" "cf010_clean" {
  account_id = local.account_id
  name       = "${local.p}-cf010-clean-allow-named-email"
  decision   = "allow"
  include    = [{ email = { email = var.access_allowed_email } }]
}

resource "cloudflare_zero_trust_access_application" "cf010_clean" {
  account_id   = local.account_id
  name         = local.cf010_clean_host
  type         = "self_hosted"
  domain       = local.cf010_clean_host
  destinations = [{ type = "public", uri = local.cf010_clean_host }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.cf010_clean.id, precedence = 1 }]
}

resource "cloudflare_workers_custom_domain" "cf010_clean" {
  account_id = local.account_id
  zone_id    = local.zone_id
  hostname   = local.cf010_clean_host
  service    = cloudflare_workers_script.cf010_clean.script_name

  depends_on = [cloudflare_zero_trust_access_application.cf010_clean]
}
