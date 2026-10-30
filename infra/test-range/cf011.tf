# CF-011: Bypass policy on an app that reaches data or a tunnel.
#
# Seeded (cf011-seeded): a Bypass policy for Everyone on an Access app that
# covers the whole host of a Worker's Custom Domain. The Worker binds a KV
# namespace. The policy is the rule's subject.
#
# Clean (cf011-clean): the host's app has an Allow policy for one address, and
# the Bypass policy sits on a separate path app for /assets only, the fix in
# rules/CF-011/fix/. A path app does not cover the whole host, so its Bypass
# policy (the clean subject) is not reported.
#
# Safety: the Bypass makes the seeded host public, and /assets of the clean
# host. Both Workers serve a fixed text and never read their namespaces,
# which stay empty.

locals {
  cf011_seeded_name = "${local.p}-cf011-seeded"
  cf011_seeded_host = "${local.p}-cf011-seeded.${var.zone_name}"
  cf011_clean_name  = "${local.p}-cf011-clean"
  cf011_clean_host  = "${local.p}-cf011-clean.${var.zone_name}"
}

# Seeded ---------------------------------------------------------------------

resource "cloudflare_workers_kv_namespace" "cf011_seeded" {
  account_id = var.account_id
  title      = "${local.p}-cf011-seeded"
}

resource "cloudflare_workers_script" "cf011_seeded" {
  account_id         = var.account_id
  script_name        = local.cf011_seeded_name
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
  bindings = [{
    type         = "kv_namespace"
    name         = "DATA"
    namespace_id = cloudflare_workers_kv_namespace.cf011_seeded.id
  }]
}

resource "cloudflare_workers_script_subdomain" "cf011_seeded" {
  account_id       = var.account_id
  script_name      = cloudflare_workers_script.cf011_seeded.script_name
  enabled          = false
  previews_enabled = false
}

resource "cloudflare_zero_trust_access_policy" "cf011_seeded" {
  account_id = var.account_id
  name       = "${local.p}-cf011-seeded-bypass-everyone"
  decision   = "bypass" # the misconfiguration, on the whole host
  include    = [{ everyone = {} }]
}

resource "cloudflare_zero_trust_access_application" "cf011_seeded" {
  account_id   = var.account_id
  name         = local.cf011_seeded_host
  type         = "self_hosted"
  domain       = local.cf011_seeded_host
  destinations = [{ type = "public", uri = local.cf011_seeded_host }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.cf011_seeded.id, precedence = 1 }]
}

resource "cloudflare_workers_custom_domain" "cf011_seeded" {
  account_id = var.account_id
  zone_id    = var.zone_id
  hostname   = local.cf011_seeded_host
  service    = cloudflare_workers_script.cf011_seeded.script_name

  depends_on = [cloudflare_zero_trust_access_application.cf011_seeded]
}

# Clean ----------------------------------------------------------------------

resource "cloudflare_workers_kv_namespace" "cf011_clean" {
  account_id = var.account_id
  title      = "${local.p}-cf011-clean"
}

resource "cloudflare_workers_script" "cf011_clean" {
  account_id         = var.account_id
  script_name        = local.cf011_clean_name
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
  bindings = [{
    type         = "kv_namespace"
    name         = "DATA"
    namespace_id = cloudflare_workers_kv_namespace.cf011_clean.id
  }]
}

resource "cloudflare_workers_script_subdomain" "cf011_clean" {
  account_id       = var.account_id
  script_name      = cloudflare_workers_script.cf011_clean.script_name
  enabled          = false
  previews_enabled = false
}

resource "cloudflare_zero_trust_access_application" "cf011_clean" {
  account_id   = var.account_id
  name         = local.cf011_clean_host
  type         = "self_hosted"
  domain       = local.cf011_clean_host
  destinations = [{ type = "public", uri = local.cf011_clean_host }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.allow_named_email.id, precedence = 1 }]
}

resource "cloudflare_zero_trust_access_policy" "cf011_clean_assets" {
  account_id = var.account_id
  name       = "${local.p}-cf011-clean-assets-bypass"
  decision   = "bypass"
  include    = [{ everyone = {} }]
}

resource "cloudflare_zero_trust_access_application" "cf011_clean_assets" {
  account_id   = var.account_id
  name         = "${local.cf011_clean_host}/assets"
  type         = "self_hosted"
  domain       = "${local.cf011_clean_host}/assets"
  destinations = [{ type = "public", uri = "${local.cf011_clean_host}/assets" }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.cf011_clean_assets.id, precedence = 1 }]
}

resource "cloudflare_workers_custom_domain" "cf011_clean" {
  account_id = var.account_id
  zone_id    = var.zone_id
  hostname   = local.cf011_clean_host
  service    = cloudflare_workers_script.cf011_clean.script_name

  depends_on = [
    cloudflare_zero_trust_access_application.cf011_clean,
    cloudflare_zero_trust_access_application.cf011_clean_assets,
  ]
}
