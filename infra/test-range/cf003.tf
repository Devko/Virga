# CF-003: long-lived account token with a high-risk write permission and no
# IP restriction.
#
# Seeded (cf003-seeded): an account token with Workers Routes Write on the
# range's zone, no expiry, and an IP condition whose `in` list holds a range
# wider than /8 (240.0.0.0/4). CF-003 reads an `in` list with such an entry
# as limiting nothing (param min_ipv4_prefix), so the token qualifies.
#
# Clean (cf003-clean): the same token with an `in` list of narrow ranges only
# (/24 and /32), which CF-003 counts as an IP restriction. The fix template in
# rules/CF-003/fix/ also sets an expiry; either one keeps the rule quiet.
#
# Why neither token can be used:
# - Cloudflare accepts a token only from an address in its `in` list. Both
#   lists hold only ranges that are never routed on the internet:
#   192.0.2.0/24 (documentation, RFC 5737), 2001:db8::/32 (documentation,
#   RFC 3849) and 240.0.0.0/4 (reserved, not forwardable, RFC 6890). No
#   client can reach the API from them.
# - The permission is one of the narrowest that CF-003 counts as high risk:
#   it edits Worker routes, on the range's zone of the test account and
#   nowhere else.
# - The token values are never output. Terraform keeps them in its state,
#   which stays private like any state; they are unusable for the reasons
#   above.
# The plain case of the rule, a token with no IP condition at all, is covered
# by rule fixtures only: in the range it would be a working credential.

data "cloudflare_account_api_token_permission_groups_list" "all" {
  account_id = var.account_id
}

locals {
  # Matched by name, as CF-003 does; the API calls names cosmetic, so the
  # precondition below stops the apply if the name does not match exactly once.
  cf003_permission = "Workers Routes Write"
  cf003_permission_ids = [
    for group in data.cloudflare_account_api_token_permission_groups_list.all.result :
    group.id if group.name == local.cf003_permission
  ]

  cf003_policies = [{
    effect            = "allow"
    permission_groups = [{ id = try(local.cf003_permission_ids[0], "") }]
    # One zone, not all zones: an all-zones grant would make the hit critical.
    resources = jsonencode({ "com.cloudflare.api.account.zone.${var.zone_id}" = "*" })
  }]

  # Never routed on the internet; see above.
  cf003_narrow_ranges = ["192.0.2.0/24", "2001:db8::/32"]
  cf003_wide_reserved = "240.0.0.0/4"
}

resource "cloudflare_account_token" "cf003_seeded" {
  account_id = var.account_id
  name       = "${local.p}-cf003-seeded"
  policies   = local.cf003_policies

  # No expires_on: the token never expires.
  condition = {
    request_ip = { in = concat(local.cf003_narrow_ranges, [local.cf003_wide_reserved]) }
  }

  lifecycle {
    precondition {
      condition     = length(local.cf003_permission_ids) == 1
      error_message = "Expected exactly one permission group named \"${local.cf003_permission}\"."
    }
  }
}

resource "cloudflare_account_token" "cf003_clean" {
  account_id = var.account_id
  name       = "${local.p}-cf003-clean"
  policies   = local.cf003_policies

  condition = {
    request_ip = { in = local.cf003_narrow_ranges }
  }

  lifecycle {
    precondition {
      condition     = length(local.cf003_permission_ids) == 1
      error_message = "Expected exactly one permission group named \"${local.cf003_permission}\"."
    }
  }
}
