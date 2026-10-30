# Shared building blocks of the range. Each rule has its own file
# (cfNNN.tf) with its seeded case and the clean counterpart; cases.yaml lists
# them with the expected results.

# The range's zone, read from the API before anything is planned. Every
# resource takes its account and zone ID from here, never from the variables,
# so nothing is planned, also with -target, unless these conditions hold: the
# operator confirmed a dedicated test account (README.md), and the zone has
# the ID and name given and belongs to account_id.
data "cloudflare_zone" "range" {
  zone_id = var.zone_id

  lifecycle {
    precondition {
      condition     = var.dedicated_test_account
      error_message = "Apply the test range only in a dedicated test account. Read README.md, then set dedicated_test_account = true."
    }
    # Terraform evaluates self only in postconditions, after the read.
    postcondition {
      condition     = self.id == var.zone_id
      error_message = "The API returned another zone for zone_id ${var.zone_id}."
    }
    postcondition {
      condition     = try(self.account.id, null) == var.account_id
      error_message = "Zone ${var.zone_id} does not belong to account_id ${var.account_id}. Use a zone of the dedicated test account."
    }
    postcondition {
      condition     = self.name == var.zone_name
      error_message = "Zone ${var.zone_id} is not named ${var.zone_name}. Set zone_name to the zone's name."
    }
  }
}

locals {
  # Checked by data.cloudflare_zone.range above.
  account_id = data.cloudflare_zone.range.account.id
  zone_id    = data.cloudflare_zone.range.id

  p = var.name_prefix

  # The only code any Worker of the range runs: a fixed text, no binding is
  # ever read (worker/dummy.mjs).
  dummy_module       = "dummy.mjs"
  dummy_worker       = file("${path.module}/worker/${local.dummy_module}")
  compatibility_date = "2026-10-01"

  # A host that never resolves (RFC 6761: .invalid is never delegated). Tunnel
  # origins point here, so even a connector started by mistake reaches nothing.
  no_origin = "no-origin.invalid"

  # Pages projects that are not about CF-024 get one secret_text variable per
  # environment. It makes `env_vars` an object in the API response, so the
  # pages collector does not record the environment as unread (R5-07), and
  # the collector never reads secret_text values. The value is no secret.
  pages_env_placeholder = {
    VTR_PLACEHOLDER = { type = "secret_text", value = "virga-test-range-placeholder" }
  }
}

# Allow policy for one named address (var.access_allowed_email). Every
# protected entry point of the range uses it, except CF-010's clean case,
# which has a policy of its own because the policy is that rule's subject.
resource "cloudflare_zero_trust_access_policy" "allow_named_email" {
  account_id = local.account_id
  name       = "${local.p}-allow-named-email"
  decision   = "allow"
  include    = [{ email = { email = var.access_allowed_email } }]
}
