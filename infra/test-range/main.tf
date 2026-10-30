# Shared building blocks of the range. Each rule has its own file
# (cfNNN.tf) with its seeded case and the clean counterpart; cases.yaml lists
# them with the expected results.

locals {
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
  account_id = var.account_id
  name       = "${local.p}-allow-named-email"
  decision   = "allow"
  include    = [{ email = { email = var.access_allowed_email } }]
}
