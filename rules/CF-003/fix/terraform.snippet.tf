# CF-003 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: the IP condition turns case cf003-seeded into cf003-clean
# (infra/test-range/cf003.tf). The range sets no expiry on either token.

resource "cloudflare_account_token" "job" {
  account_id = var.account_id
  name       = "<TOKEN_NAME>"

  policies = [{
    effect = "allow"
    # Only the permission groups the job needs.
    permission_groups = [{ id = "<PERMISSION_GROUP_ID>" }]
    # Single zones instead of all zones of the account.
    resources = jsonencode({ "com.cloudflare.api.account.zone.<ZONE_ID>" = "*" })
  }]

  # Only the addresses of the systems that use the token, such as CI runners.
  # CF-003 counts an `in` list as a restriction only when no entry is wider
  # than /8 (IPv4) or /32 (IPv6); a `not_in` list alone restricts nothing.
  condition = {
    request_ip = { in = ["<RUNNER_CIDR>"] }
  }

  # At most 90 days ahead, and rotated before then.
  expires_on = "<YYYY-MM-DDT00:00:00Z>"
}
