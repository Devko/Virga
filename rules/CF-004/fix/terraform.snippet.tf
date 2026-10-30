# CF-004 fix template for the Cloudflare Terraform provider 5.28.0. A
# template, not a diff (A-14): Virga does not see your Terraform files. Copy
# what applies and replace the values in angle brackets.
#
# Test range: the Access app turns case cf004-seeded into cf004-clean
# (infra/test-range/cf004.tf). The range uses an Allow policy for one address.

resource "cloudflare_zero_trust_access_policy" "tunnel_users" {
  account_id = var.account_id
  name       = "<HOSTNAME> users"
  decision   = "allow"
  # A narrow audience: an email domain here; IdP groups (`group = { id }`) are better.
  # Never `everyone = {}`, and no Bypass: either leaves the hostname public.
  include = [{ email_domain = { domain = "<YOUR_EMAIL_DOMAIN>" } }]
}

resource "cloudflare_zero_trust_access_application" "tunnel_hostname" {
  account_id   = var.account_id
  name         = "<HOSTNAME>"
  type         = "self_hosted" # or "ssh", "rdp", "vnc" for browser rendering of non-HTTP origins
  domain       = "<HOSTNAME>"
  destinations = [{ type = "public", uri = "<HOSTNAME>" }]
  policies     = [{ id = cloudflare_zero_trust_access_policy.tunnel_users.id, precedence = 1 }]
}

# Optional, in the tunnel's ingress rule for <HOSTNAME>: cloudflared then
# refuses every request without a valid token of this app, even if the app is
# later removed or opened up.
#
#   {
#     hostname = "<HOSTNAME>"
#     service  = "<ORIGIN>"
#     origin_request = {
#       access = {
#         required  = true
#         team_name = "<TEAM_NAME>"
#         aud_tag   = [cloudflare_zero_trust_access_application.tunnel_hostname.aud]
#       }
#     }
#   }
