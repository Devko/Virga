# CF-003 fix proposals

1. Give the token an expiry of 90 days or less and rotate it on a schedule; the account token API accepts `expires_on`.
2. Add an IP condition (`condition.request_ip.in`) with the addresses of the systems that use the token, such as CI runners.
3. Narrow the policies: only the permission groups the job needs, scoped to single zones instead of all zones.
4. Delete tokens that were not used for 90 days, or never.

Templates for Wrangler and Terraform snippets follow in phase 4.
