# CF-003 fix proposals

1. Give the token an expiry of 90 days or less and rotate it on a schedule; the account token API accepts `expires_on`.
2. Add an IP condition (`condition.request_ip.in`) with the addresses of the systems that use the token, such as CI runners.
3. Narrow the policies: only the permission groups the job needs, scoped to single zones instead of all zones.
4. Delete tokens that were not used for 90 days, or never.

## Templates

[`terraform.snippet.tf`](terraform.snippet.tf) is a template, not a diff (A-14): Virga does not see your Terraform files. Adapt the token name, permission group IDs, zone IDs, the addresses of your runners and the expiry date.

There is no Wrangler template: Wrangler does not manage account API tokens. Without Terraform, change the token in the dashboard (**Manage account** > **Account API tokens**) or through the account token API.

The test range shows the fix: case `cf003-seeded` has an `in` list with an entry wider than /8, which restricts nothing, and `cf003-clean` has narrow entries only ([cf003.tf](../../../infra/test-range/cf003.tf), [cases.yaml](../../../infra/test-range/cases.yaml)). Neither range token can be used: their lists hold only addresses that are never routed on the internet.
