# CF-010 fix proposals

1. Replace the Everyone or One-time PIN include with the groups that need the app: IdP groups or Access groups built on them.
2. Limit the app's login methods to the corporate IdP (`allowed_idps`), so One-time PIN cannot be used to sign in.
3. Add a require rule for an IdP group, an email domain or device posture where the audience has to stay broad.
4. For machine access, use a Service Auth policy with named service tokens instead of a broad Allow policy.

The Security Insight "Overprovisioned Access Policies" reports Allow-Everyone policies; link it once the insight's class is mapped.

## Templates

[`terraform.snippet.tf`](terraform.snippet.tf) is a template, not a diff (A-14): Virga does not see your Terraform files. Adapt the audience (an email domain in the template; IdP groups are better), the IdP IDs for `allowed_idps` and the app's destination.

There is no Wrangler template: Wrangler does not manage Access policies.

The test range shows the fix: case `cf010-seeded` is an Allow policy for Everyone on the app of a Worker with a KV binding, and `cf010-clean` admits one named address instead ([cf010.tf](../../../infra/test-range/cf010.tf), [cases.yaml](../../../infra/test-range/cases.yaml)).
