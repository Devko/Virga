# CF-011 fix proposals

1. Remove the Bypass policy from the app that covers the whole host or Worker.
2. If some paths really are public, put them in a separate path app (for example `example.com/assets`) and keep the Bypass policy there only.
3. For machine-to-machine access, use a Service Auth policy with named service tokens; unlike Bypass, it authenticates and is logged.

## Templates

[`terraform.snippet.tf`](terraform.snippet.tf) is a template, not a diff (A-14): Virga does not see your Terraform files. Adapt the hostname, the public path, the audience of the Allow policy and the service token name.

There is no Wrangler template: Wrangler does not manage Access policies.

The test range shows the fix: case `cf011-seeded` is a Bypass policy on an app that covers a whole host, and `cf011-clean` moves the Bypass to a path app for `/assets` and protects the host with an Allow policy ([cf011.tf](../../../infra/test-range/cf011.tf), [cases.yaml](../../../infra/test-range/cases.yaml)).
