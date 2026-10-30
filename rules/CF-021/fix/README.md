# CF-021 fix proposals

1. Disable the `r2.dev` domain if the bucket does not have to serve the public: `wrangler r2 bucket dev-url disable <BUCKET>`. `r2.dev` is rate-limited and meant for development; Access cannot protect it.
2. Put an Access application on each custom domain that should not be public, or remove the custom domain.
3. If the contents are public on purpose, keep only what has to be public in this bucket and suppress the finding with a reason.

## Templates

[`terraform.snippet.tf`](terraform.snippet.tf) is a template, not a diff (A-14): Virga does not see your Terraform files. Adapt the bucket name, the custom domain, its zone and the Access policy.

There is no Wrangler config template: a bucket's public domains are not part of a Worker's Wrangler config. Wrangler has commands for them instead: `wrangler r2 bucket dev-url disable <BUCKET>` turns `r2.dev` off, and `wrangler r2 bucket domain remove <BUCKET> --domain <DOMAIN>` removes a custom domain.

The test range shows the fix: case `cf021-seeded` is a bucket with `r2.dev` on, and `cf021-clean` has `r2.dev` off and a custom domain behind Access ([cf021.tf](../../../infra/test-range/cf021.tf), [cases.yaml](../../../infra/test-range/cases.yaml)).
