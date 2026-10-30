# CF-022 fix proposals

1. Protect preview deployments with Access: in the project's **Settings** > **General**, select **Enable access policy**, or add an Access application for `*.<project>.pages.dev`. Preview URLs are public by default, and old hash-based URLs stay reachable after newer commits.
2. Give the preview environment its own resources: separate D1 databases, KV namespaces, R2 buckets and queues, and a staging Worker behind service bindings.
3. If previews are not needed, turn them off (preview deployments: none) or limit them to selected branches.

## Templates

[`wrangler.snippet.jsonc`](wrangler.snippet.jsonc) (a Pages project's Wrangler config) and [`terraform.snippet.tf`](terraform.snippet.tf) are templates, not diffs (A-14): Virga does not see your Wrangler or Terraform files. Adapt the project name, the output directory, the binding names and the database IDs. The templates show D1; KV namespaces, R2 buckets, queues and service bindings work the same way. In a Pages Wrangler config, once one environment overrides a binding key, it must list all of them.

The test range shows the fix: case `cf022-seeded` binds one D1 database in both environments, and `cf022-clean` gives previews a database of their own ([cf022.tf](../../../infra/test-range/cf022.tf), [cases.yaml](../../../infra/test-range/cases.yaml)). The Access option in the Terraform template is not part of the range.
