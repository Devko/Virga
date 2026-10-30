# CF-009 fix proposals

1. Confirm the Worker is unused: no requests, cron triggers, queue consumers or other triggers in 30 days.
2. Delete it (`wrangler delete <NAME>`), or remove the bindings to stores that production uses and redeploy.
3. If it is a rarely used job that must keep access, give it its own scoped resources where possible and suppress the finding with a reason and an end date.

## Templates

[`wrangler.snippet.jsonc`](wrangler.snippet.jsonc) and [`terraform.snippet.tf`](terraform.snippet.tf) are templates, not diffs (A-14): Virga does not see your Wrangler or Terraform files. They keep the Worker and replace the binding to the shared store with one of its own; deleting the Worker is the other way. Adapt the Worker name, the binding name and the store. The templates show KV; the same applies to D1, R2, queues and the other store bindings.

The test range shows the fix: case `cf009-seeded` is an idle Worker bound to a namespace that a live Worker uses, and `cf009-clean` is an idle Worker bound only to a namespace of its own ([cf009.tf](../../../infra/test-range/cf009.tf), [cases.yaml](../../../infra/test-range/cases.yaml)).
