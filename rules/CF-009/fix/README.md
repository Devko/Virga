# CF-009 fix proposals

1. Confirm the Worker is unused: no requests, cron triggers, queue consumers or other triggers in 30 days.
2. Delete it (`wrangler delete <NAME>`), or remove the bindings to stores that production uses and redeploy.
3. If it is a rarely used job that must keep access, give it its own scoped resources where possible and suppress the finding with a reason and an end date.

Templates for Wrangler and Terraform snippets follow in phase 4.
