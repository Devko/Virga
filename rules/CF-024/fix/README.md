# CF-024 fix proposals

Rotate the value first. Everyone who can read the Worker's or the project's settings could read it, and older versions and deployments still carry it.

## Workers

1. Store the new value as a secret: `wrangler secret put <NAME>`, or a Secrets Store binding for values that several Workers share. Remove the variable from `vars` in the Wrangler configuration.
2. Redeploy, and stop serving old versions that still carry the value (`preview_urls = false` turns off version URLs).

## Pages

The evidence names the environment (`production` or `preview`) of each variable.

1. Store the new value as a secret in that environment: in the dashboard, add it under the project's variables and secrets with the type Secret, or run `wrangler pages secret put <NAME> --project-name <project>`. Delete the plain-text variable.
2. Redeploy: variable changes apply to new deployments only. Delete older deployments that still carry the value, preview deployments included.
3. If the build read the variable, the value may also be in the built assets. Check them before you keep any old deployment.

## Templates

[`wrangler.snippet.jsonc`](wrangler.snippet.jsonc) and [`terraform.snippet.tf`](terraform.snippet.tf) are templates, not diffs (A-14): Virga does not see your Wrangler or Terraform files. Adapt the Worker or project name and the variable names. Put the new value in through a secret manager or the environment, never into a file. A secret managed by Terraform is stored in its state; to keep it out, set it with `wrangler secret put` and let Terraform keep it (`keep_bindings`, in the template).

The test range shows the fix for both kinds ([cf024.tf](../../../infra/test-range/cf024.tf), [cases.yaml](../../../infra/test-range/cases.yaml)): cases `cf024-worker-seeded` and `cf024-pages-seeded` keep a token-shaped value in plain text, and `cf024-worker-clean` and `cf024-pages-clean` keep it as a secret. The range's values are synthetic.
