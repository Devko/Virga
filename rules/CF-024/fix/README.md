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

Templates for Wrangler and Terraform snippets follow in phase 4.
