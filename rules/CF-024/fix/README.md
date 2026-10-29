# CF-024 fix proposals

1. Rotate the value first. It has been readable by everyone who can read the Worker's settings, and older versions still carry it.
2. Store the new value as a secret: `wrangler secret put <NAME>`, or a Secrets Store binding for values that several Workers share. Remove the variable from `vars` in the Wrangler configuration.
3. Redeploy, and stop serving old versions that still carry the value (`preview_urls = false` turns off version URLs).

Templates for Wrangler and Terraform snippets follow in phase 4.
