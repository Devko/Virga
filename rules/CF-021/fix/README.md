# CF-021 fix proposals

1. Disable the `r2.dev` domain if the bucket does not have to serve the public: `wrangler r2 bucket dev-url disable <BUCKET>`. `r2.dev` is rate-limited and meant for development; Access cannot protect it.
2. Put an Access application on each custom domain that should not be public, or remove the custom domain.
3. If the contents are public on purpose, keep only what has to be public in this bucket and suppress the finding with a reason.

Templates for Wrangler and Terraform snippets follow in phase 4.
