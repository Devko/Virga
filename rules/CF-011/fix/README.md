# CF-011 fix proposals

1. Remove the Bypass policy from the app that covers the whole host or Worker.
2. If some paths really are public, put them in a separate path app (for example `example.com/assets`) and keep the Bypass policy there only.
3. For machine-to-machine access, use a Service Auth policy with named service tokens; unlike Bypass, it authenticates and is logged.

Templates for Wrangler and Terraform snippets follow in phase 4.
