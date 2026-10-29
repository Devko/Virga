# CF-022 fix proposals

1. Protect preview deployments with Access: in the project's **Settings** > **General**, select **Enable access policy**, or add an Access application for `*.<project>.pages.dev`. Preview URLs are public by default, and old hash-based URLs stay reachable after newer commits.
2. Give the preview environment its own resources: separate D1 databases, KV namespaces, R2 buckets and queues, and a staging Worker behind service bindings.
3. If previews are not needed, turn them off (preview deployments: none) or limit them to selected branches.

Templates for Wrangler and Terraform snippets follow in phase 4.
