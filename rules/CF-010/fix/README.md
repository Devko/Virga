# CF-010 fix proposals

1. Replace the Everyone or One-time PIN include with the groups that need the app: IdP groups or Access groups built on them.
2. Limit the app's login methods to the corporate IdP (`allowed_idps`), so One-time PIN cannot be used to sign in.
3. Add a require rule for an IdP group, an email domain or device posture where the audience has to stay broad.
4. For machine access, use a Service Auth policy with named service tokens instead of a broad Allow policy.

The Security Insight "Overprovisioned Access Policies" reports Allow-Everyone policies; link it once the insight's class is mapped.

Templates for Wrangler and Terraform snippets follow in phase 4.
