# CF-007 fix proposals

1. Remove the unproxied record, or proxy it, if nothing needs to reach the origin directly.
2. Change the origin address once the record is gone: the old one is known and may sit in DNS history.
3. Lock the origin down so only Cloudflare reaches it: connect it with Cloudflare Tunnel and close inbound ports, or require Authenticated Origin Pulls (mTLS) and allow only Cloudflare's IP ranges in the origin firewall.

Templates for Wrangler and Terraform snippets follow in phase 4.
