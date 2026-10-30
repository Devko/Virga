# CF-007 fix proposals

1. Remove the unproxied record, or proxy it, if nothing needs to reach the origin directly.
2. Change the origin address once the record is gone: the old one is known and may sit in DNS history.
3. Lock the origin down so only Cloudflare reaches it: connect it with Cloudflare Tunnel and close inbound ports, or require Authenticated Origin Pulls (mTLS) and allow only Cloudflare's IP ranges in the origin firewall.

## Templates

[`terraform.snippet.tf`](terraform.snippet.tf) is a template, not a diff (A-14): Virga does not see your Terraform files. Adapt the zone, the record name and the new origin address, or delete the record's resource instead.

There is no Wrangler template: Wrangler does not manage DNS records.

The test range shows the fix: case `cf007-seeded` has an unproxied record to the address of a proxied one, and `cf007-clean` has both records proxied ([cf007.tf](../../../infra/test-range/cf007.tf), [cases.yaml](../../../infra/test-range/cases.yaml)). The range cannot show a changed origin address or a locked-down origin: its addresses are documentation addresses with no origin behind them.
