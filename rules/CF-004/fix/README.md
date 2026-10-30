# CF-004 fix proposals

1. Add an Access application for the hostname (self-hosted, or the SSH, RDP or VNC browser-rendering types for non-HTTP origins) with an Allow policy on IdP groups.
2. For SSH, RDP, SMB and TCP, prefer private network routes with the Cloudflare One Client over public hostnames; CF-014 covers private routes.
3. Remove ingress rules that no longer serve anything, and avoid `bastion` on public hostnames: it lets anyone who passes the edge reach every address cloudflared can reach.

The Security Insight "Unprotected Cloudflare Tunnels" reports the same condition; link it once the insight's class is mapped.

## Templates

[`terraform.snippet.tf`](terraform.snippet.tf) is a template, not a diff (A-14): Virga does not see your Terraform files. Adapt the hostname, the audience of the Allow policy (an email domain in the template; IdP groups are better) and, for the optional origin check, your team name.

There is no Wrangler template: Wrangler does not manage tunnels or Access. For a locally managed tunnel, the optional origin check goes into the ingress rule of cloudflared's `config.yml` as `originRequest.access` with `required: true`, `teamName` and `audTag`.

The test range shows the fix: case `cf004-seeded` publishes a tunnel hostname with an SSH origin and no Access app, and `cf004-clean` puts the same kind of hostname behind an Access app with an Allow policy ([cf004.tf](../../../infra/test-range/cf004.tf), [cases.yaml](../../../infra/test-range/cases.yaml)).
