# CF-004 fix proposals

1. Add an Access application for the hostname (self-hosted, or the SSH, RDP or VNC browser-rendering types for non-HTTP origins) with an Allow policy on IdP groups.
2. For SSH, RDP, SMB and TCP, prefer private network routes with the Cloudflare One Client over public hostnames; CF-014 covers private routes.
3. Remove ingress rules that no longer serve anything, and avoid `bastion` on public hostnames: it lets anyone who passes the edge reach every address cloudflared can reach.

The Security Insight "Unprotected Cloudflare Tunnels" reports the same condition; link it once the insight's class is mapped.

Templates for Wrangler and Terraform snippets follow in phase 4.
