# Security policy

Virga holds read access to the configuration and code of the accounts it scans, so vulnerabilities in it matter. Please report them privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Please do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect.

## Scope

In scope:

- the code in this repository
- the deployment scripts
- the documented default configuration

Especially relevant:

- any path that could make the tool change a scanned account
- any path that exposes stored tokens
- any way to escape the scanner container
- any way for content from a scanned account to inject into the UI or the MCP server

Out of scope: vulnerabilities in Cloudflare itself. Report those to Cloudflare through its own disclosure program.
