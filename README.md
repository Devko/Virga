# Virga

An agentless, read-only security tool for Cloudflare accounts that runs entirely on Cloudflare. Virga models an account as a security graph. That graph connects entry points, Workers, data stores, identities, Zero Trust policies and private networks. Virga then finds toxic combinations that single configuration checks miss.

> *Virga* is rain that falls from a cloud but evaporates before it reaches the ground. The tool does the same with risk: it forms in the cloud and is caught before it hits anyone.

**Status: concept phase.** There is no code yet. The design spec, its review and the implementation plan are in [`docs/`](docs/).

## Documents

| Document | Content |
| --- | --- |
| [Design spec](docs/concept/design-spec.md) | Goal, scope, architecture, data model, rules, security of the tool, roadmap, positioning |
| [Analysis](docs/analysis.md) | Review of the spec: verified platform claims, inconsistencies, security additions, risks, open decisions |
| [Implementation plan](docs/implementation-plan.md) | Phases with gates, spikes, rule rollout, deployment topology, repository layout, phase 1 backlog |
| [Data model](docs/architecture/data-model.md) | Graph schema draft, write path, exposure semantics, rule file format, revised CF-001 |
| [Schema draft](docs/architecture/schema-draft.sql) | SQLite DDL for the per-account graph |

## Principles

1. **Agentless and read-only.** Everything goes through the Cloudflare API with an account-owned read-only token. Nothing is installed or changed in the scanned account.
2. **Runs entirely on Cloudflare.** Workers, Workflows, Durable Objects, Queues, R2, D1, Containers and Access.
3. **Simple to deploy.** Each operator runs their own instance in a dedicated account, and scan data stays there.
4. **Consume, don't rebuild.** Security Insights, the Access policy tester and unmodified open source scanners feed the graph.
5. **Open formats.** Findings as OCSF, SBOMs as CycloneDX, rules as code.

## Architecture at a glance

```mermaid
flowchart LR
  CRON["Cron"] --> WF["Scan Workflow"]
  WF --> BRK["Credential broker"] --> API["Cloudflare API<br/>(scanned account)"]
  WF --> DO[("Account graph<br/>Durable Object + SQLite")]
  WF --> SCN["Scanner container"]
  EVT["Audit log events"] --> DO
  UI["UI, API, MCP"] -->|read-only| DO
```

One Durable Object per scanned account holds the graph. Collectors fill it. Evaluators compute exposure and effective access. Rules written as SQL turn graph paths into findings.

## License

Apache-2.0, see [LICENSE](LICENSE). Contributions require a DCO sign-off, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

- Virga is an independent open source project. It is not affiliated with, endorsed by, or sponsored by Cloudflare, Inc.
- Cloudflare and the names of Cloudflare products belong to Cloudflare, Inc. They appear here only to describe what Virga works with.
- "Virga" is a meteorological term. The project claims no exclusive rights to the name.
- Use Virga only on accounts you own or are authorized to assess. The software is provided "as is", without warranty of any kind; see the [LICENSE](LICENSE).
