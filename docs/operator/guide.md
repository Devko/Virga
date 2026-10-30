# Operator guide

Status: phase 1, written 2026-10-29 against Wrangler 4.151.0 and the Cloudflare docs of that date; deploy checks updated 2026-10-30 (R3-03 to R3-06 of the [round 3 security review](../reviews/2026-10-30-security-review-round-3.md)). Items marked **verify** are documented inconsistently or not at all and still need a check in a real account (spikes S-05, S-06 and S-08 in the [implementation plan](../implementation-plan.md#phase-0-decisions-and-spikes)).

Virga is an independent project. It is not affiliated with or endorsed by Cloudflare (D-01).

An instance has three Workers in one dedicated Cloudflare account, the **tool account**:

| Worker | Holds | Reachable from |
| --- | --- | --- |
| `virga-broker` | The token vault (D1 `virga-vault`), the master key, the rate budget | Service bindings only: `ApiCaller` from the core Worker, `TokenIntake` from the web Worker |
| `virga-core` | One graph Durable Object per scanned account, the scan Workflows, the account index (D1 `virga-index`) | Service bindings only: `GraphReader` and `Admin` from the web Worker |
| `virga-web` | Nothing but static assets | The internet, behind Worker-level Access |

Every read from a scanned account goes through the broker, which allows only read calls (GET, plus POST for GraphQL queries). Nothing in Virga writes to a scanned account.

## Contents

1. [Prerequisites](#prerequisites)
2. [The deploy token](#the-deploy-token)
3. [Deploying](#deploying)
4. [Access for the UI](#access-for-the-ui)
5. [Scan tokens per profile](#scan-tokens-per-profile)
6. [Onboarding an account](#onboarding-an-account)
7. [What the scanned account's audit log shows](#what-the-scanned-accounts-audit-log-shows)
8. [Offboarding](#offboarding)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

**A dedicated tool account.** Create a Cloudflare account that runs Virga and nothing else. It holds encrypted read tokens of every scanned account, so treat it like a secrets vault:

- Workers Paid plan. Virga needs Durable Objects with SQLite, Workflows with a schedule and more than the 100,000 rows written per day of the Free plan ([S-03](../spikes/S-03-durable-object-sqlite.md)).
- Few members, each with a security key. Deploy only through CI ([analysis.md](../analysis.md#security-review-additions), item 5): anyone who can deploy the broker can read every stored token.
- Zero Trust turned on, for Access in front of the UI. Your team domain is `<team-name>.cloudflareaccess.com`.
- Secrets Store (open beta) for the master key (D-15). The first store is created when a Super Administrator or Secrets Store Admin opens Secrets Store in the dashboard, or with `npx wrangler secrets-store store create <name> --remote`. Without Secrets Store, use the [Worker secret fallback](#master-key).
- A zone in the tool account if `virga-web` is to have a Custom Domain.

**A workstation or CI runner** with:

- Node.js 22.18 or later. The scripts run as TypeScript without a build step, and Node 22 strips types by default from 22.18.
- pnpm through corepack, and a checkout of this repository.
- Linux or macOS. The deploy script runs each app's own Wrangler from `apps/<app>/node_modules/.bin`.

```sh
corepack enable
pnpm install
```

## The deploy token

The deploy script authenticates Wrangler with an account API token of the tool account. Create it under **Manage account** > **Account API tokens** > **Create Token**, with a custom set of permissions. The token form shows dashboard names (Edit); the API reports the same groups with API names (Write).

| Permission | Scope | Why | Check |
| --- | --- | --- | --- |
| Workers Scripts Edit (API: Workers Scripts Write) | Tool account | Uploads the three Workers with their Durable Object classes, Workflows and secrets. The Workflows API accepts only this group | API reference |
| Workers Admin | Tool account | Creates a Worker that does not exist yet, on the first deploy. The Workers roles page says creating a Worker needs product-level Admin; afterwards Editor is enough | **verify**: the script upload endpoint also accepts Workers Scripts Write |
| D1 Edit (API: D1 Write) | Tool account | Lists and creates `virga-vault` and `virga-index` and applies their migrations | API reference |
| Account Secrets Store Edit (API: Secrets Store Write) | Tool account | Deploys the broker with its Secrets Store binding: binding a secret counts as a write against it. Also lets the script list the store's secrets. Not needed with the `MASTER_KEY` fallback | Secrets Store docs |
| Account Settings Read | Tool account | Account lookups by Wrangler; part of the "Edit Cloudflare Workers" template | **verify** whether Wrangler needs it when `CLOUDFLARE_ACCOUNT_ID` is set |
| Workers Routes Edit and Zone Read | The zone of `virga-web`'s domain | Only if `apps/web/wrangler.jsonc` attaches a Custom Domain or route | **verify** Zone Read |

- **Resources:** include only the tool account, and only the one zone if needed.
- **TTL:** set an end date and roll the token before it. Dates are 00:00 UTC.
- **Storage:** keep the token in your CI's secret store, in a protected environment with required reviewers. Never put it in the repository, a shell history or a ticket.
- **Never onboard the deploy token as a scan token.** The broker rejects it anyway, because it has write groups.

The deploy token creates and changes resources only in the tool account. The scan tokens of other accounts never pass through it.

## Deploying

### Master key

The broker wraps each token's data key with a master key of 32 random bytes (D-15). Pick one of two places for it, before the first deploy.

**Secrets Store (default).** In `apps/broker`:

```sh
npx wrangler secrets-store store list --remote
openssl rand -base64 32 | npx wrangler secrets-store secret create <STORE_ID> --name virga-master-key --scopes workers --remote
```

Then set `store_id` in `apps/broker/wrangler.jsonc` to `<STORE_ID>` and commit it; a store ID is not a secret. The value goes from `openssl` to Wrangler through a pipe, so it never appears on screen or in a shell history. The secret needs the `workers` scope, or Workers cannot bind it. Secrets Store never shows the value again: if the key is lost, the stored tokens cannot be decrypted and every account has to be onboarded again with a new token. Rotation is described in [`apps/broker/README.md`](../../apps/broker/README.md#master-key-d-15); no entrypoint runs it yet.

**Worker secret (fallback).** Remove the `secrets_store_secrets` entry from `apps/broker/wrangler.jsonc`, then in `apps/broker`:

```sh
openssl rand -base64 32 | npx wrangler secret put MASTER_KEY
```

If `virga-broker` does not exist yet, Wrangler creates it as an empty Worker that holds the secret; the deploy replaces the code.

The deploy script refuses to deploy while the key is missing: the placeholder `store_id`, no `virga-master-key` in the store, a secret without the `workers` scope, or no `MASTER_KEY` secret in fallback mode.

### Optional settings

- **D1 location or jurisdiction.** The script creates missing databases with Wrangler's defaults. For a location hint or a jurisdiction, create them yourself first, for example `npx wrangler d1 create virga-vault --jurisdiction eu` in `apps/broker`. The script finds databases by name. If you add a `database_id` to a config, it must be the ID of the database that `database_name` names: Wrangler binds and migrates by ID.
- **Web settings.** `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` and `ADMIN_EMAILS`; see [Access for the UI](#access-for-the-ui).

### Run the deploy

```sh
export CLOUDFLARE_ACCOUNT_ID=<tool account ID>
export CLOUDFLARE_API_TOKEN=<deploy token>   # from your secret store, not typed into the shell
node scripts/deploy.ts --dry-run   # optional; needs no credentials
node scripts/deploy.ts
```

The script:

1. Refuses to run while `CLOUDFLARE_ENV` or `WRANGLER_CI_OVERRIDE_NAME` is set: with them, Wrangler would deploy a named environment or under another Worker name, not the configuration the script checked. The script itself takes no option but `--dry-run`.
2. Reads `apps/broker`, `apps/core` and `apps/web` (`wrangler.jsonc` or `wrangler.json`; `apps/web` may be missing, then it deploys broker and core only). It stops if an app has more than one of `wrangler.json`, `wrangler.jsonc` and `wrangler.toml`, or if any of them sits in a directory above an app, up to the filesystem root, including the repository root and your home directory: Wrangler run in an app directory without `--config` takes the first `wrangler.json` above it before the app's own config.
3. Checks the configs against each other and stops on any error:
   - each Worker has its expected name (`virga-broker`, `virga-core`, `virga-web`);
   - every service binding names an entrypoint that the target's main module exports, and is one the [topology](../implementation-plan.md#deployment-topology-proposal) allows: core binds `virga-broker#ApiCaller`; web binds `virga-broker#TokenIntake`, `virga-core#GraphReader` and `virga-core#Admin`, and never `ApiCaller`;
   - bindings follow the deploy order broker, core, web;
   - broker and core have `workers_dev` and `preview_urls` off and no routes;
   - only the broker binds Secrets Store, each D1 database belongs to one Worker by `database_name` and by `database_id` (D-08), and the web Worker binds no D1 database and no Durable Object;
   - Durable Object and Workflow classes are exported;
   - no config has named environments (`env` blocks), and no `secrets.required` lists a `CLOUDFLARE_` or `CF_` name.
4. Lists the D1 databases of the account. Before it creates or migrates anything, it checks that every `database_id` exists and is the database its `database_name` names, and that no database, by ID, is bound by two Workers. Then it creates `virga-vault` and `virga-index` if they are missing and applies their migrations (`wrangler d1 migrations apply --remote`).
5. Checks the master key.
6. Checks the web settings, if `apps/web` declares required secrets.
7. Runs each app's `build` script, if it has one, and deploys `virga-broker`, `virga-core` and `virga-web`, in this order.
8. Prints what is still to do as `ACTION:` lines.

It is safe to run again: existing databases are reused, applied migrations are skipped, and each Worker gets a new version.

What it never does:

- It reaches the Cloudflare API only through Wrangler, which acts on the account of `CLOUDFLARE_ACCOUNT_ID`. Apart from Wrangler it runs only the apps' `build` scripts.
- It never lets Wrangler choose a config: every Wrangler call gets `--config` with the absolute path of the file it checked, so Wrangler neither searches for a config nor follows a `.wrangler/deploy` redirect, and it never selects a named environment.
- It passes only `CLOUDFLARE_API_TOKEN` to Wrangler: a Global API Key in the environment is not used. A dry run passes no credentials at all. The `build` scripts get no `CLOUDFLARE_` or `CF_` variable at all, so no build-time package can read the token.
- It takes only `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` and `ADMIN_EMAILS` from its environment to upload as secrets of `virga-web`; never the token or any other variable.
- It runs Wrangler with stdin closed, so Wrangler never prompts and never writes resource IDs into a `wrangler.jsonc`.
- It never prints the token or a setting it uploads: all output passes through a filter that also removes anything shaped like a Cloudflare credential (`cfat_`, `cfut_`, `cfk_`, `cfoat_`). It never reads the master key.
- It sends no Wrangler telemetry (`WRANGLER_SEND_METRICS=false`).

The `npx wrangler` commands in this guide run in an app directory without `--config`. Wrangler then uses that app's own config only while no other Wrangler config sits next to or above it, which step 2 checks, and only while `CLOUDFLARE_ENV` is unset. Run the dry run first if in doubt.

### Deploy from CI

CI runs the dry run on every push (`.github/workflows/ci.yml`, job `deploy-dry-run`). For real deploys, a separate workflow with a protected environment keeps the token away from pull requests. An example, with actions pinned like the CI workflow:

```yaml
name: Deploy
on: workflow_dispatch
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-24.04
    environment: production # required reviewers, deploy branch restricted
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: pnpm/action-setup@ea17c68df8912ef543352723c149a84f56e3d413 # v6.1.0
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version-file: .nvmrc
      - run: pnpm install --frozen-lockfile
      - run: node scripts/deploy.ts
        env:
          CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
```

### Updates

Pull the new version, run `pnpm install`, then the deploy script. New D1 migrations are applied before the Workers are deployed. Durable Object migrations are part of `wrangler deploy`.

## Access for the UI

`virga-web` serves the UI, the JSON API and the MCP server. It must sit behind Worker-level Access, and it validates the Access token in code as a second check.

1. **Deploy once**, so that `virga-web` exists.
2. **Protect the Worker.** In the dashboard: **Workers & Pages** > `virga-web` > **Access** > **Protect this Worker behind Access**. Choose **All traffic**, not "Previews only". Worker-level Access covers the Worker's routes, Custom Domains, `workers.dev` hostname and previews.
3. **Choose who signs in.** The quick options are "Cloudflare account" (members of the tool account) and "Email domain". Narrow it afterwards in Zero Trust to named people or an IdP group, require your IdP's MFA, and keep the session short.
4. **Copy the AUD tag:** **Zero Trust** > **Access controls** > **Applications** > the app > **Configure** > **Additional settings** > **Application Audience (AUD) Tag**. It changes only if the app is deleted and created again.
5. **Set the settings** on `virga-web`:

   | Setting | Value |
   | --- | --- |
   | `ACCESS_TEAM_DOMAIN` | `https://<team-name>.cloudflareaccess.com`, the issuer (`iss`) of your Access tokens |
   | `ACCESS_AUD` | The AUD tag from step 4 |
   | `ADMIN_EMAILS` | Comma-separated email addresses of the people who may onboard accounts and start scans |

   Either as secrets, in `apps/web`:

   ```sh
   npx wrangler secret put ACCESS_TEAM_DOMAIN
   npx wrangler secret put ACCESS_AUD
   npx wrangler secret put ADMIN_EMAILS
   ```

   Or as environment variables of the deploy script with these names: it uploads them as secrets with the deploy (`wrangler deploy --secrets-file`, through a private temporary file that it deletes afterwards) and never prints them. Secrets stay across deploys. If `apps/web/wrangler.jsonc` declares one of them under `vars`, the config value is used instead. These three are the only names the script takes from its environment: any other name that `apps/web/wrangler.jsonc` lists under `secrets.required` must already be a secret of `virga-web`, created with `npx wrangler secret put`, and a `CLOUDFLARE_` or `CF_` name there stops the deploy.

Things to know:

- **Precedence.** A hostname or path Access app on `virga-web`'s hostname takes precedence over Worker-level Access. Do not create one with a Bypass policy or an Everyone include there; Virga's own rule CF-002 reports exactly that when it scans the tool account.
- **No `ctx.access` behind static assets.** Workers with static assets run behind an internal router that does not pass `ctx.access` to the Worker, although Access still protects the app and its assets. `virga-web` therefore validates the `Cf-Access-Jwt-Assertion` header against `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD`, and without both it cannot accept any request. Access rotates its signing keys every six weeks; the Worker reads them from `<team domain>/cdn-cgi/access/certs`.
- **No WebSockets.** Worker-level Access answers WebSocket upgrades with 403.
- **MCP clients** have to pass Access too. How a non-browser client does that (service token or `cloudflared access`) is spike S-08: **verify**.

## Scan tokens per profile

Each scanned account gets its own **account API token**, created in the scanned account by someone who administers it. Virga stores it encrypted in the broker's vault and never shows it again.

### What the broker accepts

The onboarding write check ([`apps/broker/src/write-check.ts`](../../apps/broker/src/write-check.ts)) rejects a token unless:

- it is an account API token (`cfat_`); Global API Keys (`cfk_`), user tokens (`cfut_`) and Wrangler OAuth tokens (`cfoat_`) are refused before any call;
- it is active and already valid (no future start date);
- it expires, and no more than 90 days ahead;
- every permission group of every allow policy is a read group: its name ends in ` Read`, `Read-Only` or ` Metadata Read`, or it is Account Security Center Insights or Zone Security Center Insights. Names containing Write, Edit, Admin, Editor, Revoke or Purge are rejected, and so is every name the check does not know (fail closed). Deny policies are ignored;
- an allow policy names the scanned account, and no policy names another account or any resource other than single zones;
- it can read its own policies, which needs **Account API Tokens Read**.

For the inventory profile, groups that read code or data (Workers Scripts Read, D1 Read, Workers KV Storage Read, Workers R2 Storage Read, Pages Read and every `Content Read` group) are accepted with a warning.

### Create the token

In the scanned account:

1. **Manage account** > **Account API tokens** > **Create Token**, custom token. Only Super Administrators and members with API token provisioning can create one, and only with permissions they hold themselves.
2. Name it after the instance and profile, for example `virga-inventory`. The name shows up in the account's audit log.
3. Add the permission groups of the profile (tables below).
4. **Account resources:** include the scanned account. **Zone resources:** include all zones of that account. **verify (S-05):** how the API reports "all zones of an account" to the write check. If onboarding fails with `foreign_resource`, select the zones one by one instead.
5. **Client IP address filtering:** leave it empty. The broker calls the API from Cloudflare's network, not from an address you control.
6. **TTL:** set an end date at most 90 days ahead.
7. Create the token, copy it once, and paste it straight into the Virga onboarding form. Do not send it by email or chat.

### Inventory profile

Configuration metadata only (D-14). The **Check** column says where the name comes from: "API reference" means the endpoint pages of the collector list the group as accepted.

| Permission group | Scope | Resource classes | Check |
| --- | --- | --- | --- |
| Account API Tokens Read | Account | onboarding, `tokens` | API reference |
| Account Settings Read | Account | `members` | API reference |
| Account Analytics Read | Account | `traffic` (GraphQL) | GraphQL Analytics docs |
| Account Security Center Insights | Account | `insights` | Permissions reference; the endpoint page names no group: **verify** |
| Workers Metadata Read-Only | Account | `workers`, `traffic`, `storage` (Durable Object namespaces), `access` (Worker names of Worker-level apps) | API reference, except the version detail endpoint, see below: **verify** |
| Queues Read | Account | `storage`, `workers`, `pages` (queue bindings) | API reference |
| Hyperdrive Read | Account | `storage` | API reference |
| Secrets Store Read | Account | `storage` (names only; it cannot read values) | API reference |
| Pages Metadata Read | Account | `pages` | Workers roles page; the Pages endpoint pages list only Pages Read: **verify (S-05)** |
| Access: Apps and Policies Read | Account | `access` | API reference |
| Access: Organizations, Identity Providers, and Groups Read | Account | `access` (groups, IdPs) | API reference |
| Access: Service Tokens Read | Account | `access` | API reference |
| Cloudflare Tunnel Read | Account | `tunnels` | API reference |
| Zone Read | All zones | `zones`, `dns`, `workers` | API reference |
| DNS Read | All zones | `dns` | API reference |
| Workers Routes Read | All zones | `workers` (routes) | API reference |

**Storage needs data groups for now.** D-14 prefers product-level Metadata Read-Only roles for D1, KV and R2, but the API reference lists none for their listing endpoints, and S-05 has not run. The `storage` collector needs these three to list databases, namespaces and buckets:

| Permission group | Scope | Resource classes | What else it allows |
| --- | --- | --- | --- |
| D1 Read | Account | `storage` | Running queries against the databases |
| Workers KV Storage Read | Account | `storage` | Reading values |
| Workers R2 Storage Read | Account | `storage`, R2 public domains | Reading objects |

The broker's allowlist contains none of the data endpoints, so Virga never runs a query or reads a value or an object, but the token could. Without one of the three, the `storage` class is not complete (`no_permission` without D1 Read, because its chunk runs first; `partial` otherwise), and every rule that needs `storage` is `not evaluated`.

**Workers version detail: verify.** The `workers` collector reads each deployed version for its bindings (`GET /accounts/{id}/workers/scripts/{name}/versions/{version_id}`). That endpoint's page lists Workers Content Read-Only, Workers Scripts Read and Workers Tail Read, but not Workers Metadata Read-Only. If a scan reports `no_permission` for `workers` with a token that has Metadata Read-Only, this is the cause. Do not add a Content group to an inventory token to work around it: it reads code.

**Pages.** If Pages Metadata Read turns out not to work, Pages Read does, with a write check warning: it also reads content. **verify (S-05):** that the project GET (`GET /accounts/{id}/pages/projects/{name}`) returns the values of `plain_text` env vars with Pages Metadata Read. Without them, CF-024 returns undecided rows for every project with plain-text vars.

What a missing group costs, by rule (from the `requires` of each rule):

| Rule | Needs the classes |
| --- | --- |
| CF-002 | `workers`, `access`, exposure |
| CF-003 | `tokens` |
| CF-004 | `tunnels`, `access`, exposure |
| CF-007 | `dns`, `access` |
| CF-009 | `workers`, `storage`, `pages`, `traffic`, `access`, exposure |
| CF-010, CF-011 | `access`, `workers`, `pages`, `storage`, `tunnels` |
| CF-021 | `storage`, `access`, exposure |
| CF-022 | `pages`, `access`, exposure |
| CF-024 | `workers`, `pages` ([decision 0004](../decisions/0004-cf-024-scope.md)) |

Exposure needs `access`. A rule whose classes are not all complete is `not evaluated`; it never passes and never resolves a finding.

Groups the [plan](../implementation-plan.md#token-profiles-and-permissions) lists for later phases (Zone Settings Read, rulesets and WAF, Zero Trust Read, Cloudflare One Networks Read) are not used by any collector yet. Leave them out.

### Workload profile

Phase 2. The inventory groups plus Workers Content Read-Only (or Workers Scripts Read) for Worker bundles and Containers Read (D-14). No collector uses them yet; until it does, onboard with the inventory profile.

## Onboarding an account

Onboard the tool account first (dogfooding); it is an account like any other.

1. Open `virga-web` and sign in through Access. Onboarding and manual scans are for the addresses in `ADMIN_EMAILS`.
2. Enter the scanned account's ID (32 hex characters), a display name, the profile, the scan cadence in hours (1 to 720, default 24, D-09) and the token.
3. The web Worker hands the token to the broker (`TokenIntake.store`) and keeps no copy. The broker checks it with two read calls, `GET /accounts/{id}/tokens/verify` and `GET /accounts/{id}/tokens/{token_id}`, and runs the write check. A rejected token is not stored; the form shows the reasons, and warnings such as `reaches_content`.
4. On success the account goes into the index (`Admin.addAccount`). The dispatcher starts scans of due accounts every hour at minute 17 UTC, and a new account is due at its next run. An admin can also start a scan at once (`Admin.triggerScan`).
5. After the scan, check coverage per class. `no_permission` names the class whose group is missing; add the group to a new token and onboard the account again with it.

**Renewal.** Tokens expire after at most 90 days. Create the next token before that and onboard the account again with the same ID: the broker replaces the stored token and the account keeps its graph and findings. Then delete the old token in the scanned account.

## What the scanned account's audit log shows

Every API call Virga makes in a scanned account appears in its Audit Logs v2, which have recorded reads as `view` actions since 2026-10-13:

- **Action type** `view`. Virga creates no `create`, `update` or `delete` entries. If you ever see one from Virga's token, revoke the token at once and report it: it would mean the token could write and the broker's allowlist was bypassed.
- **Actor** type `account` (an account API token), with the token's ID and name.
- **Request:** method `GET` and the path, for example `/accounts/<id>/workers/workers` or `/zones/<zone_id>/dns_records`.
- **Onboarding** adds two entries: the token verifying itself and reading its own details.
- **Volume:** one entry per call: a listing per product plus a few calls per zone, Worker, Access app, tunnel and R2 bucket, on every scan (daily by default, D-09).
- **GraphQL:** the traffic query is a `POST` to `/graphql`. Whether it is logged as a `view` action is not documented: **verify (S-06)**.

Where to look:

- **Dashboard:** **Manage Account** > **Audit Logs**. The default filter hides `view` actions ("Action type is not view"); remove it, then filter by the token.
- **API:** `GET /accounts/{account_id}/logs/audit?since=…&before=…` (both parameters are required). The filters `actor_token_id` and `action_type` accept `not`, so your own monitoring can leave Virga's reads out. Reading the audit log needs Account Settings Read.
- **Retention:** 18 months; the dashboard queries the last 90 days.

## Offboarding

There is no offboarding command yet (A-13). Until there is, offboard by hand, in this order:

1. **Revoke the token.** The scanned account deletes Virga's token under **Manage account** > **Account API tokens**. This alone ends all access, whatever happens in the tool account.
2. **Stop scans.** In `apps/core`:

   ```sh
   npx wrangler d1 execute virga-index --remote --command "UPDATE accounts SET status = 'paused' WHERE id = '<account_id>'"
   ```

   A paused account stays paused if it is onboarded again; set `status = 'active'` to resume.
3. **End a running scan,** if there is one: `npx wrangler workflows instances list virga-scan`, then `npx wrangler workflows instances terminate virga-scan <instance_id>`.
4. **Delete the stored token.** In `apps/broker`:

   ```sh
   npx wrangler d1 execute virga-vault --remote --command "DELETE FROM vault_tokens WHERE account_id = '<account_id>'"
   ```

5. **Delete the index rows,** in `apps/core`. The UI and the API stop showing the account:

   ```sh
   npx wrangler d1 execute virga-index --remote --command "DELETE FROM scan_runs WHERE account_id = '<account_id>'; DELETE FROM accounts WHERE id = '<account_id>'"
   ```

What stays behind:

- **The graph.** The account's `AccountGraph` Durable Object keeps its nodes, history and findings. No entrypoint deletes one account's object yet.
- **Workflow instances** for 3 days (completed) or 7 days (failed). They hold counters only; `npx wrangler workflows instances delete virga-scan <instance_id>` removes them earlier.
- **D1 Time Travel** can restore deleted rows of `virga-vault` and `virga-index` within its retention window. The token ciphertext stays useless without the master key, and the token itself is revoked in step 1.
- **Logs** of the Workers (observability is on) under the Workers Logs retention. They contain account IDs, never tokens.

## Troubleshooting

### Deploy

| Message or symptom | Cause and fix |
| --- | --- |
| `set CLOUDFLARE_API_TOKEN …` or `set CLOUDFLARE_ACCOUNT_ID …` | Export both. The account ID is 32 hex characters |
| `unset CLOUDFLARE_ENV` or `unset WRANGLER_CI_OVERRIDE_NAME` | Unset the variable. The script deploys only the top-level configuration it checked, under the Worker names in the configs |
| `usage: node scripts/deploy.ts [--dry-run]` | The script takes no other option; there is no `--env` |
| `error: apps/<app>/wrangler.jsonc: …` | The configs do not fit together (names, service bindings, entrypoints, order, exposure, state). Fix the config; the message names the binding |
| `… is a Wrangler config above the app` | A `wrangler.json`, `wrangler.jsonc` or `wrangler.toml` in the repository root, in `apps/` or further up, for example in your home directory. Remove or rename it: Wrangler run in an app directory without `--config` would use it |
| `… an app has one Wrangler config` | The app has more than one of `wrangler.json`, `wrangler.jsonc` and `wrangler.toml`. Keep only `wrangler.jsonc` |
| `named environments (env) are not supported` | Remove the `env` block. The script checks and deploys only the top-level configuration |
| `secrets.required names CLOUDFLARE_…` | Remove the name. The deploy token and the other `CLOUDFLARE_` and `CF_` variables never become Worker secrets |
| `D1 binding … has database_id …, which is …, not …` | The `database_id` belongs to another database than `database_name`. Correct it, or remove `database_id`: the script finds databases by name |
| `D1 database … is also bound by …` | Two Workers bind one database, by name or by ID. Each database belongs to one Worker (D-08); the vault only to `virga-broker` |
| `… not found; run pnpm install first` | The app has no Wrangler installed. Run `pnpm install` at the repository root |
| `store_id is a placeholder` | Set `store_id` in `apps/broker/wrangler.jsonc`, or use the `MASTER_KEY` fallback. A dry run only reports it |
| `Secrets Store … has no secret virga-master-key` or `has no MASTER_KEY secret` | Create the key as in [Master key](#master-key), then run the deploy again |
| `secret virga-master-key lacks the workers scope` | Add the `workers` scope to the secret in the Secrets Store dashboard |
| `failed to fetch secrets store binding due to authorization error - check deploy permissions and secret scopes` | The deploy token lacks Account Secrets Store Edit, or the secret lacks the `workers` scope |
| `More than one account available but unable to select one in non-interactive mode` | Set `CLOUDFLARE_ACCOUNT_ID` |
| `Authentication error [code: 10000]` or a 403 from Wrangler | The deploy token lacks a group from [the table](#the-deploy-token), has expired, or belongs to another account. Creating a Worker for the first time needs Workers Admin |
| `Couldn't find a D1 DB named …` | A database was deleted after the list. Run the deploy again; it creates it |
| A migration fails | D1 rolls back the failed migration; earlier ones stay applied. Fix the cause and run the deploy again |
| `virga-web does not exist yet and requires the secrets …` or `virga-web requires the secrets …` | `apps/web` lists them under `secrets.required`. Set `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` and `ADMIN_EMAILS` as environment variables of the deploy; create any other name with the `npx wrangler secret put` command the message prints |
| The dry run of `virga-web` fails on missing assets | The app's `build` script did not produce them. Run `pnpm run build` in `apps/web` to see why |
| `ACTION:` lines | Not errors. Things left to do, such as settings of `virga-web` |

### UI and onboarding

| Symptom | Cause and fix |
| --- | --- |
| Every request to `virga-web` is refused | `ACCESS_TEAM_DOMAIN` or `ACCESS_AUD` is missing or wrong. The team domain includes `https://`; the AUD tag belongs to the app that protects `virga-web` |
| No Access login page appears | Access protects only previews. Change it to **All traffic** |
| Signed in, but onboarding is refused | Your address is not in `ADMIN_EMAILS` |
| WebSocket requests fail with 403 | Worker-level Access does not support WebSockets |
| `details_unavailable` | The token cannot read its own policies. Add Account API Tokens Read |
| `not_read_only` | A group is not a read group, or its name is unknown to the check. Remove it |
| `no_expiry`, `expiry_too_far`, `expired`, `not_yet_valid` | Set a TTL end date at most 90 days ahead and no start date in the future |
| `account_not_covered` | The account resources do not include the scanned account. The account ID in the form must be the scanned account |
| `foreign_resource` | The token covers another account, or "all zones" in a form the check does not read (**verify**). Select the zones one by one |
| `not_account_token` | A user token, Global API Key or Wrangler token. Create an account API token |
| `broker_error` | Usually the master key: the broker cannot read it. Check the deploy output for the master key line |
| Warning `reaches_content` | A group reads code or data. Expected for D1, KV and R2 read until S-05 is done |

### Scans

| Symptom | Cause and fix |
| --- | --- |
| A class shows `no_permission` | A permission group is missing; see [the inventory table](#inventory-profile). Rules that need the class show `not evaluated` |
| `workers` is `no_permission` although the token has Workers Metadata Read-Only | The version detail endpoint, see [above](#inventory-profile) (**verify**) |
| `storage` is `no_permission` or `partial` | D1 Read, Workers KV Storage Read or Workers R2 Storage Read is missing |
| Scans pause and continue later | The rate budget: 1,200 REST requests per 5 minutes per token, shared with everything else that uses the same token. The broker keeps a margin and waits instead of risking the 5-minute block |
| A scan stays `running` | A scan running longer than 12 hours counts as hung and is replaced by the next one (decision 0002) |
| Nothing is scanned | The account is `paused`, or the token was removed. Check the index row and onboard again |
