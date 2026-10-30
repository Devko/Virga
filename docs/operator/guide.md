# Operator guide

Status: phase 1, written 2026-10-29 against Wrangler 4.151.0 and the Cloudflare docs of that date; deploy checks updated 2026-10-30 (R3-03 to R3-06 of the [round 3 security review](../reviews/2026-10-30-security-review-round-3.md), then R5-01 to R5-03 of the [round 5 verification](../reviews/2026-10-30-verification-round-5.md), in round 7 Wrangler's environment and the assets directory, in round 8 the order of builds and checks, R6-01 of the [round 6 verification](../reviews/2026-10-30-verification-round-6.md), and in round 9 the builds' pnpm, the generated rules and the release-age check before every install, R8-02, R8-04 and R8-05 of the [round 8 verification](../reviews/2026-10-30-verification-round-8.md)), offboarding the same day (account removal in the UI and API). Items marked **verify** are documented inconsistently or not at all and still need a check in a real account (spikes S-05, S-06 and S-08 in the [implementation plan](../implementation-plan.md#phase-0-decisions-and-spikes)).

Virga is an independent open source project. It is not affiliated with or endorsed by Cloudflare, Inc., and it uses no Cloudflare logos (D-01). The [threat model](../architecture/threat-model.md) lists what an instance protects, against whom, and the risks that remain.

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
8. [Audit trail and OCSF export](#audit-trail-and-ocsf-export)
9. [Offboarding](#offboarding)
10. [Troubleshooting](#troubleshooting)

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
- Linux or macOS. The deploy script runs each app's own Wrangler, the package in `apps/<app>/node_modules/wrangler`, with the Node that runs the script.
- Network access to `registry.npmjs.org` for the release-age check.

```sh
node scripts/check-release-age.ts
corepack enable
pnpm install --frozen-lockfile
```

The first command is the release-age check ([CONTRIBUTING.md](../../CONTRIBUTING.md)): every version in `pnpm-lock.yaml` and the pnpm version that `package.json` pins must have been published at least 14 days ago, with the integrity the registry publishes. It runs on Node alone and imports nothing from `node_modules`. Run it before anything installs or starts the checkout's pnpm, and not as `pnpm check:release-age`: that runs the pnpm the commit pins before the check has dated it. `--frozen-lockfile` installs exactly what the check dated, or nothing.

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

Run it from a plain shell. A debugger terminal, for example, sets `NODE_OPTIONS` to load its own code into every Node process, and the script refuses to run then (step 1).

The script:

1. Checks its own environment, also for a dry run, and refuses to run while:
   - one of these is set to anything. They act on the script itself, which holds the token, before it could drop them:
     - `NODE_OPTIONS`, `NODE_COMPILE_CACHE` and `OPENSSL_CONF` load code into Node and the processes it starts;
     - `LD_PRELOAD`, `LD_AUDIT` and `DYLD_INSERT_LIBRARIES` load a library into them, and `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `DYLD_FALLBACK_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`, `DYLD_FALLBACK_FRAMEWORK_PATH`, `DYLD_VERSIONED_LIBRARY_PATH` and `DYLD_VERSIONED_FRAMEWORK_PATH` make the dynamic loader look for their libraries there first;
     - `NODE_DEBUG` and `NODE_DEBUG_NATIVE` make Node print its own debug output, which the script cannot redact. With `NODE_DEBUG=child_process` that is the environment of every process the script starts, the token included;
     - `NODE_TLS_REJECT_UNAUTHORIZED` turns off certificate checks;
   - `CLOUDFLARE_ENV` or `WRANGLER_CI_OVERRIDE_NAME` is set: with them, Wrangler would deploy a named environment or under another Worker name, not the configuration the script checked;
   - `CF_API_BASE_URL` is set, or `CLOUDFLARE_API_BASE_URL`, `WRANGLER_API_ENVIRONMENT` or `CLOUDFLARE_COMPLIANCE_REGION` is set to anything but `https://api.cloudflare.com/client/v4`, `production` and `public`: the token goes only to the public API.

   Then it prints the proxy settings it passes to Wrangler (see [Behind a proxy](#behind-a-proxy)) and names the other `CLOUDFLARE_`, `CF_` and `WRANGLER_` variables that Wrangler does not get, so that a setting such as `WRANGLER_LOG` does not seem to have worked. The script itself takes no option but `--dry-run`.
2. Checks the app directories `apps/broker`, `apps/core` and `apps/web` before the builds (`apps/web` may be missing, then it deploys broker and core only). It stops if:
   - an app has more than one of `wrangler.json`, `wrangler.jsonc` and `wrangler.toml`;
   - any of them sits in a directory above an app, up to the filesystem root, including the repository root and your home directory: Wrangler run in an app directory without `--config` takes the first `wrangler.json` above it before the app's own config;
   - an app directory holds `.env`, `.env.local` or `.dev.vars`: Wrangler loads `.env` and `.env.local` from the directory it runs in into its environment, where a file could change the API host (and so where the token goes), the Worker name or the environment that is deployed;
   - an app directory, or anything under it outside its own `node_modules`, is a symlink. Wrangler bundles, migrates and uploads what a link points to, and Vite copies it into the assets, wherever it is. `node_modules` is left out because pnpm links every dependency there, as `pnpm-lock.yaml` says;
   - an app directory holds a `.corepack.env`, or an app's `package.json` names `packageManager` or `devEngines.packageManager`. Corepack, the pnpm of the [prerequisites](#prerequisites), takes the pnpm version from the nearest `package.json` that names one and loads a `.corepack.env` into its environment, where it can allow a pnpm from any URL or another registry. The release-age check dates only the root's pin, so only the root names the package manager (R8-02).

   Then it records the Wrangler each app runs: `apps/<app>/node_modules/wrangler` with symlinks followed, the bin file its `package.json` names, and the SHA-256 of every file of that package and of every package it depends on, found the way Node finds them. It also records the `wrangler` shims in `apps/<app>/node_modules/.bin`, which the `npx wrangler` commands in this guide run, and the list of packages in every `node_modules` directory Node searches from these packages, so that a package planted where Wrangler would load it counts too. It prints the Wrangler version and path it recorded.
3. Loads the rule compiler of the checkout (`packages/rules/src/generate.ts`), so that the code that checks the generated rules in step 6 is not code a build wrote. Then it runs each app's `build` script, if it has one (`apps/web` builds the UI with Vite), as `pnpm --dir apps/<app> run build` from the repository root, so that corepack takes the root's pnpm pin, and with `COREPACK_ENV_FILE=0`, so that it loads no `.corepack.env` (R8-02). Every build runs before any config is read, without credentials (see "What it never does"). The UI build itself fails on a symlink in `apps/web/spa/public`, which Vite would otherwise copy into the assets with the file it points to.
4. After the builds, compares Wrangler with what step 2 recorded and stops on any file that was added, removed or changed, then runs the checks of step 2 again. Then it reads each config (`wrangler.jsonc` or `wrangler.json`), remembers the SHA-256 of the bytes it read, and stops if:
   - a config has a `__proto__`, `constructor` or `prototype` key at any depth, or a key twice. The script reads each config the way Wrangler does (JSON with comments and trailing commas), and these are where the two readings, or Wrangler and a reviewer, could differ: Wrangler deploys the keys under `__proto__` as the config's own;
   - `assets.directory` is not a directory below the app directory. Wrangler resolves it against the config's directory and uploads whatever it holds, so the script resolves it the same way, follows every symlink on the way, and refuses a path that climbs out (`../..`), an absolute path elsewhere, a symlink that leads elsewhere or nowhere, and the app directory itself.
5. Checks the configs against each other and stops on any error:
   - each Worker sets only keys the checks cover for it (`CONFIG_KEYS` and `NESTED_KEYS` in `scripts/lib/topology.ts`). Anything else, for example `unsafe`, `build`, `previews`, `tail_consumers` or a service binding's `props`, would deploy unchecked and is an error;
   - each Worker has its expected name (`virga-broker`, `virga-core`, `virga-web`);
   - every service binding names an entrypoint that the target's main module exports, and is one the [topology](../implementation-plan.md#deployment-topology-proposal) allows: core binds `virga-broker#ApiCaller`; web binds `virga-broker#TokenIntake`, `virga-core#GraphReader` and `virga-core#Admin`, and never `ApiCaller`;
   - bindings follow the deploy order broker, core, web;
   - broker and core have `workers_dev` and `preview_urls` off and no routes;
   - only the broker binds Secrets Store, each D1 database belongs to one Worker by `database_name` and by `database_id` (D-08), and the web Worker binds no D1 database, no Durable Object and no Workflow;
   - Durable Object and Workflow classes are exported, and no Worker binds a class of another Worker (`script_name`);
   - no config has named environments (`env` blocks), and no `secrets.required` lists a `CLOUDFLARE_` or `CF_` name.
6. Compiles the rules in `rules/` with the compiler it loaded in step 3, runs every rule's fixtures, and compares the output byte for byte with `packages/rules/src/rules.gen.ts` and `fixtures.gen.ts`, which `virga-core` bundles as they are. It stops if a rule or fixture fails, or if a generated module is not the compiler's output: a statement added by hand after a rule's SQL there would run on Durable Object SQL, which runs every statement it gets (R8-05). This is the check `pnpm rules:check` runs in CI.
7. Lists the D1 databases of the account. Before it creates or migrates anything, it checks that every `database_id` exists and is the database its `database_name` names, and that no database, by ID, is bound by two Workers. Then it creates `virga-vault` and `virga-index` if they are missing and applies their migrations (`wrangler d1 migrations apply --remote`).
8. Checks the master key.
9. Checks the web settings, if `apps/web` declares required secrets.
10. Deploys `virga-broker`, `virga-core` and `virga-web`, in this order. Right before each `wrangler deploy` it checks `assets.directory` again and refuses any symlink in it: Wrangler uploads the file a link points to and the files under a linked directory, wherever they are.
11. Prints what is still to do as `ACTION:` lines.

Before every Wrangler call, in steps 7 to 10 and in a dry run alike, the script also checks that the config still holds the bytes it checked in step 4, that the generated rules still hold the bytes it checked in step 6, that the app directory holds no `.env` file, and that every file recorded in step 2 is unchanged. It refuses the call otherwise, so Wrangler never reads a config, bundles generated rules, or runs code, that the script has not checked. A failing build stops the deploy before anything in the account changes.

It is safe to run again: existing databases are reused, applied migrations are skipped, and each Worker gets a new version.

What it never does:

- It reaches the Cloudflare API only through Wrangler, which acts on the account of `CLOUDFLARE_ACCOUNT_ID`. Apart from Wrangler it runs only the apps' `build` scripts, and in its own process the rule compiler (step 6), which reads `rules/` and runs the fixtures on an in-memory database.
- It never runs Wrangler through `node_modules/.bin`: the shim there is a shell script that anything can append to, and it runs whichever `node` comes first on `PATH`. The script runs the recorded bin file of the Wrangler package with the Node that runs the script itself.
- It never lets Wrangler choose a config: every Wrangler call gets `--config` with the absolute path of the file it checked, so Wrangler neither searches for a config nor follows a `.wrangler/deploy` redirect, and it never selects a named environment.
- It never lets Wrangler load a `.env` file: every Wrangler call gets `--env-file` with the null device (`/dev/null`) in place of `.env` and `.env.local`. Wrangler 4.151.0 has no flag that turns the loading off.
- It sends the token only to `https://api.cloudflare.com/client/v4`: Wrangler gets `CLOUDFLARE_API_BASE_URL` set to it, `WRANGLER_API_ENVIRONMENT=production` and `CLOUDFLARE_COMPLIANCE_REGION=public`, and never `CF_API_BASE_URL`. A variable that is set wins over a `.env` file.
- It gives Wrangler only these variables of its environment: `PATH`, `HOME`, `TMPDIR`, `USER`, `LOGNAME`, `LANG`, `LANGUAGE`, the `LC_` variables, `TZ`, `TERM`, `COLORTERM` and `NO_COLOR` (on Windows also the usual system variables such as `SystemRoot`, `ComSpec`, `PATHEXT`, `TEMP` and `USERPROFILE`), the proxy variables `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (each also in lowercase) and `NODE_EXTRA_CA_CERTS`, `CLOUDFLARE_ACCOUNT_ID`, and for a real deploy `CLOUDFLARE_API_TOKEN`. It sets the API variables (above) and the telemetry variables (below) itself. Everything else stays out, including every other `CLOUDFLARE_`, `CF_` and `WRANGLER_` variable (credentials, bundling, logs, output files), `NODE_PATH`, `NODE_ENV` and `DEBUG`; without them, the checked config and Wrangler's defaults decide what is deployed where.
- It passes only `CLOUDFLARE_API_TOKEN` to Wrangler: a Global API Key in the environment is not used. A dry run passes no credentials at all. The `build` scripts get no `CLOUDFLARE_` or `CF_` variable in their environment, and `COREPACK_ENV_FILE=0` in place of any value of yours; see [What the build checks cover](#what-the-build-checks-cover) for what that does not prevent. No config may have a custom build (`build.command`): Wrangler would run it with the token in its environment.
- It takes only `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` and `ADMIN_EMAILS` from its environment to upload as secrets of `virga-web`; never the token or any other variable.
- It runs Wrangler with stdin closed, so Wrangler never prompts and never writes resource IDs into a `wrangler.jsonc`.
- It never prints the token or a setting it uploads: all output passes through a filter that also removes anything shaped like a Cloudflare credential (`cfat_`, `cfut_`, `cfk_`, `cfoat_`). It never reads the master key.
- It sends no Wrangler telemetry or error reports (`WRANGLER_SEND_METRICS=false`, `WRANGLER_SEND_ERROR_REPORTS=false`) and keeps Wrangler's debug log sanitized (`WRANGLER_LOG_SANITIZE=true`).

The `npx wrangler` commands in this guide run in an app directory without `--config`. Wrangler then uses that app's own config only while no other Wrangler config sits next to or above it, which step 2 checks, and only while `CLOUDFLARE_ENV` is unset. It also loads `.env` and `.env.local` from that directory, which step 2 refuses too: keep them out of the app directories. It runs the shim in `node_modules/.bin`, which the deploy compares with its record only while a deploy runs. And it gets your whole environment, not the allowlist above: unset the variables step 1 refuses before you run one with a token. Run the dry run first if in doubt.

### What the build checks cover

The `build` scripts and everything they load (Vite, its plugins, `vite.config.ts` and their dependencies) run as your user. The script keeps the token out of their environment, but it cannot keep their code from doing what your user can do. The checks above make sure that what the builds change is either refused or checked before Wrangler gets the token:

- A build that rewrites a `wrangler.jsonc`, for example to add `unsafe` bindings, a `build.command` or a `__proto__` member, is caught by the config checks, which run after every build (steps 4 and 5).
- A build that writes to Wrangler, its dependencies or a `wrangler` shim, or plants a package where Wrangler would load it, is caught by the comparison with the record of step 2.
- A build that leaves a `.env` file, a `.corepack.env`, a package manager pin or a symlink in an app directory is caught after the builds, a `.env` file again before each Wrangler call, and a link in the assets again before each `wrangler deploy`.
- A build that changes `rules.gen.ts` or `fixtures.gen.ts` so that they are no longer the compiler's output of `rules/` is caught by step 6. The compiler that checks them was loaded before the builds.
- Something that changes a config or a generated rule module after it was checked, such as a process a build left running, is caught before the next Wrangler call.

Each build starts at the repository root as `pnpm --dir apps/<app> run build`. With corepack's `pnpm`, a build started in `apps/<app>` would run with the pnpm that the app's `package.json` names, which the release-age check never dates, as a child of the deploy. From the root, corepack takes the root's pin, and `COREPACK_ENV_FILE=0` keeps it from loading a `.corepack.env` anywhere (R8-02). Step 2 refuses both in an app directory anyway, for the pnpm commands you run there yourself.

They do not protect against build code that:

- reads the token anyway. The deploy process holds it in its environment while the builds run, and a process of the same user can read that environment (on Linux, `/proc/<pid>/environ` of the deploy) or attach to the process with a debugger where the system allows it;
- reads or changes anything else your user can reach: SSH keys, other tokens, Wrangler's own login in your home directory, your shell profile, the `node` binary on `PATH` or the one that runs the deploy, or another checkout;
- changes the app's sources, the packages they bundle or migrations, or a rule in `rules/` together with its fixtures and generated modules. Wrangler bundles and applies what is there after the builds; the bindings stay checked, and every rule still passes the compiler and its fixtures, but the code inside a Worker is what the build left;
- keeps running and changes a file between the last check and the moment Wrangler reads it.

So the build code must be trusted as far as the token is, and it is covered by the supply chain checks instead: `pnpm install --frozen-lockfile` installs exactly the versions and integrity hashes in `pnpm-lock.yaml`, and the release-age check (`node scripts/check-release-age.ts`) refuses versions younger than 14 days ([CONTRIBUTING.md](../../CONTRIBUTING.md)). These checks hold only where the check runs before the install: CI runs it before any job installs, the [deploy workflow](#deploy-from-ci) before its deploy job, and on a workstation you run it before `pnpm install` ([Prerequisites](#prerequisites), [Updates](#updates)). Prefer to deploy from [CI](#deploy-from-ci). The builds run there in the same step as the token too, but each run starts on a fresh runner from a fresh checkout, nothing a build leaves behind reaches a later run, and the runner holds no other credentials of yours. On a workstation, deploy from a fresh clone, as a user that holds no other credentials you care about.

### Behind a proxy

Wrangler uses `HTTPS_PROXY` or `HTTP_PROXY` (lowercase names first) for its connections, except to the hosts in `NO_PROXY`. If the proxy presents its own certificates, export its CA as a PEM file and point `NODE_EXTRA_CA_CERTS` to it; never set `NODE_TLS_REJECT_UNAUTHORIZED`, which the script refuses. The script prints the settings it passes on, the proxy's host and port only, never a user name or password in the URL:

```text
Proxy settings passed to Wrangler:
  HTTPS_PROXY: proxy.example.com:3128 (credentials not shown)
  NODE_EXTRA_CA_CERTS: /etc/ssl/proxy-ca.pem; Node trusts these certificates as well, so a proxy with one of their keys can read the API token
```

A proxy that holds the key of such a CA can read every request Wrangler sends, the deploy token included. Deploy through it only if you trust it with the token; otherwise deploy from CI or another network.

### Deploy from CI

CI runs the dry run on every push (`.github/workflows/ci.yml`, job `deploy-dry-run`). It needs no variable beyond what a GitHub-hosted runner sets; like a real deploy, it stops if the runner sets one that step 1 refuses. For real deploys, a separate workflow with a protected environment keeps the token away from pull requests. An example, with actions pinned like the CI workflow:

```yaml
name: Deploy
on: workflow_dispatch
permissions:
  contents: read
jobs:
  # The release-age check on the commit to deploy, before anything installs
  # its pnpm or packages. It needs the registry, installs nothing and runs no
  # package code.
  release-age:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version-file: .nvmrc
      - run: node scripts/check-release-age.ts

  # No package cache: the install takes nothing another run wrote.
  deploy:
    needs: release-age
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

- **`release-age` first.** `pnpm/action-setup` installs the pnpm that `package.json` names, and `pnpm install` installs the packages that the builds and Wrangler run beside the token. Both jobs check out the commit the workflow runs for, so the deploy job installs only what the check dated. Keep `needs: release-age` on every job that installs or deploys; `scripts/test/guide.test.ts` checks this example for it.
- **No cache.** Neither job sets `cache:` on `setup-node` or restores a pnpm store.
- **The generated rules.** The deploy itself compiles `rules/` and refuses `packages/rules/src/*.gen.ts` that are not the compiler's output (step 6), so the workflow needs no `pnpm rules:check`.
- **Deploy branch.** Restrict the environment to the branch you deploy, and protect that branch so that only reviewed commits that passed CI reach it.

### Updates

Pull the new version, run `node scripts/check-release-age.ts`, then `pnpm install --frozen-lockfile`, then the deploy script. New D1 migrations are applied before the Workers are deployed. Durable Object migrations are part of `wrangler deploy`.

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

**Account API Tokens Read shows every token.** The onboarding check needs this group to read the token's own policies, so no scan token works without it. The same group lets Virga list every account API token of the scanned account. Virga stores each token's name, status, dates, permission groups, resources and IP condition, never its value, and every viewer of the instance and every MCP client sees them ([threat model](../architecture/threat-model.md#account-api-tokens-read), TM-02). Tell the account owner before they create the token.

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

## Audit trail and OCSF export

Every request to the JSON API and every MCP tool call by an identity that passed Access is recorded in the `tool_audit` table of `virga-index`: the Access email or service token client ID, the channel (`ui`, `api`, `mcp`), the route or tool name, the account ID and the outcome. Request bodies, tokens and strings from scanned accounts are never recorded. The channel `ui` comes from the `Sec-Fetch-Site` header, which a client can set, so it describes the call; only the identity is verified.

- **Reading it:** admins open the Audit trail page, or call `GET /api/audit`. Viewers and service tokens get 403.
- **Retention:** rows are deleted after 90 days by the hourly dispatcher. They hold the emails of the tool's users, so include the table in your privacy notice. Removing an account keeps its audit rows until they expire.

Findings export as OCSF 1.9.0 Detection Findings from the account page (**Export findings**) or with `GET /api/accounts/{id}/findings/export?format=json|ndjson`. A SIEM collector authenticates with an Access service token and follows the `Link: rel="next"` header until there is none. Each response holds up to 1,000 findings and about 4 MiB. Strings from the scanned account stay JSON data and are listed under `unmapped.virga.untrusted`. The [mapping](../architecture/ocsf-export.md) says what the export holds and what it does not yet do.

## Offboarding

1. **Revoke the token.** The scanned account deletes Virga's token under **Manage account** > **Account API tokens**. This alone ends all access, whatever happens in the tool account.
2. **Remove the account.** An admin opens the account's page in the UI, chooses **Remove account…** and types the account ID to confirm. Over the API it is `DELETE /api/accounts/<account_id>` with the JSON body `{"confirm": "<account_id>"}`. Like every admin call, it needs an Access sign-in of an address in `ADMIN_EMAILS`, `Content-Type: application/json` and an `Origin` header with `virga-web`'s own origin.

The removal runs in this order:

1. The broker deletes the stored token, then the account's rate budget (`TokenIntake.remove`). A scan that still runs gets no more API access.
2. Core marks the account `removing` in the index, deletes its whole graph (nodes, history and findings), then its index rows (`accounts`, `scan_runs`) (`Admin.removeAccount`, R5-08). Until the last step the account stays listed with status `removing`; the UI marks it **removal pending**, hides **Start scan**, and offers **Remove account again…**, which finishes the removal. When the graph of such an account can no longer be read, the account page shows the read error, still says that the removal is pending, and still offers **Remove account again…**. From the first step on, the dispatcher and **Start scan** start no scan of it, and a scan that begins then, for example one queued before the removal, stops at its first step without an API call or a write (R4-03). A scan that still runs is refused at its next write once the graph is deleted.

| Response | Meaning |
| --- | --- |
| 200 `{ token: { removed }, account: { removed } }` | Done. `removed: false` means there was nothing left to delete, for example on a repeat |
| 400 `confirmation_required` | The body does not name the account |
| 502 `token_not_removed` | The broker step failed. Core was not called, so the account stays listed. Run the removal again |
| 502 `account_not_removed` | The token is gone; the account stays listed as `removing`, with or without its graph. Run the removal again, or onboard the account again, which finishes the removal first |

Both steps are idempotent, so a repeat finishes a partial removal. To scan the account again, onboard it again with a new token.

The `removing` state is stored in `accounts.removing_at` ([migration 0002](../../apps/core/migrations/0002_account_removal.sql)), which `pnpm deploy` applies with the other index migrations.

What stays behind:

- **Durable Object point-in-time recovery.** SQLite-backed Durable Objects keep 30 days of history for point-in-time recovery; whether it can restore a graph after `deleteAll()` is not documented: **verify**. No Virga entrypoint restores one.
- **Workflow instances** for 3 days (completed) or 7 days (failed). They hold counters only; `npx wrangler workflows instances delete virga-scan <instance_id>` removes them earlier.
- **D1 Time Travel** can restore deleted rows of `virga-vault` and `virga-index` within its retention window. The token ciphertext stays useless without the master key, and the token itself is revoked in step 1.
- **Logs** of the Workers (observability is on) under the Workers Logs retention. They contain account IDs, never tokens.

## Troubleshooting

### Deploy

| Message or symptom | Cause and fix |
| --- | --- |
| `set CLOUDFLARE_API_TOKEN …` or `set CLOUDFLARE_ACCOUNT_ID …` | Export both. The account ID is 32 hex characters |
| `unset NODE_OPTIONS: it can load code …` (or `NODE_COMPILE_CACHE`, `LD_PRELOAD`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES`, `OPENSSL_CONF`) | Unset the variable for the deploy, for example `env -u NODE_OPTIONS node scripts/deploy.ts`, or run it from a plain shell instead of a debugger terminal. It loads code into the deploy script, which holds the token, and into Wrangler. The script refuses any value, `--max-old-space-size` included |
| `unset LD_LIBRARY_PATH: the dynamic loader looks there first …` (or `DYLD_LIBRARY_PATH`, `DYLD_FALLBACK_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`, `DYLD_FALLBACK_FRAMEWORK_PATH`, `DYLD_VERSIONED_LIBRARY_PATH`, `DYLD_VERSIONED_FRAMEWORK_PATH`) | Unset it for the deploy, for example `env -u LD_LIBRARY_PATH node scripts/deploy.ts`. A library under the name of one Node needs, in a directory on that path, runs inside the deploy script with the token in its environment. If Node needs the variable to start at all, install a Node that does not |
| `unset NODE_DEBUG: Node prints its own debug output …` (or `NODE_DEBUG_NATIVE`) | Unset it for the deploy. Node prints its debug output straight to the terminal, past the script's redaction; with `child_process` that output holds the token. To debug a Wrangler call, run the `npx wrangler` command by hand without the deploy token |
| `unset NODE_TLS_REJECT_UNAUTHORIZED: it turns off certificate checks …` | Unset it. Behind a proxy that presents its own certificates, set `NODE_EXTRA_CA_CERTS` to its CA instead ([Behind a proxy](#behind-a-proxy)) |
| `unable to get local issuer certificate` or `self-signed certificate in certificate chain` from Wrangler | A proxy presents its own certificates. Set `NODE_EXTRA_CA_CERTS` to its CA as a PEM file. `NODE_OPTIONS=--use-openssl-ca` and `NODE_USE_SYSTEM_CA` do not reach Wrangler |
| `Proxy settings passed to Wrangler: …` | Not an error. Check that the host is your proxy, and see [Behind a proxy](#behind-a-proxy) |
| `Wrangler does not get …: the deploy passes it only the variables in the operator guide` | Not an error. The named variables do not reach Wrangler (see "What it never does"); a dry run names `CLOUDFLARE_API_TOKEN` too. To see Wrangler's own log, run the `npx wrangler` command by hand |
| `unset CLOUDFLARE_ENV` or `unset WRANGLER_CI_OVERRIDE_NAME` | Unset the variable. The script deploys only the top-level configuration it checked, under the Worker names in the configs |
| `unset CLOUDFLARE_API_BASE_URL; the deploy sends the token only to …` (or `CF_API_BASE_URL`, `WRANGLER_API_ENVIRONMENT`, `CLOUDFLARE_COMPLIANCE_REGION`) | Unset the variable. The deploy sends the token only to the public API, `https://api.cloudflare.com/client/v4` |
| `usage: node scripts/deploy.ts [--dry-run]` | The script takes no other option; there is no `--env` |
| `error: apps/<app>/wrangler.jsonc: …` | The configs do not fit together (names, service bindings, entrypoints, order, exposure, state), or the file is not JSON with comments. Fix the config; the message names the binding, key or line |
| `apps/<app>/.env: Wrangler would load it into its environment …` (or `.env.local`, `.dev.vars`) | Remove the file, or move it out of the app directory while you deploy. Wrangler loads it into its environment, where it could change the API host, the Worker name or the environment. Pass settings as environment variables of the deploy instead |
| `key "__proto__" is refused …` (or `constructor`, `prototype`) | Remove the key. Wrangler reads a `__proto__` member as the prototype and deploys the keys under it, which the checks would not see |
| `duplicate key "…"` | Keep one of the two. Wrangler uses the last one, a reader may take the first |
| `assets.directory "…" resolves to … (symlinks followed), outside apps/<app>` | Point `assets.directory` to a directory below the app directory, such as `./dist/client`, and remove any symlink on the way. Wrangler would upload whatever the directory holds |
| `assets.directory "…" is apps/<app> itself` | Use a directory below it. Wrangler would upload the app's sources and config as assets |
| `assets.directory "…" passes through …, a symlink to a path that does not exist` | Remove the link and let the build create the directory |
| `assets.directory "…" holds symlinks, whose targets Wrangler would upload: …` | Replace each link with the file itself, or remove it. Wrangler uploads what a link points to, also from outside the app |
| `… is not supported: the deploy does not check it, and Wrangler would deploy it` or `virga-<x> may not set …` | Remove the key. A key the deploy is to accept needs a check first: add it to `CONFIG_KEYS` or `NESTED_KEYS` in `scripts/lib/topology.ts` together with that check |
| `build.command is not supported …` | Move the step into the app's `build` script in `package.json`, which the deploy runs without credentials. Wrangler would run `build.command` with the token in its environment |
| `unsafe is not supported …` or `previews is not supported …` | Remove the block. Unsafe bindings and the bindings of preview versions bypass every binding check |
| `… uses class … of virga-…; bindings to another Worker's classes are not part of the topology` | Remove the binding or its `script_name`. Each Worker binds only its own Durable Objects and Workflows; the web Worker reads the graph through `GraphReader` and starts scans through `Admin` |
| `virga-web must not bind Workflows` | Remove the `workflows` entry. The web Worker starts scans through `Admin` |
| `… is a Wrangler config above the app` | A `wrangler.json`, `wrangler.jsonc` or `wrangler.toml` in the repository root, in `apps/` or further up, for example in your home directory. Remove or rename it: Wrangler run in an app directory without `--config` would use it |
| `… an app has one Wrangler config` | The app has more than one of `wrangler.json`, `wrangler.jsonc` and `wrangler.toml`. Keep only `wrangler.jsonc` |
| `named environments (env) are not supported` | Remove the `env` block. The script checks and deploys only the top-level configuration |
| `secrets.required names CLOUDFLARE_…` | Remove the name. The deploy token and the other `CLOUDFLARE_` and `CF_` variables never become Worker secrets |
| `D1 binding … has database_id …, which is …, not …` | The `database_id` belongs to another database than `database_name`. Correct it, or remove `database_id`: the script finds databases by name |
| `D1 database … is also bound by …` | Two Workers bind one database, by name or by ID. Each database belongs to one Worker (D-08); the vault only to `virga-broker` |
| `… not found; run pnpm install first`, `… is not the wrangler package` or `the wrangler bin file is missing or outside the package` | The app has no Wrangler installed, or `apps/<app>/node_modules/wrangler` is something else. Run `node scripts/check-release-age.ts`, then `pnpm install --frozen-lockfile` at the repository root |
| `apps/<app> holds symlinks outside node_modules: …` | Replace each link with the file or directory itself. Wrangler and Vite read what a link points to, also from outside the repository, into the bundle, the migrations and the assets. Before the builds, the link is in your checkout; after them, a build created it |
| `…/spa/public/…: the public directory holds a symlink, and Vite would copy what it points to into the assets` (from the build of `apps/web`) | Replace the link with the file. Vite copies the file a link points to into the published assets |
| `the Wrangler of …/apps/<app> changed after the deploy recorded it before the builds: …` | A file of Wrangler, of a package it loads, or a `wrangler` shim in `node_modules/.bin` was added, removed or changed, or a package appeared where Wrangler would load it; the message names the paths. Unless you changed them yourself, treat the checkout as compromised: find what wrote them, starting with the `build` scripts and their dependencies, and deploy from a fresh clone after `node scripts/check-release-age.ts` and `pnpm install --frozen-lockfile`. Do not run `npx wrangler` in that checkout with a token |
| `…/wrangler.jsonc changed after the deploy checked it; refusing to pass it to Wrangler` | The config changed between the check and a Wrangler call, for example from your editor or a process a build left running. Find what changed it, then run the deploy again; it checks the new bytes |
| `apps/<app>: its Wrangler config was removed during the builds` | A build deleted the config. Restore it from git and find out why |
| `apps/<app>/.corepack.env: corepack would load it …` | Remove the file. Corepack loads it into the environment of pnpm commands in that directory, where it can allow a pnpm from any URL or another registry. Settings for corepack belong in your own environment. Before the builds, the file is in your checkout; after them, a build created it |
| `apps/<app>/package.json names packageManager; corepack would run pnpm commands in apps/<app> with that package manager …` (or `devEngines.packageManager`) | Remove the field. Only the root `package.json` names the package manager, and the release-age check dates only that pin. Before the builds, the field is in your checkout; after them, a build added it |
| `apps/<app>/package.json cannot be read: …` | The file is not JSON. Restore it from git |
| `packages/rules/src/rules.gen.ts is not what the rule compiler makes of rules/ …` (or `fixtures.gen.ts`) | Run `pnpm rules:build` and review the diff in `packages/rules/src/*.gen.ts` before you commit it: a change there that no change in `rules/` explains, such as a statement after a rule's SQL, was made by hand or by a tool. If `git status` shows a change there that you did not make, a build or another process wrote it: treat the checkout as compromised |
| `the rules in rules/ fail the rule compiler …` | A rule or fixture fails. `pnpm rules:check` shows the same errors; fix the rule or fixture, run `pnpm rules:build` and commit both |
| `…/packages/rules/src/rules.gen.ts changed after the deploy checked it; refusing to run Wrangler` (or `fixtures.gen.ts`) | A generated rule module changed between the check in step 6 and a Wrangler call, for example from a process a build left running. Find what changed it, then run the deploy again |
| `store_id is a placeholder` | Set `store_id` in `apps/broker/wrangler.jsonc`, or use the `MASTER_KEY` fallback. A dry run only reports it |
| `Secrets Store … has no secret virga-master-key` or `has no MASTER_KEY secret` | Create the key as in [Master key](#master-key), then run the deploy again |
| `secret virga-master-key lacks the workers scope` | Add the `workers` scope to the secret in the Secrets Store dashboard |
| `failed to fetch secrets store binding due to authorization error - check deploy permissions and secret scopes` | The deploy token lacks Account Secrets Store Edit, or the secret lacks the `workers` scope |
| `More than one account available but unable to select one in non-interactive mode` | Set `CLOUDFLARE_ACCOUNT_ID` |
| `Authentication error [code: 10000]` or a 403 from Wrangler | The deploy token lacks a group from [the table](#the-deploy-token), has expired, or belongs to another account. Creating a Worker for the first time needs Workers Admin |
| `Couldn't find a D1 DB named …` | A database was deleted after the list. Run the deploy again; it creates it |
| A migration fails | D1 rolls back the failed migration; earlier ones stay applied. Fix the cause and run the deploy again |
| `virga-web does not exist yet and requires the secrets …` or `virga-web requires the secrets …` | `apps/web` lists them under `secrets.required`. Set `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` and `ADMIN_EMAILS` as environment variables of the deploy; create any other name with the `npx wrangler secret put` command the message prints |
| The dry run of `virga-web` fails on missing assets | The app's `build` script did not produce them. Run `pnpm --dir apps/web run build` at the repository root to see why |
| `building virga-web failed` | The build runs before any config is read or anything remote changes. Run `pnpm --dir apps/web run build` at the repository root to see the error |
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
| `tunnels` is `partial` with every chunk done and the detail `truncated (…)` | A remotely managed tunnel's ingress yields more than 1,000 entry points, or more than 1 MiB of their props: rules without a hostname are expanded per hostname ([decision 0005](../decisions/0005-truncated-collection-coverage.md)). CF-004, CF-010 and CF-011 stay `not evaluated`, and the tunnels' earlier entry points and findings are kept, until the ingress fits. Reduce the rules without a hostname, or split the tunnel |
| Scans pause and continue later | The rate budget: 1,200 REST requests per 5 minutes per token, shared with everything else that uses the same token. The broker keeps a margin and waits instead of risking the 5-minute block |
| A scan stays `running` | A scan running longer than 12 hours counts as hung and is replaced by the next one (decision 0002) |
| Nothing is scanned | The account is `paused`, or the token was removed. Check the index row and onboard again |
