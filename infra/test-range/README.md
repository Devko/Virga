# Test range

Terraform for the seeded test account ("test range" in the [implementation plan](../../docs/implementation-plan.md#approach)). It creates one deliberate misconfiguration per phase 1 rule and a clean counterpart next to each, so that phase 1 gate 3 can check that every rule hits its seeded case and stays quiet on the clean one. [`cases.yaml`](cases.yaml) lists the cases and the expected results. The range is written ahead of the phase 1 gate and applied once the test account exists ([decision 0007](../../docs/decisions/0007-later-phases-before-the-phase-1-gate.md)).

**Not validated yet.** The files have not been run through `terraform validate`, planned or applied: no Terraform binary was available when they were written. Every resource and attribute was checked by hand against the docs of the pinned provider, `cloudflare/cloudflare` 5.28.0. Expect small fixes on the first `terraform validate` and the first apply, and record them here. Known risks:

- The API may refuse 240.0.0.0/4 in a token's IP condition, or proxied records to 203.0.113.0/24. Replace them with another range that is never routed on the internet and keeps the case's meaning: for CF-003 an entry wider than /8 (IPv4) or /32 (IPv6), such as `fc00::/7`; for CF-007 an address outside the ranges the rule leaves out.
- The Pages API does not return secret values, so plans may show a change on the `secret_text` variables every time.
- The permission group names and the token permissions below come from the docs, not from a run.

## Only in a dedicated test account

Apply the range only in a Cloudflare account that exists for it:

- never in a production account;
- never in an account the Virga operator uses for anything else: not the tool account, and not an account Virga scans for real;
- with a zone that serves nothing else, ideally a domain bought for the range.

The range creates public entry points, Access policies that admit everyone or bypass Access, a public R2 bucket and account tokens with a write permission. Each of them is harmless only because the Worker code is a dummy, the stores are empty, the origins do not exist and the tokens cannot be used ([Safety](#safety)). Next to real resources the same settings would be real findings. `dedicated_test_account = true` is required as a reminder.

## Prerequisites

Terraform cannot create these; set them up once by hand.

1. A dedicated account (see above). The gates wait for a paid account (decision 0007). R2 must be enabled for the account.
2. A zone in that account, full setup and active, with no other records.
3. The account's `workers.dev` subdomain: open **Workers & Pages** once in the dashboard. The provider has no resource for it.
4. A Zero Trust organization (team name): open **Zero Trust** once. Access applications need it.
5. Terraform 1.5 or later.

## API token for Terraform

Create a token with these permissions (dashboard names; the API calls Edit "Write"). Scope account permissions to the test account and zone permissions to the range's zone.

| Scope | Permission | For |
| --- | --- | --- |
| Account | Workers Scripts Edit | Workers, their `workers.dev` settings and cron triggers |
| Account | Workers KV Storage Edit | KV namespaces |
| Account | D1 Edit | D1 databases |
| Account | Workers R2 Storage Edit | R2 buckets, `r2.dev` and custom domains |
| Account | Cloudflare Pages Edit | Pages projects |
| Account | Access: Apps and Policies Edit | Access apps and policies |
| Account | Cloudflare Tunnel Edit | The CF-004 tunnel and its configuration |
| Account | Account API Tokens Edit | The CF-003 tokens and the permission group list |
| Zone | Zone Read, DNS Edit, Workers Routes Edit | Records and Custom Domains |

This list follows the API reference and has not been tried yet.

Use a **user** API token (**My Profile** > **API Tokens**), or an **account** API token that expires within 90 days. An account token with these permissions, no expiry and no IP condition is itself a CF-003 finding, which `cases.yaml` lists under `known_extra`.

## Apply

```sh
cd infra/test-range
cp terraform.tfvars.example terraform.tfvars   # git-ignored; or use TF_VAR_<name>
export CLOUDFLARE_API_TOKEN=...                 # never in a file
terraform init
terraform plan
terraform apply
```

After the first `terraform init`, commit `.terraform.lock.hcl` with the hashes of the platforms in use (`terraform providers lock -platform=linux_amd64 -platform=darwin_arm64 -platform=windows_amd64`).

The state holds the CF-003 token values and the synthetic CF-024 values. Both are unusable, but keep the state local and private like any Terraform state, and never commit it (`*.tfstate` is git-ignored).

## Check gate 3

1. Create a read-only inventory token for the test account and onboard the account in a Virga instance ([operator guide](../../docs/operator/guide.md)).
2. Wait for the first cron run of `cf009-live` (the next full hour). CF-009's seeded case hits only in scans that start 30 days or more after apply; CF-003's seeded hit turns critical after 90 days.
3. Run a full scan. Every class the phase 1 rules require must be `complete`; a `not_evaluated` rule fails the check.
4. Compare the rule runs with `cases.yaml`. `terraform output -json subjects` maps each case to its graph node ID; the finding is `<rule>:<subject>`.

The same scan serves gate 5 (no 429, no 5-minute block).

## Destroy

```sh
cd infra/test-range
export CLOUDFLARE_API_TOKEN=...
terraform destroy
```

Then:

1. Check in the dashboard that nothing with the name prefix (`vtr` by default) is left: Workers, Pages projects, KV namespaces, D1 databases, R2 buckets, Access apps and policies, the tunnel, account API tokens, and the records in the range's zone. Remove leftovers by hand.
2. Delete the state files.
3. Remove the account from the Virga instance and delete its inventory token.

Destroy fails if someone changed the range by hand: a tunnel with an active connector, an R2 bucket with objects, or a Pages project with deployments. Stop the connector, empty the bucket or delete the deployments, and run `terraform destroy` again.

## Safety

| Item | What it is | Why it is harmless |
| --- | --- | --- |
| CF-003 tokens | Account tokens with Workers Routes Write, no expiry | The `in` lists hold only ranges that are never routed on the internet (192.0.2.0/24, 2001:db8::/32, 240.0.0.0/4), so no request can come from an allowed address. The grant covers one zone of the test account. Values are never output |
| CF-024 values | Token-shaped plain-text and secret values | Synthetic: the fakes of the repository's fixtures, never issued by Cloudflare, assembled from parts so secret scanners skip the file |
| Every Worker | Code behind every Worker entry point | [`worker/dummy.mjs`](worker/dummy.mjs) answers with a fixed text and never reads a binding |
| CF-002 `workers.dev` URL | Public on purpose | Dummy Worker without bindings |
| CF-010 seeded Custom Domain | Access admits anyone who signs in | Dummy Worker; its namespace is empty and never read |
| CF-011 seeded host, `/assets` of the clean host | Public through Bypass | Dummy Workers; empty namespaces |
| CF-021 `r2.dev` | Public bucket | The bucket is empty; nothing writes objects |
| CF-022 and CF-024 Pages projects | Public preview and production URLs | Nothing is deployed; the D1 databases are empty |
| CF-004 tunnel hostnames | Published, the seeded one without Access | No connector runs, and the origins point to `no-origin.invalid`, which never resolves |
| CF-007 records | An unproxied record publishes an "origin" | The addresses are from 203.0.113.0/24 (RFC 5737), never routed; there is no origin |
| Protected entry points | Allow policy for one address | `nobody@example.com` by default: example.com receives no mail, so nobody can sign in |

Ordering: Access apps are created before the Custom Domains, R2 custom domain and tunnel records they protect, so no clean entry point is public during apply. A new Worker can be reachable on `workers.dev` for the moment between its upload and its subdomain setting; it serves the dummy text.

Do not upload objects, write keys or rows, deploy Pages content or start a connector in the range.

## What Terraform cannot create

| Need | How the range gets it |
| --- | --- |
| Zone, `workers.dev` subdomain, Zero Trust organization | Manual prerequisites, above |
| Traffic for CF-009 (`invocations_30d`) | An hourly cron trigger on `cf009-live`; every run is an invocation. If cron runs turn out not to count, `cases.yaml` says what to do |
| A Worker 30 days old for CF-009 | Time: the seeded case hits from day 30 after apply |
| A token unused for 90 days for CF-003 | Time: the severity turns critical after 90 days |
| CF-001 (phase 2) | Placeholder only ([`cf001.tf`](cf001.tf)): it needs the phase 2 collectors and a Wrangler deploy |

Cases left to the rule fixtures, because the range cannot hold them safely or the provider cannot set them: a token without any IP condition, Worker version and preview URLs (a version gets one only when it is uploaded with previews on), Worker-level Access and the hostname app that overrides it, and every `unknown` exposure.

## Files

| File | Content |
| --- | --- |
| `versions.tf` | Terraform and provider pins, provider block |
| `variables.tf` | Account, zone, prefix, the one allowed address |
| `main.tf` | Shared locals and the Allow policy for one address |
| `cf001.tf` to `cf024.tf` | One file per rule: seeded case, clean counterpart, why it is safe |
| `outputs.tf` | `subjects`: graph node ID per case |
| `cases.yaml` | Expected result per rule and case, for gate 3 |
| `worker/dummy.mjs` | The only Worker code in the range |

The fix templates in `rules/CF-xxx/fix/` turn each seeded case into its clean counterpart.
