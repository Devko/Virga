# The graph node ID of the subject of every case in cases.yaml, keyed by the
# case. A gate 3 check reads it with `terraform output -json subjects` and
# looks up the finding `<rule>:<subject>` (graph contract, node IDs). No
# value here is secret: names, and IDs of tokens, policies and records.
output "subjects" {
  description = "Graph node ID of each case's subject, keyed by the case in cases.yaml."
  value = {
    "cf002-seeded" = "worker_script:${cloudflare_workers_script.cf002_seeded.script_name}"
    "cf002-clean"  = "worker_script:${cloudflare_workers_script.cf002_clean.script_name}"

    "cf003-seeded" = "account_token:${cloudflare_account_token.cf003_seeded.id}"
    "cf003-clean"  = "account_token:${cloudflare_account_token.cf003_clean.id}"

    # <tunnel ID>:<hostname>:<path>, with an empty path
    "cf004-seeded" = "tunnel_hostname:${cloudflare_zero_trust_tunnel_cloudflared.cf004.id}:${local.cf004_seeded_host}:"
    "cf004-clean"  = "tunnel_hostname:${cloudflare_zero_trust_tunnel_cloudflared.cf004.id}:${local.cf004_clean_host}:"

    "cf007-seeded" = "dns_record:${cloudflare_dns_record.cf007_seeded_origin.id}"
    "cf007-clean"  = "dns_record:${cloudflare_dns_record.cf007_clean_origin.id}"

    "cf009-seeded" = "worker_script:${cloudflare_workers_script.cf009_seeded.script_name}"
    "cf009-clean"  = "worker_script:${cloudflare_workers_script.cf009_clean.script_name}"
    "cf009-live"   = "worker_script:${cloudflare_workers_script.cf009_live.script_name}"

    "cf010-seeded" = "access_policy:${cloudflare_zero_trust_access_policy.cf010_seeded.id}"
    "cf010-clean"  = "access_policy:${cloudflare_zero_trust_access_policy.cf010_clean.id}"

    "cf011-seeded" = "access_policy:${cloudflare_zero_trust_access_policy.cf011_seeded.id}"
    "cf011-clean"  = "access_policy:${cloudflare_zero_trust_access_policy.cf011_clean_assets.id}"

    "cf021-seeded" = "r2_bucket:${cloudflare_r2_bucket.cf021_seeded.name}"
    "cf021-clean"  = "r2_bucket:${cloudflare_r2_bucket.cf021_clean.name}"

    "cf022-seeded" = "pages_project:${cloudflare_pages_project.cf022_seeded.name}"
    "cf022-clean"  = "pages_project:${cloudflare_pages_project.cf022_clean.name}"

    "cf024-worker-seeded" = "worker_script:${cloudflare_workers_script.cf024_worker_seeded.script_name}"
    "cf024-worker-clean"  = "worker_script:${cloudflare_workers_script.cf024_worker_clean.script_name}"
    "cf024-pages-seeded"  = "pages_project:${cloudflare_pages_project.cf024_pages_seeded.name}"
    "cf024-pages-clean"   = "pages_project:${cloudflare_pages_project.cf024_pages_clean.name}"
  }
}
