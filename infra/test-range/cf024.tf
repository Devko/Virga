# CF-024: secret in a plain-text variable instead of a secret binding.
#
# The rule covers Workers and Pages (decision 0004), so it has two seeded
# cases and two clean ones:
#
# - cf024-worker-seeded: a Worker with a token-shaped value in a plain_text
#   binding, next to a harmless one (LOG_LEVEL).
# - cf024-worker-clean: the same Worker with that value in a secret_text
#   binding, the fix in rules/CF-024/fix/. LOG_LEVEL stays plain text.
# - cf024-pages-seeded: a Pages project with a token-shaped value in a
#   plain_text variable of its production environment, next to harmless
#   ones (SITE_NAME).
# - cf024-pages-clean: the same project with that value as secret_text.
#
# The Pages cases depend on spike S-05: whether an inventory token with Pages
# Metadata Read gets the values of plain-text variables. Without values the
# collector cannot judge them, and both Pages cases are undecided
# (cases.yaml).
#
# The values are synthetic. They have the shape of an account API token
# (`cfat_` and at least 40 characters), so the collector's pattern matches,
# but Cloudflare never issued them; they are the fakes of the repository's
# fixtures (FAKE_TOKEN in packages/collectors/test/platform/fixtures/workers.ts
# and PAGES_TOKEN in apps/core/test/e2e/account.ts). Like there, they are
# assembled from parts so that secret scanners do not flag this file. The
# Workers have no entry point, and the Pages projects have no deployment.

locals {
  cf024_fake_worker_token = join("", ["cfat", "_", "Q7v2Lm9XkT4pR8sWc1Ny6Hb3Jd5Fg0Za2Ue7Io4P", "a1B2c"])
  cf024_fake_pages_token  = join("", ["cfat", "_", "Hk3Zr8Wq1Lm6Tp9Xc2Vb5Nd7Fs0Gj4Ya8Re1Ui6O", "x9Y8z"])

  # A harmless plain-text value, shorter than anything the collector's
  # high-entropy check looks at (32 characters).
  cf024_site_name = { type = "plain_text", value = "virga-test-range" }
}

# Workers --------------------------------------------------------------------

resource "cloudflare_workers_script" "cf024_worker_seeded" {
  account_id         = var.account_id
  script_name        = "${local.p}-cf024-worker-seeded"
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
  bindings = [
    # The misconfiguration: a token-shaped value in plain text.
    { type = "plain_text", name = "CF_API_TOKEN", text = local.cf024_fake_worker_token },
    { type = "plain_text", name = "LOG_LEVEL", text = "info" },
  ]
}

resource "cloudflare_workers_script_subdomain" "cf024_worker_seeded" {
  account_id       = var.account_id
  script_name      = cloudflare_workers_script.cf024_worker_seeded.script_name
  enabled          = false
  previews_enabled = false
}

resource "cloudflare_workers_script" "cf024_worker_clean" {
  account_id         = var.account_id
  script_name        = "${local.p}-cf024-worker-clean"
  content            = local.dummy_worker
  main_module        = local.dummy_module
  compatibility_date = local.compatibility_date
  bindings = [
    { type = "secret_text", name = "CF_API_TOKEN", text = local.cf024_fake_worker_token },
    { type = "plain_text", name = "LOG_LEVEL", text = "info" },
  ]
}

resource "cloudflare_workers_script_subdomain" "cf024_worker_clean" {
  account_id       = var.account_id
  script_name      = cloudflare_workers_script.cf024_worker_clean.script_name
  enabled          = false
  previews_enabled = false
}

# Pages ----------------------------------------------------------------------

resource "cloudflare_pages_project" "cf024_pages_seeded" {
  account_id        = var.account_id
  name              = "${local.p}-cf024-pages-seeded"
  production_branch = "main"

  deployment_configs = {
    preview = {
      env_vars = { SITE_NAME = local.cf024_site_name }
    }
    production = {
      env_vars = {
        # The misconfiguration: a token-shaped value in plain text.
        CF_API_TOKEN = { type = "plain_text", value = local.cf024_fake_pages_token }
        SITE_NAME    = local.cf024_site_name
      }
    }
  }
}

resource "cloudflare_pages_project" "cf024_pages_clean" {
  account_id        = var.account_id
  name              = "${local.p}-cf024-pages-clean"
  production_branch = "main"

  deployment_configs = {
    preview = {
      env_vars = { SITE_NAME = local.cf024_site_name }
    }
    production = {
      env_vars = {
        CF_API_TOKEN = { type = "secret_text", value = local.cf024_fake_pages_token }
        SITE_NAME    = local.cf024_site_name
      }
    }
  }
}
