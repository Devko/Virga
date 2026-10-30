# CF-022: Pages project with public preview deployments and bindings to
# production.
#
# Seeded (cf022-seeded): a direct-upload Pages project whose preview and
# production environments bind the same D1 database. Preview deployments are
# on by default for a project without a Git source, and no Access app covers
# `*.<project>.pages.dev`, so the preview wildcard is public.
#
# Clean (cf022-clean): the same project with a separate D1 database for
# previews, the second fix in rules/CF-022/fix/.
#
# Safety: nothing is deployed to either project, so every pages.dev URL
# serves no content at all; the databases stay empty.

resource "cloudflare_d1_database" "cf022_shared" {
  account_id = local.account_id
  name       = "${local.p}-cf022-shared"
}

resource "cloudflare_pages_project" "cf022_seeded" {
  account_id        = local.account_id
  name              = "${local.p}-cf022-seeded"
  production_branch = "main"

  deployment_configs = {
    preview = {
      # The misconfiguration: previews reach the production database.
      d1_databases = { DB = { id = cloudflare_d1_database.cf022_shared.id } }
      env_vars     = local.pages_env_placeholder
    }
    production = {
      d1_databases = { DB = { id = cloudflare_d1_database.cf022_shared.id } }
      env_vars     = local.pages_env_placeholder
    }
  }
}

resource "cloudflare_d1_database" "cf022_clean_production" {
  account_id = local.account_id
  name       = "${local.p}-cf022-clean-production"
}

resource "cloudflare_d1_database" "cf022_clean_preview" {
  account_id = local.account_id
  name       = "${local.p}-cf022-clean-preview"
}

resource "cloudflare_pages_project" "cf022_clean" {
  account_id        = local.account_id
  name              = "${local.p}-cf022-clean"
  production_branch = "main"

  deployment_configs = {
    preview = {
      d1_databases = { DB = { id = cloudflare_d1_database.cf022_clean_preview.id } }
      env_vars     = local.pages_env_placeholder
    }
    production = {
      d1_databases = { DB = { id = cloudflare_d1_database.cf022_clean_production.id } }
      env_vars     = local.pages_env_placeholder
    }
  }
}
