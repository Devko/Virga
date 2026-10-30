terraform {
  required_version = ">= 1.5.0"

  required_providers {
    cloudflare = {
      source = "cloudflare/cloudflare"
      # Exactly this version. 5.28.0 was released on 2026-10-12, more than 14
      # days before the range was written (2026-10-30). Every resource and
      # attribute here was checked against the docs of this version only.
      version = "5.28.0"
    }
  }
}

# The API token comes from the environment (CLOUDFLARE_API_TOKEN), never from
# a file. README.md lists the permissions it needs.
provider "cloudflare" {}
