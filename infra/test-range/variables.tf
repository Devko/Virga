# Set these in terraform.tfvars (git-ignored) or as TF_VAR_<name> in the
# environment. No real ID belongs in a committed file.

variable "account_id" {
  description = "ID of the dedicated test account. Never a production account, and never an account the Virga operator uses for anything else."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "account_id must be a 32-character hex account ID."
  }
}

variable "dedicated_test_account" {
  description = "Set to true to confirm that account_id is a dedicated test account that holds nothing but this range (README.md)."
  type        = bool

  validation {
    condition     = var.dedicated_test_account
    error_message = "Apply the test range only in a dedicated test account. Read README.md first."
  }
}

variable "zone_id" {
  description = "ID of a zone in the test account that is used for nothing but this range."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "zone_id must be a 32-character hex zone ID."
  }
}

variable "zone_name" {
  description = "Name of that zone, in lower case, for example range.example.org."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.zone_name))
    error_message = "zone_name must be a lower-case DNS name."
  }
}

variable "name_prefix" {
  description = "Prefix of every name in the range (Workers, Pages projects, buckets, hostnames, tokens)."
  type        = string
  default     = "vtr"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{0,9}$", var.name_prefix))
    error_message = "name_prefix must be 1 to 10 lower-case letters or digits, starting with a letter."
  }
}

variable "access_allowed_email" {
  description = "The one address that the Allow policies of protected entry points admit. The default is at example.com, which receives no mail, so nobody can sign in, not even with a One-time PIN."
  type        = string
  default     = "nobody@example.com"

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+$", var.access_allowed_email))
    error_message = "access_allowed_email must be one email address."
  }
}
