-- One row per scanned account. The token is encrypted with a per-token data
-- key (AES-256-GCM); the data key is wrapped with the master key of
-- key_version. Both ciphertexts bind account_id and token_id as associated
-- data, the wrapped key also binds key_version.
CREATE TABLE vault_tokens (
  account_id TEXT PRIMARY KEY,
  token_id TEXT NOT NULL,
  profile TEXT NOT NULL CHECK (profile IN ('inventory', 'workload')),
  key_version INTEGER NOT NULL,
  key_iv BLOB NOT NULL,
  wrapped_key BLOB NOT NULL,
  token_iv BLOB NOT NULL,
  token_ciphertext BLOB NOT NULL,
  expires_on TEXT,
  checked_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;
