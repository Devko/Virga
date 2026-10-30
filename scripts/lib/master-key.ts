import type { WorkerConfig } from "./config.ts";

/** Names used by apps/broker/src/master-key.ts (D-15). */
export const MASTER_KEY_BINDING = "MASTER_KEY_STORE";
export const MASTER_KEY_SECRET = "MASTER_KEY";

export type MasterKeySetup =
  | {
      mode: "secrets_store";
      storeId: string;
      secretName: string;
      /** store_id is still the placeholder from the repository. */
      placeholder: boolean;
      /** store_id is set but not 32 hex characters like the IDs in the API reference. */
      unusualId: boolean;
    }
  | { mode: "worker_secret" };

/**
 * Where the broker reads its master key: the Secrets Store binding when the
 * config has one (the default), otherwise the MASTER_KEY Worker secret.
 */
export function masterKeySetup(broker: WorkerConfig): MasterKeySetup {
  const binding = broker.secretsStore.find((b) => b.binding === MASTER_KEY_BINDING);
  if (!binding) return { mode: "worker_secret" };
  const placeholder = binding.storeId.trim() === "" || /[<>]/.test(binding.storeId);
  return {
    mode: "secrets_store",
    storeId: binding.storeId,
    secretName: binding.secretName,
    placeholder,
    unusualId: !placeholder && !/^[0-9a-f]{32}$/i.test(binding.storeId),
  };
}

export interface StoreSecret {
  name: string;
  scopes: string[];
  status: string;
}

const ANSI = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g");

/**
 * Rows of the table that `wrangler secrets-store secret list` prints (it has
 * no JSON output). Columns are found by their header names.
 */
export function parseSecretTable(output: string): StoreSecret[] {
  const rows = output
    .replace(ANSI, "")
    .split("\n")
    .filter((line) => /^\s*[│|]/.test(line))
    .map((line) =>
      line
        .trim()
        .split(/[│|]/)
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
  const headerIndex = rows.findIndex((cells) => cells.includes("Name") && cells.includes("Status"));
  const header = rows[headerIndex];
  if (!header) return [];
  const col = (name: string) => header.indexOf(name);
  const [name, scopes, status] = [col("Name"), col("Scopes"), col("Status")];
  return rows.slice(headerIndex + 1).flatMap((cells) => {
    const secretName = cells[name];
    if (!secretName) return [];
    return [
      {
        name: secretName,
        scopes: (cells[scopes] ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        status: cells[status] ?? "",
      },
    ];
  });
}
