import { describe, expect, it } from "vitest";
import { masterKeySetup, parseSecretTable } from "../lib/master-key.ts";
import { worker } from "./helpers.ts";

const store = (storeId: string) =>
  worker("broker", {
    secretsStore: [{ binding: "MASTER_KEY_STORE", storeId, secretName: "virga-master-key" }],
  });

describe("masterKeySetup", () => {
  it("uses Secrets Store when the binding exists", () => {
    expect(masterKeySetup(store("023e105f4ecef8ad9ca31a8372d0c353"))).toEqual({
      mode: "secrets_store",
      storeId: "023e105f4ecef8ad9ca31a8372d0c353",
      secretName: "virga-master-key",
      placeholder: false,
      unusualId: false,
    });
  });

  it("recognizes the repository's placeholder and unusual IDs", () => {
    expect(masterKeySetup(store("<SECRETS_STORE_ID>"))).toMatchObject({
      placeholder: true,
      unusualId: false,
    });
    expect(masterKeySetup(store("my-store"))).toMatchObject({
      placeholder: false,
      unusualId: true,
    });
  });

  it("falls back to the MASTER_KEY secret without the binding", () => {
    expect(masterKeySetup(worker("broker"))).toEqual({ mode: "worker_secret" });
    const other = worker("broker", {
      secretsStore: [{ binding: "OTHER", storeId: "x", secretName: "y" }],
    });
    expect(masterKeySetup(other)).toEqual({ mode: "worker_secret" });
  });
});

describe("parseSecretTable", () => {
  const esc = String.fromCharCode(27);
  const table = [
    "🔐 Listing secrets... (store-id: 023e105f4ecef8ad9ca31a8372d0c353, page: 1, per-page: 100)",
    "┌──────────────────┬──────────────────────────────────┬─────────┬──────────────────────┬─────────┬─────────┬──────────┐",
    `│ ${esc}[34mName${esc}[39m             │ ID                               │ Comment │ Scopes               │ Status  │ Created │ Modified │`,
    "├──────────────────┼──────────────────────────────────┼─────────┼──────────────────────┼─────────┼─────────┼──────────┤",
    "│ virga-master-key │ 13bc7498c6374a4e9d13be091c3c65f1 │         │ workers              │ active  │ 1/1/2026│ 1/1/2026 │",
    "├──────────────────┼──────────────────────────────────┼─────────┼──────────────────────┼─────────┼─────────┼──────────┤",
    "│ other            │ 23bc7498c6374a4e9d13be091c3c65f1 │ x       │ workers, ai_gateway  │ pending │ 1/1/2026│ 1/1/2026 │",
    "└──────────────────┴──────────────────────────────────┴─────────┴──────────────────────┴─────────┴─────────┴──────────┘",
  ].join("\n");

  it("reads names, scopes and status by column name", () => {
    expect(parseSecretTable(table)).toEqual([
      { name: "virga-master-key", scopes: ["workers"], status: "active" },
      { name: "other", scopes: ["workers", "ai_gateway"], status: "pending" },
    ]);
  });

  it("returns nothing without a table", () => {
    expect(parseSecretTable("List request returned no secrets.")).toEqual([]);
  });
});
