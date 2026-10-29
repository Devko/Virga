import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      // The Worker plus test-only exports: a fixture broker and a scan
      // Workflow with stub collectors (test/worker.ts).
      main: "./test/worker.ts",
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          TEST_MIGRATIONS: await readD1Migrations(path.join(import.meta.dirname, "migrations")),
        },
        // The broker is another Worker; in tests its ApiCaller answers from fixtures.
        serviceBindings: { BROKER: { name: "virga-core", entrypoint: "FixtureBroker" } },
        workflows: {
          TEST_SCAN_WORKFLOW: { name: "virga-test-scan", className: "TestScanWorkflow" },
        },
      },
    })),
  ],
  test: {
    setupFiles: ["./test/setup.ts"],
  },
});
