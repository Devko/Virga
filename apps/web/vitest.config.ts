import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { TEST_ACCESS } from "./test/config.ts";

export default defineConfig({
  test: {
    projects: [
      {
        // The Worker in workerd, plus stub entrypoints for core and the broker (test/worker.ts).
        plugins: [
          cloudflareTest({
            main: "./test/worker.ts",
            wrangler: { configPath: "./wrangler.jsonc" },
            miniflare: {
              bindings: { ...TEST_ACCESS },
              serviceBindings: {
                CORE_READ: { name: "virga-web", entrypoint: "StubGraphReader" },
                CORE_ADMIN: { name: "virga-web", entrypoint: "StubAdmin" },
                BROKER_INTAKE: { name: "virga-web", entrypoint: "StubTokenIntake" },
              },
            },
          }),
        ],
        test: { name: "worker", include: ["test/**/*.test.ts"] },
      },
      {
        // SPA views rendered to HTML in Node.
        oxc: { jsx: { runtime: "automatic", importSource: "react" } },
        test: { name: "spa", include: ["spa/**/*.test.tsx"], environment: "node" },
      },
    ],
  },
});
