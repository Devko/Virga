declare namespace Cloudflare {
  interface Env {
    TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
    /** The scan Workflow with stub collectors (test/worker.ts). */
    TEST_SCAN_WORKFLOW: Workflow<{ accountId: string }>;
  }
}
