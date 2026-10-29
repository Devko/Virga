export { AccountGraph } from "./account-graph.ts";
export { Admin } from "./admin.ts";
export { GraphReader } from "./graph-reader.ts";
export { DispatchWorkflow, ScanWorkflow } from "./scan/workflows.ts";

export default {
  // No routes: the core Worker is reached only through service bindings.
  async fetch(): Promise<Response> {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
