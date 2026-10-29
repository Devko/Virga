export { AccountGraph } from "./account-graph.ts";

export default {
  // No routes: the core Worker is reached only through service bindings.
  async fetch(): Promise<Response> {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
