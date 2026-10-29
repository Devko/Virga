export { ApiCaller } from "./api-caller.ts";
export { RateBudget } from "./rate-budget.ts";
export { TokenIntake } from "./token-intake.ts";

export default {
  // No routes: the broker is reached only through service bindings.
  async fetch(): Promise<Response> {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
