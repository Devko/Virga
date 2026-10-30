// The only code that the Workers of the Virga test range run (infra/test-range).
// Every request gets the same fixed text, and no handler reads a binding, so a
// public entry point of the range exposes nothing.

const BODY = "Virga test range: dummy content. Nothing here is real.\n";

export default {
  fetch() {
    return new Response(BODY, {
      headers: {
        "cache-control": "no-store",
        "content-type": "text/plain; charset=utf-8",
        "x-robots-tag": "noindex",
      },
    });
  },

  // Target of the CF-009 cron trigger. A run counts as an invocation and does nothing.
  scheduled() {
    // Nothing to do.
  },
};
