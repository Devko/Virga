import createDebug from "debug";

const log = createDebug("spike");

export default {
  async fetch(): Promise<Response> {
    log("request");
    return new Response("spike s04");
  },
};
