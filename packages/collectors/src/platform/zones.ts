import type { Collector } from "../types.ts";
import { listZones } from "./lists.ts";
import { bool, GraphBuilder, str } from "./util.ts";

/** `zone` nodes. The zone list is the whole payload, so it runs as a single chunk. */
export const zonesCollector: Collector<never> = {
  resourceClass: "zones",
  permissions: ["Zone Read"],

  async plan() {
    return [[]];
  },

  async collect(ctx) {
    const g = new GraphBuilder();
    for (const zone of await listZones(ctx)) {
      const id = str(zone.id);
      if (!id) continue;
      g.node("zone", id, str(zone.name), {
        status: str(zone.status),
        paused: bool(zone.paused),
        type: str(zone.type),
        plan: str(zone.plan?.name),
      });
    }
    return g.output();
  },
};
