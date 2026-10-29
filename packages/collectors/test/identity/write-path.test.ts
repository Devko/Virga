import {
  applyBatch,
  beginScan,
  migrate,
  prepareBatch,
  recordCoverage,
  replaceInsights,
  setSignals,
  sweep,
} from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { describe, expect, it } from "vitest";
import { IDENTITY_COLLECTORS } from "../../src/identity/index.ts";
import type { Collector } from "../../src/types.ts";
import {
  accessRoutes,
  insightsRoutes,
  membersRoutes,
  tokensRoutes,
  trafficRoutes,
  tunnelsRoutes,
} from "./fixtures/routes.ts";
import { trafficGraphql } from "./fixtures/traffic.ts";
import { context, NOW, type Routes } from "./helpers.ts";

const ROUTES: Record<string, Routes> = {
  access: accessRoutes,
  tunnels: tunnelsRoutes,
  tokens: tokensRoutes,
  members: membersRoutes,
  insights: insightsRoutes,
  traffic: trafficRoutes,
};

// What the scan Workflow does with each chunk, against the real schema.
describe("identity output through the graph write path", () => {
  for (const collector of IDENTITY_COLLECTORS as Collector<unknown>[]) {
    const cls = collector.resourceClass;
    it(`writes ${cls} and completes the class`, async () => {
      const db = openNodeDatabase();
      migrate(db);
      beginScan(db, { id: "scan-1", kind: "fixture", at: NOW });
      const graphql = cls === "traffic" ? trafficGraphql().handler : undefined;
      const { ctx } = context(ROUTES[cls] ?? {}, graphql);
      const chunks = await collector.plan(ctx);
      let nodes = 0;
      for (const unit of chunks) {
        const out = await collector.collect(ctx, unit);
        const batch = { scanId: "scan-1", resourceClass: cls, nodes: out.nodes, edges: out.edges };
        applyBatch(db, await prepareBatch(batch, NOW));
        if (out.signals) setSignals(db, out.signals, NOW);
        if (out.insights) replaceInsights(db, out.insights, NOW);
        nodes += out.nodes.length;
      }
      recordCoverage(db, { scanId: "scan-1", resourceClass: cls, status: "complete" });
      expect(sweep(db, "scan-1", cls, NOW)).toEqual({ swept: true, nodes: 0, edges: 0 });
      const count = (sql: string) => db.query<{ n: number }>(sql)[0]?.n ?? 0;
      expect(count("SELECT count(*) AS n FROM nodes")).toBeLessThanOrEqual(nodes);
      if (cls === "insights") {
        expect(count("SELECT count(*) AS n FROM insights")).toBeGreaterThan(0);
      }
      if (cls === "traffic" || cls === "tokens") {
        expect(count("SELECT count(*) AS n FROM signals")).toBeGreaterThan(0);
      }
      db.close();
    });
  }
});
