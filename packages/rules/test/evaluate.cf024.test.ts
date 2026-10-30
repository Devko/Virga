import {
  applyBatch,
  beginScan,
  type CoverageStatus,
  migrate,
  type NodeInput,
  prepareBatch,
  recordCoverage,
  sweep,
} from "@virga/graph";
import { type NodeSqlRunner, openNodeDatabase } from "@virga/graph/node";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluateRules } from "../src/evaluate.ts";
import { RULES } from "../src/index.ts";

const CF024 = RULES.find((rule) => rule.id === "CF-024");
if (!CF024) throw new Error("missing rule CF-024");

const WORKER = "CF-024:worker_script:mailer";
const PAGES = "CF-024:pages_project:shop";
const flagged = { looks_secret: true, secret_pattern: "cfat_" };
const clean = { looks_secret: false, secret_pattern: null };

let db: NodeSqlRunner;
beforeEach(() => {
  db = openNodeDatabase();
  migrate(db);
});
afterEach(() => db.close());

async function write(scanId: string, resourceClass: string, nodes: NodeInput[], at: number) {
  const edges =
    resourceClass === "workers"
      ? [{ type: "DEPLOYS" as const, src: "worker_script:mailer", dst: "worker_version:v1" }]
      : [];
  applyBatch(db, await prepareBatch({ scanId, resourceClass, nodes, edges }, at));
}

/** One scan: the Worker and the project hold one variable each, with the given verdicts. */
async function scan(
  id: string,
  at: number,
  vars: { worker: object; pages: object },
  pages: CoverageStatus = "complete",
): Promise<void> {
  beginScan(db, { id, kind: "full", at });
  await write(
    id,
    "workers",
    [
      { type: "worker_script", nativeId: "mailer", name: "mailer" },
      {
        type: "worker_version",
        nativeId: "v1",
        props: {
          script_node_id: "worker_script:mailer",
          plain_text_vars: [{ name: "API_TOKEN", kind: "plain_text", ...vars.worker }],
          secret_names: [],
        },
      },
    ],
    at,
  );
  recordCoverage(db, { scanId: id, resourceClass: "workers", status: "complete" });
  if (pages === "complete") {
    await write(
      id,
      "pages",
      [
        {
          type: "pages_project",
          nativeId: "shop",
          name: "shop",
          props: {
            production_branch: "main",
            subdomain: "shop.pages.dev",
            preview_deployments: "all",
            plain_text_vars: [
              { name: "STRIPE_KEY", environment: "production", kind: "plain_text", ...vars.pages },
            ],
          },
        },
      ],
      at,
    );
  }
  recordCoverage(db, { scanId: id, resourceClass: "pages", status: pages });
  for (const cls of ["workers", "pages"]) sweep(db, id, cls, at);
}

const status = (fingerprint: string) =>
  db.query<{ status: string; last_seen: number }>(
    "SELECT status, last_seen FROM findings WHERE fingerprint = ?",
    fingerprint,
  )[0];

describe("CF-024 through the findings lifecycle", () => {
  it("keeps Worker and Pages findings apart", async () => {
    await scan("s1", 1000, { worker: flagged, pages: flagged });
    expect(evaluateRules(db, [CF024], "s1", 1000)[0]).toMatchObject({ hits: 2, opened: 2 });

    // The project moves its key to a secret env var; the Worker does not.
    await scan("s2", 2000, { worker: flagged, pages: clean });
    expect(evaluateRules(db, [CF024], "s2", 2000)[0]).toMatchObject({ hits: 1, resolved: 1 });
    expect(status(PAGES)).toEqual({ status: "resolved", last_seen: 1000 });
    expect(status(WORKER)).toEqual({ status: "open", last_seen: 2000 });
  });

  it("is not evaluated without complete pages coverage, and changes no Worker finding", async () => {
    await scan("s1", 1000, { worker: flagged, pages: flagged });
    evaluateRules(db, [CF024], "s1", 1000);

    // The Worker is fixed, but Pages could not be read in this scan.
    await scan("s2", 2000, { worker: clean, pages: clean }, "no_permission");
    expect(evaluateRules(db, [CF024], "s2", 2000)[0]).toMatchObject({
      status: "not_evaluated",
      missing: ["pages"],
      resolved: 0,
    });
    expect(status(WORKER)).toEqual({ status: "open", last_seen: 1000 });
    expect(status(PAGES)).toEqual({ status: "open", last_seen: 1000 });

    await scan("s3", 3000, { worker: clean, pages: flagged });
    expect(evaluateRules(db, [CF024], "s3", 3000)[0]).toMatchObject({ hits: 1, resolved: 1 });
    expect(status(WORKER)?.status).toBe("resolved");
    expect(status(PAGES)).toEqual({ status: "open", last_seen: 3000 });
  });

  it("keeps a finding whose value can no longer be inspected", async () => {
    await scan("s1", 1000, { worker: flagged, pages: flagged });
    evaluateRules(db, [CF024], "s1", 1000);
    const unknown = { looks_secret: null, secret_pattern: null };
    await scan("s2", 2000, { worker: unknown, pages: unknown });
    expect(evaluateRules(db, [CF024], "s2", 2000)[0]).toMatchObject({
      status: "evaluated",
      hits: 0,
      undecided: 2,
      resolved: 0,
    });
    expect(status(WORKER)).toEqual({ status: "open", last_seen: 1000 });
    expect(status(PAGES)).toEqual({ status: "open", last_seen: 1000 });
  });
});
