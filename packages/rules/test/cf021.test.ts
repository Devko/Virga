import {
  applyBatch,
  beginScan,
  type Confidence,
  type ExposureDecision,
  migrate,
  prepareBatch,
  recordCoverage,
  replaceExposure,
  sweep,
} from "@virga/graph";
import { type NodeSqlRunner, openNodeDatabase } from "@virga/graph/node";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluateRules } from "../src/evaluate.ts";
import { RULES } from "../src/index.ts";

const rule = RULES.find((r) => r.id === "CF-021");
if (!rule) throw new Error("missing rule CF-021");
const CF021 = rule;

const FINGERPRINT = "CF-021:r2_bucket:customer-exports";

interface Domain {
  host: string;
  kind: "custom" | "r2_dev";
  /** As the storage collector stores it; `undefined` leaves the prop out. */
  enabled: unknown;
  /** The exposure evaluator's row for the domain, if it has one. */
  exposure?: [ExposureDecision, Confidence];
}

let db: NodeSqlRunner;
beforeEach(() => {
  db = openNodeDatabase();
  migrate(db);
});
afterEach(() => db.close());

/** One full scan of the bucket customer-exports, then CF-021 through the findings lifecycle. */
async function scan(id: string, at: number, domains: Domain[]) {
  beginScan(db, { id, kind: "full", at });
  const batch = await prepareBatch(
    {
      scanId: id,
      resourceClass: "storage",
      nodes: [
        { type: "r2_bucket", nativeId: "customer-exports", name: "customer-exports", props: {} },
        ...domains.map((d) => ({
          type: "r2_public_domain" as const,
          nativeId: d.host,
          name: d.host,
          props: {
            bucket: "customer-exports",
            kind: d.kind,
            zone_id: null,
            ...(d.enabled === undefined ? {} : { enabled: d.enabled }),
          },
        })),
      ],
      edges: domains.map((d) => ({
        type: "ROUTES_TO" as const,
        src: `r2_public_domain:${d.host}`,
        dst: "r2_bucket:customer-exports",
        key: "",
        props: {},
      })),
    },
    at,
  );
  applyBatch(db, batch);
  for (const input of CF021.requires) {
    recordCoverage(db, { scanId: id, resourceClass: input, status: "complete" });
  }
  sweep(db, id, "storage", at);
  replaceExposure(
    db,
    domains.flatMap((d) =>
      d.exposure
        ? [
            {
              entryId: `r2_public_domain:${d.host}`,
              decision: d.exposure[0],
              confidence: d.exposure[1],
            },
          ]
        : [],
    ),
    at,
  );
  const [run] = evaluateRules(db, [CF021], id, at);
  const status = db.query<{ status: string }>(
    "SELECT status FROM findings WHERE fingerprint = ?",
    FINGERPRINT,
  )[0]?.status;
  return { run, status };
}

const files = (enabled: unknown, exposure?: Domain["exposure"]): Domain => ({
  host: "files.example.com",
  kind: "custom",
  enabled,
  exposure,
});

describe("R4-02: CF-021 does not resolve a public bucket when a domain's enabled state turns unknown", () => {
  it.each<[string, unknown]>([
    ["null", null],
    ["missing", undefined],
    ["not a boolean", "true"],
  ])(
    "R4-02: keeps the finding open when a custom domain's enabled state is %s",
    async (_, enabled) => {
      const first = await scan("s1", 1000, [files(true, ["public", 2])]);
      expect(first.run).toMatchObject({ status: "evaluated", hits: 1, opened: 1 });
      expect(first.status).toBe("open");

      // The evaluator decides a domain with an unknown enabled state `unknown`.
      const second = await scan("s2", 2000, [files(enabled, ["unknown", 0])]);
      expect(second.run).toMatchObject({ status: "evaluated", hits: 0, undecided: 1, resolved: 0 });
      expect(second.status).toBe("open");
    },
  );

  it("R4-02: keeps the finding open when the r2.dev domain's enabled state turns unknown", async () => {
    const r2dev = (enabled: unknown): Domain => ({
      host: "pub-0113a9e4549cf9b1ff1bf56e04da0cef.r2.dev",
      kind: "r2_dev",
      enabled,
      exposure: enabled === true ? ["public", 2] : ["unknown", 0],
    });
    const first = await scan("s1", 1000, [r2dev(true)]);
    expect(first.run).toMatchObject({ hits: 1, opened: 1 });

    const second = await scan("s2", 2000, [r2dev(null)]);
    expect(second.run).toMatchObject({ status: "evaluated", hits: 0, undecided: 1, resolved: 0 });
    expect(second.status).toBe("open");
  });

  it("R4-02: a domain with an unknown enabled state is undecided even where exposure says public", async () => {
    // A disabled domain serves nothing, so only an enabled one decides the bucket.
    const result = await scan("s1", 1000, [files(null, ["public", 2])]);
    expect(result.run).toMatchObject({ hits: 0, undecided: 1, opened: 0 });
  });

  it("R4-02: still resolves the finding once the domain is disabled", async () => {
    await scan("s1", 1000, [files(true, ["public", 2])]);
    const second = await scan("s2", 2000, [files(false)]);
    expect(second.run).toMatchObject({ status: "evaluated", hits: 0, undecided: 0, resolved: 1 });
    expect(second.status).toBe("resolved");
  });
});
