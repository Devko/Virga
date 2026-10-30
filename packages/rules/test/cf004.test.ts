import { migrate } from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { describe, expect, it } from "vitest";
import { FIXTURES } from "../src/fixtures.gen.ts";
import { loadFixture, RULES, runRule } from "../src/index.ts";

/** CF-004's rows for one of its fixtures, by fingerprint. */
async function rows(name: string) {
  const rule = RULES.find((r) => r.id === "CF-004");
  const fixture = FIXTURES.find((f) => f.rule === "CF-004" && f.name === name);
  if (!rule || !fixture) throw new Error(`missing CF-004 or ${name}`);
  const db = openNodeDatabase();
  try {
    migrate(db);
    await loadFixture(db, fixture);
    return Object.fromEntries(runRule(db, rule).map((row) => [row.fingerprint, row]));
  } finally {
    db.close();
  }
}

const TUNNEL = "tunnel_hostname:7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d";

describe("CF-004 evidence", () => {
  it("R3-02: names a fall-through entry point in the evidence", async () => {
    const found = await rows("positive-fallthrough-behind-path-rule");
    expect(Object.keys(found)).toEqual([`CF-004:${TUNNEL}:app.example.com`]);
    expect(found[`CF-004:${TUNNEL}:app.example.com`]).toMatchObject({
      via_fallthrough: 1,
      public_paths: '["/"]',
    });
  });

  it("R3-02: says when a hostname rule is the entry point", async () => {
    const found = await rows("positive-rdp-on-path");
    expect(Object.values(found).map((row) => row.via_fallthrough)).toEqual([0]);
  });
});
