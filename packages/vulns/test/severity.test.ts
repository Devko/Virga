import { describe, expect, it } from "vitest";
import { cvss3BaseScore, rankOfScore, roundUp30, roundUp31 } from "../src/cvss.ts";
import type { OsvSeverity } from "../src/osv.ts";
import { severityRank } from "../src/severity.ts";

const BASE = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

describe("cvss3BaseScore", () => {
  it.each([
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0],
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0],
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1],
    ["CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5],
    ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2],
    ["CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0],
    ["CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8],
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9],
    ["CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3],
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3],
    ["CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N", 0.0],
    ["CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5],
    ["CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
    // temporal and environmental metrics are valid but do not change the base score
    [`CVSS:3.1/${BASE}/E:P/RL:O/RC:C`, 9.8],
    [
      `CVSS:3.1/${BASE}/E:X/RL:X/RC:X/CR:H/IR:M/AR:L/MAV:A/MAC:H/MPR:L/MUI:R/MS:C/MC:N/MI:L/MA:H`,
      9.8,
    ],
    // any order
    ["CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N", 9.8],
  ])("scores %s as %s", (vector, score) => {
    expect(cvss3BaseScore(vector)).toBe(score);
  });

  it.each([
    ["no prefix", BASE],
    ["lowercase prefix", `cvss:3.1/${BASE}`],
    ["version 3.2", `CVSS:3.2/${BASE}`],
    ["version 4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"],
    ["version 2", "AV:N/AC:L/Au:N/C:P/I:P/A:P"],
    ["a missing base metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"],
    ["a repeated metric", `CVSS:3.1/${BASE}/AV:N`],
    ["an unknown metric", `CVSS:3.1/${BASE}/XX:Y`],
    ["an invalid base value", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["an invalid temporal value", `CVSS:3.1/${BASE}/E:Z`],
    ["a trailing slash", `CVSS:3.1/${BASE}/`],
    ["an empty metric", `CVSS:3.1/AV:N//AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`],
    ["a metric without value", `CVSS:3.1/${BASE}/E`],
    ["whitespace", ` CVSS:3.1/${BASE}`],
    ["a lowercase value", "CVSS:3.1/AV:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["a prototype key as metric", `CVSS:3.1/${BASE}/constructor:X`],
    ["empty", ""],
  ])("rejects %s", (_, vector) => {
    expect(cvss3BaseScore(vector)).toBeNull();
  });

  it("rounds up as each version defines it", () => {
    expect(roundUp31(4.000000000000001)).toBe(4.0);
    expect(roundUp30(4.000000000000001)).toBe(4.1);
    expect(roundUp31(4.02)).toBe(4.1);
    expect(roundUp30(4.02)).toBe(4.1);
    expect(roundUp31(4.0)).toBe(4.0);
  });
});

describe("rankOfScore", () => {
  it.each([
    [0, 0],
    [0.1, 1],
    [3.9, 1],
    [4.0, 2],
    [6.9, 2],
    [7.0, 3],
    [8.9, 3],
    [9.0, 4],
    [10, 4],
  ])("maps %s to %s", (score, rank) => {
    expect(rankOfScore(score)).toBe(rank);
  });
});

describe("severityRank", () => {
  const v3 = (score: string): OsvSeverity => ({ type: "CVSS_V3", score });
  const critical = v3(`CVSS:3.1/${BASE}`);
  const high = v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  const none = v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
  const broken = v3("CVSS:3.1/AV:N");
  const v4: OsvSeverity = {
    type: "CVSS_V4",
    score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  };
  const v2: OsvSeverity = { type: "CVSS_V2", score: "AV:N/AC:L/Au:N/C:P/I:P/A:P" };
  const ubuntu: OsvSeverity = { type: "Ubuntu", score: "high" };

  it.each<[string, OsvSeverity[], string | null, number | null]>([
    ["a v3 vector", [critical], null, 4],
    ["a v3 vector over the database severity", [high], "CRITICAL", 3],
    ["a v3 score of 0", [none], "HIGH", 0],
    ["the highest of several v3 vectors", [high, critical], null, 4],
    ["v3 next to v4", [v4, high], null, 3],
    ["GHSA LOW without v3", [], "LOW", 1],
    ["GHSA MODERATE without v3", [v4], "MODERATE", 2],
    ["GHSA HIGH without v3", [v2], "HIGH", 3],
    ["GHSA CRITICAL without v3", [ubuntu], "CRITICAL", 4],
    ["only a v4 vector", [v4], null, null],
    ["only a v2 vector", [v2], null, null],
    ["nothing", [], null, null],
    ["an unknown database severity", [v4], "SEVERE", null],
    ["a lowercase database severity", [], "high", null],
    ["a broken v3 vector, even with a database severity", [broken], "HIGH", null],
    ["a broken v3 vector next to a lower one", [high, broken], null, null],
    ["a broken v3 vector next to a critical one", [broken, critical], null, 4],
  ])("ranks %s", (_, severity, database, rank) => {
    expect(severityRank(severity, database)).toBe(rank);
  });
});
