import { describe, expect, it } from "vitest";
import { readGitleaks } from "../src/gitleaks.ts";
import { MASK, maskSecret } from "../src/secrets.ts";
import { readTrivy } from "../src/trivy.ts";
import {
  CF_SECRET,
  CF_SECRET_BODY,
  gitleaksSample,
  json,
  KEY_SECRET,
  PLAIN_SECRET,
  SEEDED_BODIES,
  trivySample,
} from "./samples.ts";

/** Every six-character piece of every seeded secret body. */
const pieces = SEEDED_BODIES.flatMap((body) =>
  Array.from({ length: body.length - 5 }, (_, i) => body.slice(i, i + 6)),
);

const expectNoSecret = (text: string) => {
  for (const piece of pieces) expect(text.includes(piece), piece).toBe(false);
};

/** Everything a caller could see of a thrown value. */
const describeThrown = (error: unknown): string => {
  if (!(error instanceof Error)) return String(error);
  const own = Object.fromEntries(
    Object.getOwnPropertyNames(error).map((key) => [
      key,
      String((error as unknown as Record<string, unknown>)[key]),
    ]),
  );
  return [String(error), error.message, error.stack ?? "", JSON.stringify(own)].join("\n");
};

const thrown = (fn: () => unknown): unknown => {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("expected a rejection");
};

describe("secret masking", () => {
  it("keeps only a known prefix and a fixed mask", () => {
    expect(maskSecret(CF_SECRET)).toEqual({ prefix: "cfat_", masked: `cfat_${MASK}` });
    expect(maskSecret(PLAIN_SECRET)).toEqual({ prefix: null, masked: MASK });
    expect(maskSecret(KEY_SECRET)).toEqual({ prefix: null, masked: MASK });
    // The mask does not depend on the length of the secret.
    expect(maskSecret(`cfat_${"a".repeat(400)}`).masked).toBe(maskSecret("cfat_ab").masked);
  });

  it("the samples really carry the seeded secrets", () => {
    expect(json(gitleaksSample)).toContain(CF_SECRET_BODY);
    expect(json(trivySample)).toContain(CF_SECRET_BODY);
  });

  it("no part of a seeded secret appears in the gitleaks result", () => {
    const report = readGitleaks(json(gitleaksSample));
    expectNoSecret(JSON.stringify(report));
    expect(report.secrets.find((s) => s.prefix === "cfat_")?.masked).toBe(`cfat_${MASK}`);
  });

  it("no part of a seeded secret appears in the Trivy result", () => {
    expectNoSecret(JSON.stringify(readTrivy(json(trivySample))));
  });

  const broken: [string, () => unknown][] = [
    [
      "a secret of the wrong type next to a seeded one",
      () => {
        const findings = structuredClone(gitleaksSample) as Record<string, unknown>[];
        Object.assign(findings[1] ?? {}, { Secret: 1 });
        return readGitleaks(json(findings));
      },
    ],
    [
      "a report cut off inside the secret",
      () => {
        const text = json(gitleaksSample);
        return readGitleaks(text.slice(0, text.indexOf(CF_SECRET_BODY) + 20));
      },
    ],
    [
      "a control character right after the secret",
      () => {
        const text = json(gitleaksSample).replace(CF_SECRET_BODY, `${CF_SECRET_BODY}\u0001`);
        return readGitleaks(text);
      },
    ],
    [
      "a duplicate Secret key",
      () => {
        const text = json(gitleaksSample).replace('"Secret":', `"Secret":"${CF_SECRET}","Secret":`);
        return readGitleaks(text);
      },
    ],
    [
      "a secret longer than the string limit",
      () => {
        return readGitleaks(json(gitleaksSample), { limits: { maxStringLength: 30 } });
      },
    ],
    [
      "a report over the size limit",
      () => {
        return readGitleaks(json(gitleaksSample), { limits: { maxBytes: 100 } });
      },
    ],
    [
      "the secret copied into the file name",
      () => {
        const findings = structuredClone(gitleaksSample) as Record<string, unknown>[];
        Object.assign(findings[0] ?? {}, { File: CF_SECRET });
        return readGitleaks(json(findings));
      },
    ],
    [
      "the secret copied into the rule ID",
      () => {
        const findings = structuredClone(gitleaksSample) as Record<string, unknown>[];
        Object.assign(findings[0] ?? {}, { RuleID: CF_SECRET_BODY });
        return readGitleaks(json(findings));
      },
    ],
    [
      "a Trivy report with a broken secret entry",
      () => {
        const sample = structuredClone(trivySample);
        const secret = sample.Results[2]?.Secrets?.[0] as Record<string, unknown> | undefined;
        if (secret) secret.StartLine = "3";
        return readTrivy(json(sample));
      },
    ],
    [
      "the secret as a Trivy rule ID",
      () => {
        const sample = structuredClone(trivySample);
        const secret = sample.Results[2]?.Secrets?.[0] as Record<string, unknown> | undefined;
        if (secret) secret.RuleID = CF_SECRET;
        return readTrivy(json(sample));
      },
    ],
  ];

  it.each(broken)("no part of a seeded secret appears when rejecting %s", (_, run) => {
    const error = thrown(run);
    expect(error).toHaveProperty("reason");
    expect((error as Error).cause).toBeUndefined();
    expectNoSecret(describeThrown(error));
  });
});
