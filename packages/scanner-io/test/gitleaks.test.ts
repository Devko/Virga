import { describe, expect, it } from "vitest";
import { ScannerOutputRejected } from "../src/errors.ts";
import { readGitleaks } from "../src/gitleaks.ts";
import { holdsSecretPiece, MASK, SECRET_PIECE } from "../src/secrets.ts";
import { LINE_SEPARATOR } from "./chars.ts";
import { prng } from "./mutate.ts";
import { CF_SECRET, gitleaksSample, json } from "./samples.ts";

type Finding = Record<string, unknown>;
const clone = (): Finding[] => structuredClone(gitleaksSample) as Finding[];

const rejection = (value: unknown) => {
  try {
    readGitleaks(typeof value === "string" ? value : json(value));
  } catch (error) {
    expect(error).toBeInstanceOf(ScannerOutputRejected);
    return error as ScannerOutputRejected;
  }
  throw new Error("expected a rejection");
};

describe("readGitleaks", () => {
  it("keeps rule, file, lines, the known prefix and a fixed mask", () => {
    const report = readGitleaks(json(gitleaksSample));
    expect(report.tool).toBe("gitleaks");
    expect(report.packages).toEqual([]);
    expect(report.vulnerabilities).toEqual([]);
    expect(report.secrets).toEqual([
      {
        ruleId: "private-key",
        file: "keys/dev.pem",
        line: 20,
        endLine: 22,
        prefix: null,
        masked: MASK,
      },
      {
        ruleId: "generic-api-key",
        file: "src/config.js",
        line: 3,
        endLine: 3,
        prefix: null,
        masked: MASK,
      },
      {
        ruleId: "cloudflare-api-token",
        file: "worker.js",
        line: 12,
        endLine: 12,
        prefix: "cfat_",
        masked: `cfat_${MASK}`,
      },
    ]);
  });

  it.each(["cfat_", "cfut_", "cfk_"])("recognizes the %s prefix", (prefix) => {
    const findings = clone();
    Object.assign(findings[0] ?? {}, { Secret: `${prefix}${"x".repeat(40)}` });
    const secret = readGitleaks(json(findings)).secrets.find((s) => s.file === "worker.js");
    expect(secret).toMatchObject({ prefix, masked: `${prefix}${MASK}` });
  });

  it("does not take a prefix that is all there is, or one in the wrong case", () => {
    for (const value of ["cfat_", "CFAT_abcdef", "xcfat_abcdef", "REDACTED"]) {
      const findings = clone();
      Object.assign(findings[0] ?? {}, { Secret: value });
      const secret = readGitleaks(json(findings)).secrets.find((s) => s.file === "worker.js");
      expect(secret).toMatchObject({ prefix: null, masked: MASK });
    }
  });

  it("drops exact duplicates and keeps the order stable", () => {
    const findings = clone();
    const first = findings[0];
    if (first) findings.push(structuredClone(first));
    findings.reverse();
    expect(readGitleaks(json(findings))).toEqual(readGitleaks(json(gitleaksSample)));
  });

  it("accepts an empty report", () => {
    expect(readGitleaks("[]").secrets).toEqual([]);
  });

  it.each([
    ["an object instead of a list", "{}", "wrong_type", "/"],
    ["a finding that is not an object", "[1]", "wrong_type", "/0"],
    ["null", "null", "wrong_type", "/"],
  ])("rejects %s", (_, text, reason, path) => {
    expect(rejection(text)).toMatchObject({ reason, at: path });
  });

  it.each([
    ["a missing secret", { Secret: undefined }, "missing_field", "/0/Secret"],
    ["a secret that is not text", { Secret: 12 }, "wrong_type", "/0/Secret"],
    ["a missing rule", { RuleID: undefined }, "missing_field", "/0/RuleID"],
    ["a rule with spaces", { RuleID: "rule id" }, "invalid_format", "/0/RuleID"],
    ["a file with a NUL", { File: "a\u0000.js" }, "invalid_text", "/0/File"],
    ["a file with a line separator", { File: `a${LINE_SEPARATOR}.js` }, "invalid_text", "/0/File"],
    ["a long file", { File: "a".repeat(1025) }, "string_too_long", "/0/File"],
    ["a negative line", { StartLine: -1 }, "out_of_range", "/0/StartLine"],
    ["a line as text", { StartLine: "12" }, "wrong_type", "/0/StartLine"],
    ["an end before the start", { EndLine: 11 }, "out_of_range", "/0/EndLine"],
    ["a huge line", { StartLine: 2 ** 40, EndLine: 2 ** 40 }, "out_of_range", "/0/StartLine"],
  ])("rejects %s", (_, fields, reason, path) => {
    const findings = clone();
    Object.assign(findings[0] ?? {}, fields);
    expect(rejection(findings)).toMatchObject({ tool: "gitleaks", reason, at: path });
  });

  it("rejects a finding whose kept fields contain its own secret", () => {
    const findings = clone();
    Object.assign(findings[0] ?? {}, { File: `dist/${CF_SECRET.slice(5)}.js` });
    expect(rejection(findings)).toMatchObject({ reason: "secret_in_kept_field", at: "/0" });
  });

  describe("secret guard (R9 hardening)", () => {
    // Synthetic secrets, built at run time like the samples.
    const SECRET = ["Ab3dE6gH", "9jK2mN5p", "Q8sT1vW4"].join("");
    const withSecret = (secret: string, fields: Record<string, unknown>): Finding[] => {
      const findings = clone();
      Object.assign(findings[1] ?? {}, { Secret: secret, ...fields });
      return findings;
    };
    const guard = (secret: string, fields: Record<string, unknown>) =>
      rejection(withSecret(secret, fields));
    const accepts = (secret: string, fields: Record<string, unknown>) =>
      readGitleaks(json(withSecret(secret, fields)));

    it("R9 secret guard: rejects a file with 23 of the 24 characters of its secret", () => {
      for (const part of [SECRET.slice(1), SECRET.slice(0, -1)]) {
        expect(guard(SECRET, { File: `dist/${part}.js` })).toMatchObject({
          reason: "secret_in_kept_field",
          at: "/1",
        });
      }
    });

    it("R9 secret guard: rejects any six consecutive characters of the secret", () => {
      for (let i = 0; i + 6 <= SECRET.length; i++) {
        const piece = SECRET.slice(i, i + 6);
        expect(guard(SECRET, { File: `a/${piece}/b.js` }).reason).toBe("secret_in_kept_field");
        expect(guard(SECRET, { RuleID: `rule-${piece}` }).reason).toBe("secret_in_kept_field");
      }
    });

    it("R9 secret guard: keeps a file that shares five characters with the secret", () => {
      const report = accepts(SECRET, { File: `a/${SECRET.slice(3, 8)}/b.js` });
      expect(report.secrets.map((s) => s.file)).toContain(`a/${SECRET.slice(3, 8)}/b.js`);
    });

    it("R9 secret guard: searches a 7-character secret", () => {
      const short = SECRET.slice(0, 7);
      expect(guard(short, { File: `x${short.slice(1)}.js` }).reason).toBe("secret_in_kept_field");
      expect(guard(short, { File: `${short}.js` }).reason).toBe("secret_in_kept_field");
    });

    it("R9 secret guard: searches a secret of four or five characters whole", () => {
      for (const short of [SECRET.slice(0, 4), SECRET.slice(0, 5)]) {
        expect(guard(short, { File: `cfg/${short}.txt` }).reason).toBe("secret_in_kept_field");
        expect(() => accepts(short, { File: `cfg/${short.slice(1)}.txt` })).not.toThrow();
      }
    });

    it("R9 secret guard: does not search a secret under four characters", () => {
      const tiny = SECRET.slice(0, 3);
      expect(() => accepts(tiny, { File: `src/${tiny}.js` })).not.toThrow();
    });

    it("R9 secret guard: leaves the known prefix out of the search", () => {
      const token = `cfat_${SECRET}`;
      const report = accepts(token, { File: "docs/cfat_tokens.md" });
      expect(report.secrets.find((s) => s.file === "docs/cfat_tokens.md")).toMatchObject({
        prefix: "cfat_",
      });
      expect(guard(token, { File: `docs/${SECRET.slice(10, 16)}.md` }).reason).toBe(
        "secret_in_kept_field",
      );
    });

    it("R9 secret guard: leaves PEM armor out of the search, not the key", () => {
      const material = ["MIIEvQIBADAN", "BgkqhkiG9w0B", "Zq8Rw2Lm4Tn6"].join("");
      const pem = `-----BEGIN RSA PRIVATE KEY-----\n${material}\n-----END RSA PRIVATE KEY-----`;
      for (const file of ["keys/PRIVATE_KEY.pem", "BEGIN RSA PRIVATE KEY.txt", "certs/END.pem"]) {
        expect(() => accepts(pem, { File: file })).not.toThrow();
      }
      expect(guard(pem, { File: `keys/${material.slice(20, 26)}.pem` }).reason).toBe(
        "secret_in_kept_field",
      );
    });

    it("R9 secret guard: the piece search agrees with a naive search", () => {
      const naive = (kept: string, body: string): boolean => {
        if (body.length < SECRET_PIECE) return kept.includes(body);
        for (let i = 0; i + SECRET_PIECE <= body.length; i++) {
          if (kept.includes(body.slice(i, i + SECRET_PIECE))) return true;
        }
        return false;
      };
      const rng = prng(9);
      // A small alphabet, so that pieces often match; a surrogate pair too.
      const alphabet = ["a", "b", "c", "/", ".", "😀", String.fromCharCode(0xffff)];
      const text = (max: number) =>
        Array.from({ length: rng.int(max) }, () => rng.pick(alphabet)).join("");
      let matches = 0;
      for (let i = 0; i < 20_000; i++) {
        const kept = text(30);
        const body = text(rng.chance(0.2) ? 6 : 24);
        const expected = naive(kept, body);
        if (expected) matches++;
        expect(holdsSecretPiece(kept, body), JSON.stringify([kept, body])).toBe(expected);
      }
      expect(matches).toBeGreaterThan(1_000);
    });

    it("R9 secret guard: searches long secrets and long paths in linear time", () => {
      // 60 findings, each with a 250,000-character secret and a 1,000-character path.
      const body = Array.from({ length: 25_000 }, (_, i) => `${i}`.padStart(10, "z")).join("");
      const findings = Array.from({ length: 60 }, (_, i) => ({
        RuleID: "private-key",
        File: `${"p".repeat(990)}/${i}.pem`,
        StartLine: i,
        EndLine: i,
        Secret: body,
      }));
      const started = performance.now();
      expect(readGitleaks(json(findings)).secrets).toHaveLength(60);
      expect(performance.now() - started).toBeLessThan(2_000);
    });
  });

  it("rejects too many findings instead of truncating", () => {
    expect(() => readGitleaks(json(gitleaksSample), { limits: { maxSecrets: 2 } })).toThrow(
      expect.objectContaining({ reason: "too_many_items", at: "/" }),
    );
  });
});
