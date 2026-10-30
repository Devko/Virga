import { describe, expect, it } from "vitest";
import { detectSecret, detectSecretIn, entropy } from "../../src/platform/secrets.ts";

// Fake credentials are assembled at runtime so secret scanners do not flag this file.
const forty = "Q7v2Lm9XkT4pR8sWc1Ny6Hb3Jd5Fg0Za2Ue7Io4P";
const fake = (prefix: string) => `${prefix}_${forty}a1B2c`;

describe("detectSecret", () => {
  it("recognizes Cloudflare scannable token formats", () => {
    expect(detectSecret(fake("cfat"))).toEqual({ looks_secret: true, secret_pattern: "cfat_" });
    expect(detectSecret(fake("cfut"))).toEqual({ looks_secret: true, secret_pattern: "cfut_" });
    expect(detectSecret(`Bearer ${fake("cfk")}`)).toEqual({
      looks_secret: true,
      secret_pattern: "cfk_",
    });
  });

  it("needs the full token length after a Cloudflare prefix", () => {
    expect(detectSecret("cfat_short").secret_pattern).toBeNull();
    expect(detectSecret(`xcfat_${forty}`).secret_pattern).not.toBe("cfat_");
  });

  it("recognizes AWS access key IDs", () => {
    const key = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
    expect(detectSecret(key).secret_pattern).toBe("aws_access_key");
    expect(detectSecret(`aws=${key};`).secret_pattern).toBe("aws_access_key");
    expect(detectSecret(`${key}X`).secret_pattern).not.toBe("aws_access_key");
  });

  it("recognizes private key blocks", () => {
    for (const kind of ["RSA ", "EC ", "OPENSSH ", "ENCRYPTED ", ""]) {
      const block = `-----BEGIN ${kind}PRIVATE KEY-----\nMIIB\n-----END ${kind}PRIVATE KEY-----`;
      expect(detectSecret(block).secret_pattern, kind).toBe("private_key");
    }
    expect(detectSecret("-----BEGIN PGP PRIVATE KEY BLOCK-----").secret_pattern).toBe(
      "private_key",
    );
    expect(detectSecret("-----BEGIN PUBLIC KEY-----").secret_pattern).toBeNull();
  });

  it("flags long random strings", () => {
    expect(detectSecret(forty).secret_pattern).toBe("high_entropy");
    const stripeLike = ["sk", "live", "51HxQ2bL8vN3mR7tK9pW4cY6zA1dF5gJ"].join("_");
    expect(detectSecret(stripeLike).secret_pattern).toBe("high_entropy");
    // 37 to 45 hex characters is the old Global API Key format.
    expect(detectSecret("c2547eb745079dac9320b638f5e225cf483cc").secret_pattern).toBe(
      "high_entropy",
    );
  });

  it("leaves identifiers, URLs and words alone", () => {
    const quiet = [
      "",
      "production",
      "https://api.example.com/v1/resources/items",
      "0f2ac74b498b48028cb68387c421e279", // 32 hex: account, zone or namespace ID
      "182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e",
      "ThisIsAVeryLongCamelCaseIdentifierWithoutDigits",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
      "Short value with spaces that is long enough to be over thirty-two characters",
    ];
    for (const value of quiet) {
      expect(detectSecret(value), value).toEqual({ looks_secret: false, secret_pattern: null });
    }
  });

  it("never returns the value", () => {
    const verdict = detectSecret(fake("cfat"));
    expect(JSON.stringify(verdict)).not.toContain(forty);
  });
});

describe("detectSecretIn", () => {
  const clean = { looks_secret: false, secret_pattern: null };

  it("R2-09: tests every string of a JSON value, keys included", () => {
    expect(detectSecretIn({ a: { b: ["x", fake("cfut")] } }).secret_pattern).toBe("cfut_");
    expect(detectSecretIn({ [fake("cfk")]: 1 }).secret_pattern).toBe("cfk_");
    expect(detectSecretIn([[[forty]]]).secret_pattern).toBe("high_entropy");
    expect(detectSecretIn({ region: "eu", retries: 3, on: true, off: null })).toEqual(clean);
    for (const value of [null, 0, false, [], {}, ""]) expect(detectSecretIn(value)).toEqual(clean);
  });

  it("is detectSecret for a single string", () => {
    for (const value of [fake("cfat"), forty, "production"]) {
      expect(detectSecretIn(value)).toEqual(detectSecret(value));
    }
  });

  it("names the strongest pattern, whatever the order", () => {
    const key = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
    expect(detectSecretIn([forty, key, fake("cfk")]).secret_pattern).toBe("cfk_");
    expect(detectSecretIn({ z: fake("cfat"), a: forty }).secret_pattern).toBe("cfat_");
  });

  it("walks deep nesting without recursion", () => {
    let value: unknown = { k: fake("cfat") };
    for (let i = 0; i < 100_000; i++) value = i % 2 ? [value] : { v: value };
    expect(detectSecretIn(value).secret_pattern).toBe("cfat_");
  });
});

describe("entropy", () => {
  it("is zero for one repeated character and log2(n) for n distinct ones", () => {
    expect(entropy("")).toBe(0);
    expect(entropy("aaaa")).toBe(0);
    expect(entropy("abcd")).toBe(2);
  });
});
