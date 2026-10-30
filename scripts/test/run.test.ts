import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { configOverrides, parseJsonOutput, processRunner, redact } from "../lib/run.ts";

describe("redact", () => {
  it("removes known secrets and Cloudflare credential shapes", () => {
    const text = "token abcdefgh123 and cfat_AbCdEf0123456789xyz, cfk_0123456789abcdef in a line";
    expect(redact(text, ["abcdefgh123"])).toBe(
      "token [redacted] and [redacted], [redacted] in a line",
    );
  });

  it("leaves short values alone so it never redacts common words", () => {
    expect(redact("a b c", ["a"])).toBe("a b c");
  });
});

describe("parseJsonOutput", () => {
  it("skips banners before the JSON document", () => {
    const stdout = ' ⛅️ wrangler 4.151.0\n───\n[\n  { "uuid": "u", "name": "virga-vault" }\n]\n';
    expect(parseJsonOutput(stdout)).toEqual([{ uuid: "u", name: "virga-vault" }]);
  });

  it("fails without JSON", () => {
    expect(() => parseJsonOutput("nothing here")).toThrow(/no JSON/);
  });
});

const CONFIG = "/repo/apps/web/wrangler.jsonc";

describe("configOverrides", () => {
  it("R3-03: names the variables that make Wrangler deploy something else", () => {
    expect(configOverrides({ CLOUDFLARE_ENV: "prod", WRANGLER_CI_OVERRIDE_NAME: "x" })).toEqual([
      "CLOUDFLARE_ENV",
      "WRANGLER_CI_OVERRIDE_NAME",
    ]);
    expect(configOverrides({ CLOUDFLARE_ENV: "", PATH: "/bin" })).toEqual([]);
  });
});

describe("processRunner", () => {
  let dir = "";
  beforeAll(() => {
    // A stand-in for Wrangler that prints what it received.
    dir = mkdtempSync(join(tmpdir(), "virga-run-"));
    mkdirSync(join(dir, "node_modules", ".bin"), { recursive: true });
    const bin = join(dir, "node_modules", ".bin", "wrangler");
    writeFileSync(
      bin,
      [
        "#!/bin/sh",
        'echo "args=$*"',
        // biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion
        'echo "token=${CLOUDFLARE_API_TOKEN:-unset} key=${CLOUDFLARE_API_KEY:-unset} metrics=$WRANGLER_SEND_METRICS"',
        // biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion
        'echo "env=${CLOUDFLARE_ENV-unset} name=${WRANGLER_CI_OVERRIDE_NAME-unset}"',
        'echo "warning cfat_0123456789abcdefghij" >&2',
        "exit 3",
      ].join("\n"),
    );
    chmodSync(bin, 0o755);
  });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
    vi.unstubAllEnvs();
  });

  it("R3-03: passes the checked config, and no credentials in a dry run", async () => {
    vi.stubEnv("CLOUDFLARE_API_TOKEN", "the-deploy-token-value");
    vi.stubEnv("CLOUDFLARE_API_KEY", "a-global-api-key");
    const printed: string[] = [];
    const run = processRunner({
      credentials: "none",
      secrets: () => [],
      print: (stream, line) => printed.push(`${stream}:${line}`),
    });
    const result = await run({
      bin: "wrangler",
      cwd: dir,
      config: CONFIG,
      args: ["deploy", "--dry-run"],
      capture: true,
    });
    expect(result.code).toBe(3);
    expect(result.stdout).toBe(
      `args=deploy --dry-run --config ${CONFIG}\ntoken=unset key=unset metrics=false\nenv=unset name=unset\n`,
    );
    // Captured stdout is not printed; stderr is, redacted.
    expect(printed).toEqual(["stderr:warning [redacted]"]);
  });

  it("keeps only the API token for a deploy and never prints it", async () => {
    vi.stubEnv("CLOUDFLARE_API_TOKEN", "the-deploy-token-value");
    vi.stubEnv("CLOUDFLARE_API_KEY", "a-global-api-key");
    const printed: string[] = [];
    const run = processRunner({
      credentials: "token",
      secrets: () => ["the-deploy-token-value"],
      print: (_stream, line) => printed.push(line),
    });
    const result = await run({ bin: "wrangler", cwd: dir, config: CONFIG, args: [] });
    expect(result.stdout).toContain("token=[redacted] key=unset metrics=false");
    expect(printed.join("\n")).not.toContain("the-deploy-token-value");
  });

  it("R3-03: refuses arguments that choose another config or environment", async () => {
    const run = processRunner({ credentials: "none", secrets: () => [] });
    for (const extra of [
      ["--env", "prod"],
      ["-e", "prod"],
      ["--env=prod"],
      ["--config", "x"],
      ["-c", "x"],
    ]) {
      await expect(
        run({ bin: "wrangler", cwd: dir, config: CONFIG, args: ["deploy", ...extra] }),
      ).rejects.toThrow(/chooses the config or environment/);
    }
    await expect(
      run({ bin: "wrangler", cwd: dir, config: "wrangler.jsonc", args: ["deploy"] }),
    ).rejects.toThrow(/absolute/);
  });

  it("R3-03: never passes a named environment or another Worker name to Wrangler", async () => {
    vi.stubEnv("CLOUDFLARE_ENV", "prod");
    vi.stubEnv("WRANGLER_CI_OVERRIDE_NAME", "");
    const run = processRunner({ credentials: "token", secrets: () => [] });
    const result = await run({
      bin: "wrangler",
      cwd: dir,
      config: CONFIG,
      args: [],
      capture: true,
    });
    expect(result.stdout).toContain("env=unset name=unset");
  });

  it("asks for pnpm install when the app has no Wrangler", async () => {
    const run = processRunner({ credentials: "none", secrets: () => [] });
    await expect(
      run({ bin: "wrangler", cwd: join(dir, "nothing"), config: CONFIG, args: [] }),
    ).rejects.toThrow(/pnpm install/);
  });
});
