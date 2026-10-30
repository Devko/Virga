import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  apiOverrides,
  configOverrides,
  dotEnvFiles,
  parseJsonOutput,
  processRunner,
  redact,
} from "../lib/run.ts";

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

describe("apiOverrides", () => {
  it("R5-03: names variables that would send the token to another API", () => {
    expect(
      apiOverrides({
        CLOUDFLARE_API_BASE_URL: "http://127.0.0.1:18787/client/v4",
        CF_API_BASE_URL: "http://127.0.0.1:18787/client/v4",
        WRANGLER_API_ENVIRONMENT: "staging",
        CLOUDFLARE_COMPLIANCE_REGION: "fedramp_high",
      }),
    ).toEqual([
      "CLOUDFLARE_API_BASE_URL",
      "WRANGLER_API_ENVIRONMENT",
      "CLOUDFLARE_COMPLIANCE_REGION",
      "CF_API_BASE_URL",
    ]);
    expect(
      apiOverrides({
        CLOUDFLARE_API_BASE_URL: "https://api.cloudflare.com/client/v4",
        WRANGLER_API_ENVIRONMENT: "production",
        CF_API_BASE_URL: "",
      }),
    ).toEqual([]);
  });
});

describe("dotEnvFiles", () => {
  it("R5-03: finds the files Wrangler loads into its environment", () => {
    const dir = mkdtempSync(join(tmpdir(), "virga-dotenv-"));
    try {
      expect(dotEnvFiles(dir)).toEqual([]);
      for (const name of [".env", ".env.local", ".dev.vars", ".env.example"]) {
        writeFileSync(join(dir, name), "CLOUDFLARE_API_BASE_URL=http://127.0.0.1:18787\n");
      }
      expect(dotEnvFiles(dir)).toEqual(
        [".env", ".env.local", ".dev.vars"].map((f) => join(dir, f)),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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
        // biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion
        'echo "api=${CLOUDFLARE_API_BASE_URL-unset} cf=${CF_API_BASE_URL-unset} apienv=${WRANGLER_API_ENVIRONMENT-unset} region=${CLOUDFLARE_COMPLIANCE_REGION-unset}"',
        // biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion
        'echo "sanitize=${WRANGLER_LOG_SANITIZE-unset} reports=${WRANGLER_SEND_ERROR_REPORTS-unset}"',
        'echo "warning cfat_0123456789abcdefghij" >&2',
        "exit 3",
      ].join("\n"),
    );
    chmodSync(bin, 0o755);
    // A stand-in for pnpm, found through PATH, that lists the Cloudflare variables it sees.
    mkdirSync(join(dir, "path"));
    const pnpm = join(dir, "path", "pnpm");
    writeFileSync(
      pnpm,
      [
        "#!/bin/sh",
        'echo "args=$*"',
        "echo \"vars=$(env | grep -E '^(CLOUDFLARE|CF)_' | cut -d= -f1 | sort | tr '\\n' ' ')\"",
      ].join("\n"),
    );
    chmodSync(pnpm, 0o755);
  });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
    vi.unstubAllEnvs();
  });

  it("R3-05: runs builds without the deploy token or any other CLOUDFLARE_ variable", async () => {
    vi.stubEnv("PATH", `${join(dir, "path")}:${process.env.PATH ?? ""}`);
    vi.stubEnv("CLOUDFLARE_API_TOKEN", "the-deploy-token-value");
    vi.stubEnv("CLOUDFLARE_ACCOUNT_ID", "0123456789abcdef0123456789abcdef");
    vi.stubEnv("CF_API_TOKEN", "another-token-value");
    const run = processRunner({ credentials: "token", secrets: () => [], print: () => {} });
    const build = await run({ bin: "pnpm", cwd: dir, args: ["run", "build"], capture: true });
    expect(build.stdout).toBe("args=run build\nvars=\n");
    const wrangler = await run({
      bin: "wrangler",
      cwd: dir,
      config: CONFIG,
      args: [],
      capture: true,
    });
    expect(wrangler.stdout).toContain("token=the-deploy-token-value");
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
    expect(result.stdout.split("\n")).toEqual([
      `args=deploy --dry-run --config ${CONFIG} --env-file ${devNull}`,
      "token=unset key=unset metrics=false",
      "env=unset name=unset",
      "api=https://api.cloudflare.com/client/v4 cf=unset apienv=production region=public",
      "sanitize=true reports=false",
      "",
    ]);
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
      // R5-03: the .env file to load, and the directory it is looked up in.
      ["--env-file", ".env"],
      ["--env-file=.env"],
      ["--cwd", "/tmp"],
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

  it("R5-03: pins the API endpoint, so neither the shell nor a file can supply another", async () => {
    vi.stubEnv("CLOUDFLARE_API_BASE_URL", "http://127.0.0.1:18787/client/v4");
    vi.stubEnv("CF_API_BASE_URL", "http://127.0.0.1:18787/client/v4");
    vi.stubEnv("WRANGLER_API_ENVIRONMENT", "staging");
    vi.stubEnv("WRANGLER_LOG_SANITIZE", "false");
    const run = processRunner({ credentials: "token", secrets: () => [] });
    const result = await run({
      bin: "wrangler",
      cwd: dir,
      config: CONFIG,
      args: [],
      capture: true,
    });
    expect(result.stdout).toContain(
      "api=https://api.cloudflare.com/client/v4 cf=unset apienv=production region=public",
    );
    expect(result.stdout).toContain("sanitize=true reports=false");
  });

  it("R5-03: refuses to run Wrangler where it would load a .env, .env.local or .dev.vars file", async () => {
    const run = processRunner({ credentials: "token", secrets: () => [] });
    for (const name of [".env", ".env.local", ".dev.vars"]) {
      writeFileSync(join(dir, name), "CLOUDFLARE_API_BASE_URL=http://127.0.0.1:18787/client/v4\n");
      try {
        await expect(run({ bin: "wrangler", cwd: dir, config: CONFIG, args: [] })).rejects.toThrow(
          `${join(dir, name)}: Wrangler would load it into its environment`,
        );
      } finally {
        rmSync(join(dir, name));
      }
    }
  });

  it("asks for pnpm install when the app has no Wrangler", async () => {
    const run = processRunner({ credentials: "none", secrets: () => [] });
    await expect(
      run({ bin: "wrangler", cwd: join(dir, "nothing"), config: CONFIG, args: [] }),
    ).rejects.toThrow(/pnpm install/);
  });
});
