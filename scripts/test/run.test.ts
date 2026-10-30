import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  API_VARS,
  apiOverrides,
  configOverrides,
  dotEnvFiles,
  droppedSettings,
  parseJsonOutput,
  processRunner,
  redact,
  unsafeVars,
  wranglerEnv,
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

/** An operator's shell: what Node and Wrangler need, the deploy's own variables, and much else. */
const SHELL: Record<string, string> = {
  PATH: "/usr/local/bin:/usr/bin:/bin",
  HOME: "/home/op",
  TMPDIR: "/tmp/op",
  USER: "op",
  LANG: "en_US.UTF-8",
  LC_ALL: "en_US.UTF-8",
  TERM: "xterm-256color",
  TZ: "Europe/Berlin",
  https_proxy: "http://proxy.example:3128",
  HTTPS_PROXY: "http://proxy.example:3128",
  NO_PROXY: "localhost,.example",
  NODE_EXTRA_CA_CERTS: "/etc/ssl/proxy-ca.pem",
  CLOUDFLARE_API_TOKEN: "the-deploy-token-value",
  CLOUDFLARE_ACCOUNT_ID: "0123456789abcdef0123456789abcdef",
  // Other Cloudflare and Wrangler settings: credentials, other accounts, other
  // auth hosts, bundling, logs and output files.
  CLOUDFLARE_API_KEY: "a-global-api-key",
  CLOUDFLARE_EMAIL: "op@example.com",
  CF_API_TOKEN: "another-token-value",
  CF_ACCOUNT_ID: "fedcba9876543210fedcba9876543210",
  CLOUDFLARE_ACCESS_CLIENT_ID: "access-client",
  CLOUDFLARE_INCLUDE_PROCESS_ENV: "true",
  CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV: "true",
  WRANGLER_AUTH_DOMAIN: "dash.example",
  WRANGLER_BUILD_CONDITIONS: "development",
  WRANGLER_LOG: "debug",
  WRANGLER_LOG_PATH: "/tmp/wrangler.log",
  WRANGLER_OUTPUT_FILE_PATH: "/tmp/wrangler-output.json",
  WRANGLER_SEND_METRICS: "true",
  // Node, libraries and other tools.
  NODE_PATH: "/opt/node_modules",
  NODE_ENV: "development",
  NODE_DEBUG: "http,tls",
  SSL_CERT_FILE: "/etc/ssl/other.pem",
  LD_LIBRARY_PATH: "/opt/lib",
  DEBUG: "*",
  DOTENV_KEY: "dotenv://:key_0123@dotenv.org/vault/.env.vault?environment=production",
  SENTRY_DSN: "https://key@sentry.example/1",
  GITHUB_TOKEN: "ghp_0123456789",
  AWS_SECRET_ACCESS_KEY: "aws-secret",
  npm_config_user_agent: "pnpm/10.28.0",
};

/** What the deploy itself sets for every Wrangler call. */
const SET_BY_DEPLOY = {
  ...API_VARS,
  WRANGLER_SEND_METRICS: "false",
  WRANGLER_SEND_ERROR_REPORTS: "false",
  WRANGLER_LOG_SANITIZE: "true",
};

const pick = (env: Record<string, string>, names: string[]) =>
  Object.fromEntries(names.map((name) => [name, env[name]]));

describe("wranglerEnv", () => {
  const PASSED = [
    "PATH",
    "HOME",
    "TMPDIR",
    "USER",
    "LANG",
    "LC_ALL",
    "TERM",
    "TZ",
    "https_proxy",
    "HTTPS_PROXY",
    "NO_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "CLOUDFLARE_ACCOUNT_ID",
  ];

  it("R5-03: passes what Node and Wrangler need, the proxy, the account and the token, nothing else", () => {
    expect(wranglerEnv(SHELL, "token", "linux")).toEqual({
      ...pick(SHELL, [...PASSED, "CLOUDFLARE_API_TOKEN"]),
      ...SET_BY_DEPLOY,
    });
  });

  it("R5-03: passes no token in a dry run", () => {
    expect(wranglerEnv(SHELL, "none", "linux")).toEqual({
      ...pick(SHELL, PASSED),
      ...SET_BY_DEPLOY,
    });
  });

  it("R5-03: passes the Windows system variables on Windows only, where names have no case", () => {
    const windows = {
      Path: "C:\\Windows\\system32;C:\\Program Files\\nodejs",
      SystemRoot: "C:\\Windows",
      windir: "C:\\Windows",
      ComSpec: "C:\\Windows\\system32\\cmd.exe",
      PATHEXT: ".COM;.EXE;.BAT;.CMD",
      TEMP: "C:\\Users\\op\\AppData\\Local\\Temp",
      TMP: "C:\\Users\\op\\AppData\\Local\\Temp",
      USERPROFILE: "C:\\Users\\op",
      APPDATA: "C:\\Users\\op\\AppData\\Roaming",
      LOCALAPPDATA: "C:\\Users\\op\\AppData\\Local",
      "ProgramFiles(x86)": "C:\\Program Files (x86)",
      Https_Proxy: "http://proxy.example:3128",
      cloudflare_api_token: "the-deploy-token-value",
    };
    const dropped = {
      PSModulePath: "C:\\x",
      OneDrive: "C:\\Users\\op\\OneDrive",
      Wrangler_Log: "debug",
    };
    expect(wranglerEnv({ ...windows, ...dropped }, "token", "win32")).toEqual({
      ...windows,
      ...SET_BY_DEPLOY,
    });
    expect(Object.keys(wranglerEnv(windows, "token", "linux")).sort()).toEqual(
      Object.keys(SET_BY_DEPLOY).sort(),
    );
  });
});

describe("droppedSettings", () => {
  it("R5-03: names the Cloudflare and Wrangler variables that Wrangler does not get as set", () => {
    const dropped = [
      "CF_ACCOUNT_ID",
      "CF_API_TOKEN",
      "CLOUDFLARE_ACCESS_CLIENT_ID",
      "CLOUDFLARE_API_KEY",
      "CLOUDFLARE_EMAIL",
      "CLOUDFLARE_INCLUDE_PROCESS_ENV",
      "CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV",
      "WRANGLER_AUTH_DOMAIN",
      "WRANGLER_BUILD_CONDITIONS",
      "WRANGLER_LOG",
      "WRANGLER_LOG_PATH",
      "WRANGLER_OUTPUT_FILE_PATH",
      "WRANGLER_SEND_METRICS",
    ];
    expect(droppedSettings(SHELL, "token", "linux")).toEqual(dropped);
    expect(droppedSettings(SHELL, "none", "linux")).toEqual(
      [...dropped, "CLOUDFLARE_API_TOKEN"].sort(),
    );
    // A pinned value the operator set as well is not dropped.
    expect(
      droppedSettings(
        { ...API_VARS, WRANGLER_LOG_SANITIZE: "true", WRANGLER_LOG: "" },
        "token",
        "linux",
      ),
    ).toEqual([]);
  });
});

describe("unsafeVars", () => {
  it("R5-03: names variables that load code or turn off certificate checks", () => {
    expect(
      unsafeVars(
        {
          NODE_OPTIONS: "--require ./capture.js",
          NODE_TLS_REJECT_UNAUTHORIZED: "0",
          LD_PRELOAD: "/tmp/capture.so",
          LD_AUDIT: "/tmp/capture.so",
          DYLD_INSERT_LIBRARIES: "/tmp/capture.dylib",
          OPENSSL_CONF: "/tmp/engine.cnf",
          PATH: "/usr/bin",
          NODE_PATH: "/opt/node_modules",
          NODE_EXTRA_CA_CERTS: "/etc/ssl/proxy-ca.pem",
        },
        "linux",
      ),
    ).toEqual([
      "NODE_OPTIONS",
      "NODE_TLS_REJECT_UNAUTHORIZED",
      "LD_PRELOAD",
      "LD_AUDIT",
      "DYLD_INSERT_LIBRARIES",
      "OPENSSL_CONF",
    ]);
  });

  it("R5-03: refuses any value, and ignores empty ones and other cases outside Windows", () => {
    expect(unsafeVars({ NODE_OPTIONS: "--max-old-space-size=4096" }, "linux")).toEqual([
      "NODE_OPTIONS",
    ]);
    expect(unsafeVars({ NODE_TLS_REJECT_UNAUTHORIZED: "1" }, "darwin")).toEqual([
      "NODE_TLS_REJECT_UNAUTHORIZED",
    ]);
    expect(unsafeVars({ NODE_OPTIONS: "", node_options: "--require x" }, "linux")).toEqual([]);
    expect(unsafeVars({ node_options: "--require x" }, "win32")).toEqual(["node_options"]);
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
    // A stand-in for Wrangler that lists the names of its environment, one per line.
    mkdirSync(join(dir, "names", "node_modules", ".bin"), { recursive: true });
    const names = join(dir, "names", "node_modules", ".bin", "wrangler");
    writeFileSync(names, ["#!/bin/sh", "env | cut -d= -f1"].join("\n"));
    chmodSync(names, 0o755);
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

  it("R5-03: gives Wrangler the allowlisted environment, not the operator's", async () => {
    try {
      for (const [name, value] of Object.entries(SHELL)) vi.stubEnv(name, value);
      const run = processRunner({ credentials: "token", secrets: () => [] });
      const result = await run({
        bin: "wrangler",
        cwd: join(dir, "names"),
        config: CONFIG,
        args: [],
        capture: true,
      });
      // The shell adds its own.
      const names = result.stdout
        .split("\n")
        .filter((name) => name !== "" && !/^(?:PWD|OLDPWD|SHLVL|_)$/.test(name));
      expect(names.sort()).toEqual(Object.keys(wranglerEnv(process.env, "token")).sort());
      for (const name of ["WRANGLER_LOG", "CF_API_TOKEN", "NODE_PATH", "GITHUB_TOKEN", "DEBUG"]) {
        expect(names).not.toContain(name);
      }
      expect(names).toContain("HTTPS_PROXY");
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("asks for pnpm install when the app has no Wrangler", async () => {
    const run = processRunner({ credentials: "none", secrets: () => [] });
    await expect(
      run({ bin: "wrangler", cwd: join(dir, "nothing"), config: CONFIG, args: [] }),
    ).rejects.toThrow(/pnpm install/);
  });
});
