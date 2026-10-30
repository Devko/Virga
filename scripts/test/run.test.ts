import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { devNull, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  API_VARS,
  apiOverrides,
  configOverrides,
  dotEnvFiles,
  droppedSettings,
  parseJsonOutput,
  processRunner,
  proxyNotice,
  type RunnerOptions,
  redact,
  unsafeVars,
  type WranglerCommand,
  wranglerEnv,
} from "../lib/run.ts";
import { recordWranglers, type WranglerInstall } from "../lib/wrangler.ts";
import { type FakeWrangler, fakeWrangler, put } from "./helpers.ts";

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

describe("proxyNotice", () => {
  const CA_NOTE =
    "/etc/ssl/proxy-ca.pem; Node trusts these certificates as well, so a proxy with one of their keys can read the API token";

  it("R5-03: names the proxy settings Wrangler gets, with the proxy's host and never its credentials", () => {
    const lines = proxyNotice(
      {
        http_proxy: "proxy.example:8080",
        HTTPS_PROXY: "http://alice:s3cret-pass@proxy.example:3128",
        NO_PROXY: "localhost,.example",
        NODE_EXTRA_CA_CERTS: "/etc/ssl/proxy-ca.pem",
        PATH: "/usr/bin",
        HTTP_PROXY: "",
      },
      "linux",
    );
    expect(lines).toEqual([
      "Proxy settings passed to Wrangler:",
      "  HTTPS_PROXY: proxy.example:3128 (credentials not shown)",
      "  http_proxy: proxy.example:8080",
      "  NO_PROXY: localhost,.example",
      `  NODE_EXTRA_CA_CERTS: ${CA_NOTE}`,
    ]);
    expect(lines.join("\n")).not.toMatch(/alice|s3cret/);
  });

  it("R5-03: prints no value it cannot read as a URL", () => {
    expect(proxyNotice({ https_proxy: "alice:s3cret@" }, "linux")).toEqual([
      "Proxy settings passed to Wrangler:",
      "  https_proxy: (not a URL)",
    ]);
    expect(proxyNotice({ https_proxy: "alice:s3cret@proxy.example:3128" }, "linux")).toEqual([
      "Proxy settings passed to Wrangler:",
      "  https_proxy: proxy.example:3128 (credentials not shown)",
    ]);
  });

  it("R5-03: is empty without proxy settings, and matches without case on Windows", () => {
    expect(proxyNotice({ PATH: "/usr/bin", NO_PROXY: "" }, "linux")).toEqual([]);
    expect(proxyNotice({ Https_Proxy: "http://proxy.example:3128" }, "linux")).toEqual([]);
    expect(proxyNotice({ Https_Proxy: "http://proxy.example:3128" }, "win32")).toEqual([
      "Proxy settings passed to Wrangler:",
      "  Https_Proxy: proxy.example:3128",
    ]);
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

/** Source of a stand-in Wrangler bin file that logs its call and prints what it received. */
const PRINTING_BIN = String.raw`const { appendFileSync } = require("node:fs");
const { resolve } = require("node:path");
const e = process.env;
const orUnset = (v) => (v === undefined || v === "" ? "unset" : v);
const ifUnset = (v) => (v === undefined ? "unset" : v);
appendFileSync(resolve(__dirname, "../../../../../..", "calls.log"), process.argv.slice(2).join(" ") + "\n");
console.log("args=" + process.argv.slice(2).join(" "));
console.log("token=" + orUnset(e.CLOUDFLARE_API_TOKEN) + " key=" + orUnset(e.CLOUDFLARE_API_KEY) + " metrics=" + (e.WRANGLER_SEND_METRICS ?? ""));
console.log("env=" + ifUnset(e.CLOUDFLARE_ENV) + " name=" + ifUnset(e.WRANGLER_CI_OVERRIDE_NAME));
console.log("api=" + ifUnset(e.CLOUDFLARE_API_BASE_URL) + " cf=" + ifUnset(e.CF_API_BASE_URL) + " apienv=" + ifUnset(e.WRANGLER_API_ENVIRONMENT) + " region=" + ifUnset(e.CLOUDFLARE_COMPLIANCE_REGION));
console.log("sanitize=" + ifUnset(e.WRANGLER_LOG_SANITIZE) + " reports=" + ifUnset(e.WRANGLER_SEND_ERROR_REPORTS));
console.error("warning cfat_0123456789abcdefghij");
process.exitCode = 3;
`;

/** Source of a stand-in Wrangler bin file that lists the names of its environment, one per line. */
const NAMES_BIN = "for (const name of Object.keys(process.env)) console.log(name);\n";

const CONFIG_TEXT = '{ "name": "virga-web" }\n';
const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");

describe("processRunner", () => {
  let dir = "";
  /** apps/web with the printing Wrangler. */
  let app = "";
  /** An app whose Wrangler lists its environment. */
  let names = "";
  let config = "";
  let wranglers: Map<string, WranglerInstall>;
  beforeAll(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), "virga-run-")));
    app = join(dir, "apps", "web");
    fakeWrangler(dir, [app], PRINTING_BIN);
    names = join(dir, "names", "apps", "web");
    fakeWrangler(join(dir, "names"), [names], NAMES_BIN);
    config = join(app, "wrangler.jsonc");
    writeFileSync(config, CONFIG_TEXT);
    wranglers = recordWranglers([app, names]);
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

  const runner = (options: Partial<RunnerOptions> = {}) =>
    processRunner({ credentials: "token", secrets: () => [], wranglers, ...options });
  const wrangler = (args: string[], extra: Partial<WranglerCommand> = {}): WranglerCommand => ({
    bin: "wrangler",
    cwd: app,
    config,
    configSha256: sha256(CONFIG_TEXT),
    args,
    capture: true,
    ...extra,
  });

  it("R3-05: runs builds without the deploy token or any other CLOUDFLARE_ variable", async () => {
    vi.stubEnv("PATH", `${join(dir, "path")}:${process.env.PATH ?? ""}`);
    vi.stubEnv("CLOUDFLARE_API_TOKEN", "the-deploy-token-value");
    vi.stubEnv("CLOUDFLARE_ACCOUNT_ID", "0123456789abcdef0123456789abcdef");
    vi.stubEnv("CF_API_TOKEN", "another-token-value");
    const run = runner({ print: () => {} });
    const build = await run({ bin: "pnpm", cwd: dir, args: ["run", "build"], capture: true });
    expect(build.stdout).toBe("args=run build\nvars=\n");
    const result = await run(wrangler([]));
    expect(result.stdout).toContain("token=the-deploy-token-value");
  });

  it("R3-03: passes the checked config, and no credentials in a dry run", async () => {
    vi.stubEnv("CLOUDFLARE_API_TOKEN", "the-deploy-token-value");
    vi.stubEnv("CLOUDFLARE_API_KEY", "a-global-api-key");
    const printed: string[] = [];
    const run = runner({
      credentials: "none",
      print: (stream, line) => printed.push(`${stream}:${line}`),
    });
    const result = await run(wrangler(["deploy", "--dry-run"]));
    expect(result.code).toBe(3);
    expect(result.stdout.split("\n")).toEqual([
      `args=deploy --dry-run --config ${config} --env-file ${devNull}`,
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
    const run = runner({
      secrets: () => ["the-deploy-token-value"],
      print: (_stream, line) => printed.push(line),
    });
    const result = await run(wrangler([], { capture: false }));
    expect(result.stdout).toContain("token=[redacted] key=unset metrics=false");
    expect(printed.join("\n")).not.toContain("the-deploy-token-value");
  });

  it("R3-03: refuses arguments that choose another config or environment", async () => {
    const run = runner({ credentials: "none" });
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
      await expect(run(wrangler(["deploy", ...extra]))).rejects.toThrow(
        /chooses the config or environment/,
      );
    }
    await expect(run(wrangler(["deploy"], { config: "wrangler.jsonc" }))).rejects.toThrow(
      /absolute/,
    );
  });

  it("R3-03: never passes a named environment or another Worker name to Wrangler", async () => {
    vi.stubEnv("CLOUDFLARE_ENV", "prod");
    vi.stubEnv("WRANGLER_CI_OVERRIDE_NAME", "");
    const result = await runner()(wrangler([]));
    expect(result.stdout).toContain("env=unset name=unset");
  });

  it("R5-03: pins the API endpoint, so neither the shell nor a file can supply another", async () => {
    vi.stubEnv("CLOUDFLARE_API_BASE_URL", "http://127.0.0.1:18787/client/v4");
    vi.stubEnv("CF_API_BASE_URL", "http://127.0.0.1:18787/client/v4");
    vi.stubEnv("WRANGLER_API_ENVIRONMENT", "staging");
    vi.stubEnv("WRANGLER_LOG_SANITIZE", "false");
    const result = await runner()(wrangler([]));
    expect(result.stdout).toContain(
      "api=https://api.cloudflare.com/client/v4 cf=unset apienv=production region=public",
    );
    expect(result.stdout).toContain("sanitize=true reports=false");
  });

  it("R5-03: refuses to run Wrangler where it would load a .env, .env.local or .dev.vars file", async () => {
    const run = runner();
    for (const name of [".env", ".env.local", ".dev.vars"]) {
      writeFileSync(join(app, name), "CLOUDFLARE_API_BASE_URL=http://127.0.0.1:18787/client/v4\n");
      try {
        await expect(run(wrangler([]))).rejects.toThrow(
          `${join(app, name)}: Wrangler would load it into its environment`,
        );
      } finally {
        rmSync(join(app, name));
      }
    }
  });

  it("R5-03: gives Wrangler the allowlisted environment, not the operator's", async () => {
    try {
      for (const [name, value] of Object.entries(SHELL)) vi.stubEnv(name, value);
      writeFileSync(join(names, "wrangler.jsonc"), CONFIG_TEXT);
      const result = await runner()(
        wrangler([], { cwd: names, config: join(names, "wrangler.jsonc") }),
      );
      const listed = result.stdout.split("\n").filter((name) => name !== "");
      expect(listed.sort()).toEqual(Object.keys(wranglerEnv(process.env, "token")).sort());
      for (const name of ["WRANGLER_LOG", "CF_API_TOKEN", "NODE_PATH", "GITHUB_TOKEN", "DEBUG"]) {
        expect(listed).not.toContain(name);
      }
      expect(listed).toContain("HTTPS_PROXY");
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("R6-01: refuses an app whose Wrangler was not recorded before the builds", async () => {
    await expect(runner()(wrangler([], { cwd: join(dir, "nothing") }))).rejects.toThrow(
      `${join(dir, "nothing")}: no Wrangler was recorded for it before the builds`,
    );
  });
});

describe("processRunner and what the builds can change (R6-01)", () => {
  let root = "";
  let app = "";
  let config = "";
  let fake: FakeWrangler;
  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "virga-run-r601-")));
    app = join(root, "apps", "web");
    fake = fakeWrangler(root, [app], PRINTING_BIN);
    config = join(app, "wrangler.jsonc");
    writeFileSync(config, CONFIG_TEXT);
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const calls = () =>
    existsSync(join(root, "calls.log")) ? readFileSync(join(root, "calls.log"), "utf8") : "";
  const run = (wranglers: Map<string, WranglerInstall>) =>
    processRunner({ credentials: "token", secrets: () => [], wranglers, print: () => {} })({
      bin: "wrangler",
      cwd: app,
      config,
      configSha256: sha256(CONFIG_TEXT),
      args: ["deploy"],
      capture: true,
    });

  it("R6-01: runs the recorded package's bin file with this node, never a shim or another node", async () => {
    // A `node` first on PATH, as the pnpm shim would find it.
    put(join(root, "path", "node"), '#!/bin/sh\necho "path node ran"\n', 0o755);
    vi.stubEnv("PATH", `${join(root, "path")}:${process.env.PATH ?? ""}`);
    try {
      const result = await run(recordWranglers([app]));
      expect(result.stdout).toContain(`args=deploy --config ${config} --env-file ${devNull}`);
      expect(result.stdout).not.toMatch(/shim ran|path node ran/);
      expect(calls()).toBe(`deploy --config ${config} --env-file ${devNull}\n`);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("R6-01: refuses a config whose bytes differ from the bytes that were checked", async () => {
    const wranglers = recordWranglers([app]);
    for (const text of [
      '{ "name": "virga-web", "unsafe": { "bindings": [{ "name": "API", "type": "service", "service": "virga-broker", "entrypoint": "ApiCaller" }] } }\n',
      '{ "name": "virga-web", "build": { "command": "node steal.js" } }\n',
      CONFIG_TEXT.replace("\n", " \n"),
    ]) {
      writeFileSync(config, text);
      await expect(run(wranglers)).rejects.toThrow(
        `${config} changed after the deploy checked it; refusing to pass it to Wrangler`,
      );
    }
    rmSync(config);
    await expect(run(wranglers)).rejects.toThrow(`${config} cannot be read`);
    expect(calls()).toBe("");
  });

  it("R6-01: refuses to run Wrangler once a file it runs has changed", async () => {
    const shim = fake.shims[0] as string;
    for (const file of [
      fake.bin,
      join(fake.wrangler, "wrangler-dist", "cli.js"),
      join(fake.esbuild, "lib", "main.js"),
      join(fake.platform, "bin", "esbuild"),
      shim,
    ]) {
      const wranglers = recordWranglers([app]);
      const before = readFileSync(file);
      appendFileSync(file, "\n// planted\n");
      await expect(run(wranglers), file).rejects.toThrow(
        `the Wrangler of ${app} changed after the deploy recorded it before the builds: ${file}.`,
      );
      writeFileSync(file, before);
    }
    expect(calls()).toBe("");
    // Unchanged, it runs.
    await run(recordWranglers([app]));
    expect(calls()).not.toBe("");
  });
});
