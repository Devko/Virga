import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { devNull } from "node:os";
import { isAbsolute, join } from "node:path";

interface BaseCommand {
  /** The Worker's directory. */
  cwd: string;
  args: string[];
  /** Keep stdout for parsing instead of printing it. stderr is always printed. */
  capture?: boolean;
}

/** Runs the app's own pinned Wrangler. */
export interface WranglerCommand extends BaseCommand {
  bin: "wrangler";
  /**
   * Absolute path of the config the script checked. Wrangler gets it as
   * --config; without it, Wrangler would take the first wrangler.json in any
   * directory above `cwd` before the app's own wrangler.jsonc (R3-03).
   */
  config: string;
}

/** Runs a package script. */
export interface PnpmCommand extends BaseCommand {
  bin: "pnpm";
}

export type Command = WranglerCommand | PnpmCommand;

export interface Result {
  code: number;
  stdout: string;
  stderr: string;
}

export type Runner = (command: Command) => Promise<Result>;

/** Credentials Wrangler reads from the environment. A dry run passes none of them on. */
export const CREDENTIAL_VARS = [
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_API_KEY",
  "CLOUDFLARE_EMAIL",
  "CF_API_TOKEN",
  "CF_API_KEY",
  "CF_EMAIL",
];

/**
 * Names of the deploy's own Cloudflare settings and credentials. They never
 * become Worker secrets, and builds never see them.
 */
export const isCloudflareVar = (name: string) => /^(?:CLOUDFLARE|CF)_/i.test(name);

const TOKEN_PATTERN = /\b(?:cfat|cfut|cfk|cfoat)_[A-Za-z0-9_-]{8,}/g;

/**
 * Wrangler flags that pick another config, a named environment, the .env
 * files to load or the directory to look for them in. Only the runner sets
 * --config and --env-file.
 */
const CHOOSERS = /^(?:--config|-c|--env|-e|--env-file|--cwd)(?:=|$)/;

/**
 * Variables with which Wrangler deploys something other than the checked
 * config: a named environment, or another Worker name (meant for Workers Builds).
 */
export const OVERRIDE_VARS = ["CLOUDFLARE_ENV", "WRANGLER_CI_OVERRIDE_NAME"];

/** The override variables set in `env`. The deploy refuses to run while one is set. */
export function configOverrides(env: Readonly<Record<string, string | undefined>>): string[] {
  return OVERRIDE_VARS.filter((name) => (env[name] ?? "") !== "");
}

/**
 * Where Wrangler sends the token: its defaults for the public API, set
 * explicitly for every Wrangler call. Wrangler fills only variables that are
 * unset or empty from a .env file, so no file can change these (R5-03).
 */
export const API_VARS: Readonly<Record<string, string>> = {
  CLOUDFLARE_API_BASE_URL: "https://api.cloudflare.com/client/v4",
  WRANGLER_API_ENVIRONMENT: "production",
  CLOUDFLARE_COMPLIANCE_REGION: "public",
};

/** The old name of CLOUDFLARE_API_BASE_URL, which Wrangler still reads. Never passed on. */
const OLD_API_VARS = ["CF_API_BASE_URL"];

/** Keep Wrangler's telemetry off and the token out of its debug log. */
const QUIET_VARS = {
  WRANGLER_SEND_METRICS: "false",
  WRANGLER_SEND_ERROR_REPORTS: "false",
  WRANGLER_LOG_SANITIZE: "true",
};

/** API variables in `env` that would send the token elsewhere. The deploy refuses to run while one is set. */
export function apiOverrides(env: Readonly<Record<string, string | undefined>>): string[] {
  const set = (name: string) => (env[name] ?? "") !== "";
  return [
    ...Object.keys(API_VARS).filter((name) => set(name) && env[name] !== API_VARS[name]),
    ...OLD_API_VARS.filter(set),
  ];
}

/**
 * Files Wrangler 4.151.0 loads into its environment from the directory it
 * runs in: .env and .env.local for every command, .dev.vars for `dev` and
 * `types`. What they set would be unchecked input to the deploy (R5-03).
 */
const DOTENV_FILES = [".env", ".env.local", ".dev.vars"];

/** The files of DOTENV_FILES that exist in `dir`. */
export function dotEnvFiles(dir: string): string[] {
  return DOTENV_FILES.map((file) => join(dir, file)).filter((path) => existsSync(path));
}

export const dotEnvProblem = (path: string) =>
  `${path}: Wrangler would load it into its environment, where it can change the API host, the Worker name or the environment that is deployed. Remove it; the deploy takes settings only from its own environment`;

/** Replaces known secret values and anything shaped like a Cloudflare credential. */
export function redact(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const secret of secrets) {
    if (secret.length >= 8) out = out.split(secret).join("[redacted]");
  }
  return out.replace(TOKEN_PATTERN, "[redacted]");
}

export interface RunnerOptions {
  /**
   * What Wrangler gets: `none` strips every credential from its environment
   * (dry run); `token` keeps only CLOUDFLARE_API_TOKEN, so Wrangler cannot
   * fall back to a Global API Key. Builds never get credentials.
   */
  credentials: "none" | "token";
  /** Values that must never be printed, such as the API token. */
  secrets: () => readonly string[];
  print?: (stream: "stdout" | "stderr", line: string) => void;
}

/**
 * The environment of a child process. A build (`pnpm`) runs the app's whole
 * build-time dependency tree and never reaches the API, so it gets no
 * CLOUDFLARE_ or CF_ variable at all (R3-05). Wrangler gets API_VARS set.
 */
function childEnv(command: Command, credentials: RunnerOptions["credentials"]): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, ...QUIET_VARS };
  for (const name of [...OVERRIDE_VARS, ...OLD_API_VARS]) delete env[name];
  if (command.bin === "pnpm") {
    for (const name of Object.keys(env)) {
      if (isCloudflareVar(name)) delete env[name];
    }
    return env;
  }
  Object.assign(env, API_VARS);
  for (const name of CREDENTIAL_VARS) {
    if (credentials === "none" || name !== "CLOUDFLARE_API_TOKEN") delete env[name];
  }
  return env;
}

/**
 * Runs commands with stdin closed, so Wrangler never prompts and never writes
 * resource IDs back into a config. Wrangler gets the checked config and loads
 * no .env file: --env-file names the null device in place of its defaults
 * (4.151.0 has no flag that turns loading off), and the runner refuses a
 * directory that holds one (R5-03). All output passes through `redact`.
 */
export function processRunner(options: RunnerOptions): Runner {
  const print =
    options.print ??
    ((stream, line) => (stream === "stdout" ? process.stdout : process.stderr).write(`${line}\n`));
  return (command) =>
    new Promise((resolve, reject) => {
      let file = "pnpm";
      let args = command.args;
      if (command.bin === "wrangler") {
        file = join(command.cwd, "node_modules", ".bin", "wrangler");
        const chooser = command.args.find((arg) => CHOOSERS.test(arg));
        if (chooser !== undefined) {
          reject(new Error(`wrangler argument ${chooser} chooses the config or environment`));
          return;
        }
        if (!isAbsolute(command.config)) {
          reject(new Error(`wrangler --config needs an absolute path, not ${command.config}`));
          return;
        }
        if (!existsSync(file)) {
          reject(new Error(`${file} not found; run pnpm install first`));
          return;
        }
        const dotEnv = dotEnvFiles(command.cwd);
        if (dotEnv.length > 0) {
          reject(new Error(dotEnv.map(dotEnvProblem).join("\n")));
          return;
        }
        args = [...command.args, "--config", command.config, "--env-file", devNull];
      }
      const child = spawn(file, args, {
        cwd: command.cwd,
        env: childEnv(command, options.credentials),
        stdio: ["ignore", "pipe", "pipe"],
      });
      const out = { stdout: "", stderr: "" };
      const pending = { stdout: "", stderr: "" };
      const emit = (stream: "stdout" | "stderr", line: string) => {
        const clean = redact(line, options.secrets());
        out[stream] += `${clean}\n`;
        if (stream === "stderr" || !command.capture) print(stream, clean);
      };
      const collect = (stream: "stdout" | "stderr") => (chunk: Buffer) => {
        const lines = (pending[stream] + chunk.toString("utf8")).split("\n");
        pending[stream] = lines.pop() ?? "";
        for (const line of lines) emit(stream, line);
      };
      child.stdout.on("data", collect("stdout"));
      child.stderr.on("data", collect("stderr"));
      child.on("error", reject);
      child.on("close", (code) => {
        for (const stream of ["stdout", "stderr"] as const) {
          if (pending[stream] !== "") emit(stream, pending[stream]);
        }
        resolve({ code: code ?? 1, ...out });
      });
    });
}

/** The JSON document in a command's output, skipping banners and warnings before it. */
export function parseJsonOutput(stdout: string): unknown {
  const lines = stdout.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]?.trimStart() ?? "";
    if (!line.startsWith("[") && !line.startsWith("{")) continue;
    try {
      return JSON.parse(lines.slice(i).join("\n"));
    } catch {}
  }
  throw new Error("the command printed no JSON");
}
