import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

export interface Command {
  /** `wrangler` runs the app's own pinned Wrangler; `pnpm` runs a package script. */
  bin: "wrangler" | "pnpm";
  /** The Worker's directory; Wrangler finds its config there. */
  cwd: string;
  args: string[];
  /** Keep stdout for parsing instead of printing it. stderr is always printed. */
  capture?: boolean;
}

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

const TOKEN_PATTERN = /\b(?:cfat|cfut|cfk|cfoat)_[A-Za-z0-9_-]{8,}/g;

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
   * `none` strips every credential from the environment of child processes
   * (dry run); `token` keeps only CLOUDFLARE_API_TOKEN, so Wrangler cannot
   * fall back to a Global API Key.
   */
  credentials: "none" | "token";
  /** Values that must never be printed, such as the API token. */
  secrets: () => readonly string[];
  print?: (stream: "stdout" | "stderr", line: string) => void;
}

/**
 * Runs commands with stdin closed, so Wrangler never prompts and never writes
 * resource IDs back into a config. All output passes through `redact`.
 */
export function processRunner(options: RunnerOptions): Runner {
  const print =
    options.print ??
    ((stream, line) => (stream === "stdout" ? process.stdout : process.stderr).write(`${line}\n`));
  return (command) =>
    new Promise((resolve, reject) => {
      const file =
        command.bin === "wrangler" ? join(command.cwd, "node_modules", ".bin", "wrangler") : "pnpm";
      if (command.bin === "wrangler" && !existsSync(file)) {
        reject(new Error(`${file} not found; run pnpm install first`));
        return;
      }
      const env: NodeJS.ProcessEnv = { ...process.env, WRANGLER_SEND_METRICS: "false" };
      for (const name of CREDENTIAL_VARS) {
        if (options.credentials === "none" || name !== "CLOUDFLARE_API_TOKEN") delete env[name];
      }
      const child = spawn(file, command.args, {
        cwd: command.cwd,
        env,
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
