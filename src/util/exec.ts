import { spawn } from "node:child_process";

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** True when the executable could not be found / spawned. */
  spawnError?: string;
}

export interface ExecOptions {
  timeoutMs?: number;
  /** Max bytes to retain from stdout/stderr. */
  maxBuffer?: number;
  cwd?: string;
  input?: string;
}

/**
 * Run a command with a hard timeout and bounded output capture. Used only to
 * query and drive external analysis tools; it never runs the target under
 * study. Returns a structured result instead of throwing on non-zero exit.
 */
export function execCommand(
  command: string,
  args: string[] = [],
  opts: ExecOptions = {},
): Promise<ExecResult> {
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const maxBuffer = opts.maxBuffer ?? 8 * 1024 * 1024;

  return new Promise((resolvePromise) => {
    let child;
    try {
      child = spawn(command, args, { cwd: opts.cwd, windowsHide: true });
    } catch (e) {
      resolvePromise({ code: null, stdout: "", stderr: "", timedOut: false, spawnError: (e as Error).message });
      return;
    }

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout?.on("data", (d: Buffer) => {
      if (stdout.length < maxBuffer) stdout += d.toString("utf8");
    });
    child.stderr?.on("data", (d: Buffer) => {
      if (stderr.length < maxBuffer) stderr += d.toString("utf8");
    });
    child.on("error", (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise({ code: null, stdout, stderr, timedOut, spawnError: e.message });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise({ code, stdout, stderr, timedOut });
    });

    if (opts.input !== undefined) {
      child.stdin?.end(opts.input);
    }
  });
}

/** True if a command appears runnable (resolves by attempting a version probe). */
export async function commandExists(command: string, versionArg = "--version"): Promise<ExecResult> {
  return execCommand(command, [versionArg], { timeoutMs: 8_000 });
}
