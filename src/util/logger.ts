/** Minimal structured logger that writes to stderr so stdout stays clean for data. */

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 99,
};

let current: LogLevel = (process.env.SPECTRA_LOG as LogLevel) || "info";

export function setLogLevel(level: LogLevel): void {
  current = level;
}

function emit(level: Exclude<LogLevel, "silent">, msg: string, meta?: unknown): void {
  if (ORDER[level] < ORDER[current]) return;
  const line =
    meta === undefined
      ? `[spectra:${level}] ${msg}`
      : `[spectra:${level}] ${msg} ${safeJson(meta)}`;
  process.stderr.write(line + "\n");
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export const log = {
  debug: (msg: string, meta?: unknown) => emit("debug", msg, meta),
  info: (msg: string, meta?: unknown) => emit("info", msg, meta),
  warn: (msg: string, meta?: unknown) => emit("warn", msg, meta),
  error: (msg: string, meta?: unknown) => emit("error", msg, meta),
};
