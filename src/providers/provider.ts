import type { ArtifactFormat, ProviderInfo } from "../types.js";

/**
 * A provider adapts an external, independently-licensed analysis tool (for
 * example a disassembler or a signature scanner) to SpectraProbe. The core
 * never bundles these tools; a provider only detects whether one is installed
 * and reports what it can do, so the platform degrades gracefully when it is
 * absent. Each provider must honour the licence of the tool it wraps.
 */
export interface Provider {
  readonly name: string;
  readonly description: string;
  readonly supports: ArtifactFormat[];
  readonly capabilities: string[];
  /** Installation / licensing note shown when the tool is unavailable. */
  readonly note: string;
  /** Detect availability and version; must never throw. */
  detect(): Promise<ProviderInfo>;
}

/** Shared detect() implementation for providers that probe a CLI's version. */
export async function detectCli(
  provider: Omit<Provider, "detect">,
  command: string,
  versionArg: string,
  parseVersion: (out: string) => string | undefined,
): Promise<ProviderInfo> {
  const { commandExists } = await import("../util/exec.js");
  const res = await commandExists(command, versionArg);
  const available = !res.spawnError && !res.timedOut && (res.code === 0 || res.stdout.length > 0 || res.stderr.length > 0) && res.code !== null;
  const versionText = parseVersion(`${res.stdout}\n${res.stderr}`);
  return {
    name: provider.name,
    description: provider.description,
    available,
    ...(available && versionText ? { version: versionText } : {}),
    supports: provider.supports,
    capabilities: provider.capabilities,
    ...(available ? {} : { note: provider.note }),
  };
}
