import type { ArtifactFormat, ProviderInfo } from "../types.js";
import { commandExists, execCommand } from "../util/exec.js";
import type { Provider } from "./provider.js";
import { detectCli } from "./provider.js";

function firstVersion(out: string): string | undefined {
  // Prefer a version that follows the word "version" or sits in quotes.
  const labelled = out.match(/version[ "\t:v]*?(\d+\.\d+(?:\.\d+)?)/i);
  if (labelled) return labelled[1];
  // Otherwise take the first plain version, ignoring IPv4-looking sequences.
  const cleaned = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, " ");
  const m = cleaned.match(/\b\d+\.\d+(?:\.\d+)?\b/);
  return m ? m[0] : undefined;
}

/** YARA: pattern matching for files (defensive signature scanning). */
const yara: Provider = {
  name: "yara",
  description: "Pattern/signature scanning of files with YARA rules",
  supports: ["pe", "elf", "macho", "data", "zip", "jar", "apk", "wasm"] as ArtifactFormat[],
  capabilities: ["scan"],
  note: "Install YARA (https://virustotal.github.io/yara/) and ensure `yara` is on PATH.",
  detect: () => detectCli(yara, "yara", "--version", firstVersion),
};

/** radare2: open-source reverse-engineering framework. */
const radare2: Provider = {
  name: "radare2",
  description: "Disassembly and analysis via the radare2 framework",
  supports: ["pe", "elf", "macho", "wasm", "data"] as ArtifactFormat[],
  capabilities: ["disassemble", "analyze", "symbols"],
  note: "Install radare2 (https://rada.re) and ensure `r2` is on PATH.",
  detect: () => detectCli(radare2, "r2", "-v", firstVersion),
};

/** Capstone disassembly framework (via its Python package). */
const capstone: Provider = {
  name: "capstone",
  description: "Multi-architecture disassembly via the Capstone engine (Python)",
  supports: ["pe", "elf", "macho", "data"] as ArtifactFormat[],
  capabilities: ["disassemble"],
  note: "Install with `pip install capstone` and ensure `python3` is on PATH.",
  async detect(): Promise<ProviderInfo> {
    const res = await execCommand("python3", ["-c", "import capstone;print(capstone.__version__)"], {
      timeoutMs: 10_000,
    });
    const available = res.code === 0 && !res.spawnError;
    return {
      name: capstone.name,
      description: capstone.description,
      available,
      ...(available ? { version: res.stdout.trim() } : { note: capstone.note }),
      supports: capstone.supports,
      capabilities: capstone.capabilities,
    };
  },
};

/** LIEF: cross-format executable parsing library (via its Python package). */
const lief: Provider = {
  name: "lief",
  description: "Cross-format binary parsing/abstraction via the LIEF library (Python)",
  supports: ["pe", "elf", "macho"] as ArtifactFormat[],
  capabilities: ["parse", "symbols", "imports", "exports"],
  note: "Install with `pip install lief` and ensure `python3` is on PATH.",
  async detect(): Promise<ProviderInfo> {
    const res = await execCommand("python3", ["-c", "import lief;print(lief.__version__)"], { timeoutMs: 10_000 });
    const available = res.code === 0 && !res.spawnError;
    return {
      name: lief.name,
      description: lief.description,
      available,
      ...(available ? { version: res.stdout.trim() } : { note: lief.note }),
      supports: lief.supports,
      capabilities: lief.capabilities,
    };
  },
};

/** Ghidra headless analyzer (for authorized, in-depth static analysis). */
const ghidra: Provider = {
  name: "ghidra",
  description: "Decompilation and deep static analysis via Ghidra (headless)",
  supports: ["pe", "elf", "macho"] as ArtifactFormat[],
  capabilities: ["decompile", "analyze", "symbols"],
  note: "Install Ghidra and set GHIDRA_INSTALL_DIR, or put analyzeHeadless on PATH.",
  async detect(): Promise<ProviderInfo> {
    const base: Omit<ProviderInfo, "available"> = {
      name: ghidra.name,
      description: ghidra.description,
      supports: ghidra.supports,
      capabilities: ghidra.capabilities,
    };
    const dir = process.env.GHIDRA_INSTALL_DIR;
    if (dir) {
      return { ...base, available: true, note: `configured via GHIDRA_INSTALL_DIR=${dir}` };
    }
    const res = await commandExists("analyzeHeadless", "-help");
    const available = !res.spawnError;
    return available ? { ...base, available } : { ...base, available, note: ghidra.note };
  },
};

/** JADX: Android APK/DEX to Java decompiler. */
const jadx: Provider = {
  name: "jadx",
  description: "Android APK/DEX decompilation to Java via JADX",
  supports: ["apk", "dex", "jar"] as ArtifactFormat[],
  capabilities: ["decompile", "manifest"],
  note: "Install JADX (https://github.com/skylot/jadx) and ensure `jadx` is on PATH.",
  detect: () => detectCli(jadx, "jadx", "--version", firstVersion),
};

/** Java runtime, used by several JVM-oriented providers. */
const java: Provider = {
  name: "java",
  description: "Java runtime (enables JVM-based providers and .class inspection)",
  supports: ["jar", "class"] as ArtifactFormat[],
  capabilities: ["run-jvm-tools"],
  note: "Install a JDK/JRE and ensure `java` is on PATH.",
  detect: () => detectCli(java, "java", "-version", firstVersion),
};

/** All providers known to the toolkit. */
export const PROVIDERS: Provider[] = [yara, radare2, capstone, lief, ghidra, jadx, java];

/** Detect every provider concurrently and return their capability reports. */
export async function detectProviders(): Promise<ProviderInfo[]> {
  const infos = await Promise.all(
    PROVIDERS.map((p) =>
      p.detect().catch(
        (e): ProviderInfo => ({
          name: p.name,
          description: p.description,
          available: false,
          supports: p.supports,
          capabilities: p.capabilities,
          note: `detection failed: ${(e as Error).message}`,
        }),
      ),
    ),
  );
  return infos;
}

/** Providers applicable to a given artifact format (regardless of availability). */
export function providersForFormat(format: ArtifactFormat): Provider[] {
  return PROVIDERS.filter((p) => p.supports.includes(format));
}
