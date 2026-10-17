/**
 * Core data model for SpectraProbe.
 *
 * Everything the toolkit produces is expressed in terms of a small set of
 * structures: an {@link Artifact} (an identified input), {@link Evidence}
 * (raw observations from a tool), and {@link Finding} (an interpreted
 * conclusion that cites its evidence). Keeping these explicit is what lets the
 * platform distinguish verified facts from inference.
 */

/** Broad category of a recognised input. */
export type ArtifactFormat =
  | "pe" // Windows PE executable / DLL
  | "elf" // Linux/Unix ELF
  | "macho" // macOS Mach-O
  | "wasm" // WebAssembly binary
  | "zip" // generic ZIP container
  | "jar" // Java archive
  | "apk" // Android package
  | "electron-asar" // Electron asar archive
  | "dotnet" // .NET assembly (PE subtype)
  | "javascript" // single JS/TS file
  | "js-project" // directory containing a Node/JS project
  | "class" // single Java .class file
  | "dex" // Android Dalvik executable
  | "text" // readable text
  | "data" // recognised but unparsed binary
  | "directory" // generic directory
  | "unknown";

/** How confident a statement is. */
export type Confidence = "high" | "medium" | "low";

/** Whether a statement is an established fact, an inference, or an open question. */
export type Certainty = "verified" | "inferred" | "unknown";

/** A cryptographic/structural digest set for an artifact. */
export interface Hashes {
  sha256: string;
  sha1: string;
  md5: string;
  /** CRC32 as a zero-padded 8-char hex string (useful for archive cross-checks). */
  crc32: string;
}

/** An identified input to the analysis engine. */
export interface Artifact {
  /** Stable id derived from the content hash (first 16 hex chars of sha256). */
  id: string;
  /** Absolute path on disk at ingestion time. */
  path: string;
  /** Basename. */
  name: string;
  /** Detected high-level format. */
  format: ArtifactFormat;
  /** Human label, e.g. "PE32+ executable (x86-64)". */
  description: string;
  /** Best-guess media type. */
  mime: string;
  /** Size in bytes (0 for directories). */
  size: number;
  /** Present for files, absent for directories. */
  hashes?: Hashes;
  /** Shannon entropy of the whole file in bits/byte (0..8), when computed. */
  entropy?: number;
  /** True when the input is a directory. */
  isDirectory: boolean;
  /** Analyses that are applicable to this artifact. */
  capabilities: string[];
  ingestedAt: string;
}

/** A raw observation produced by a specific analysis step. */
export interface Evidence {
  id: string;
  /** Which engine/provider produced it, e.g. "static:pe", "provider:yara". */
  source: string;
  /** Where in the artifact it was seen (offset, section, file path, node...). */
  location?: string;
  /** Machine-readable payload. */
  data: unknown;
  createdAt: string;
}

/** An interpreted conclusion that must reference supporting evidence. */
export interface Finding {
  id: string;
  /** Artifact this finding is about. */
  artifactId: string;
  /** Short category slug, e.g. "import", "string", "capability", "integrity". */
  category: string;
  /** One-line human statement. */
  title: string;
  /** Longer explanation. */
  detail?: string;
  certainty: Certainty;
  confidence: Confidence;
  /** Tool/engine that generated it. */
  source: string;
  /** Ids of {@link Evidence} records that back this finding. */
  evidence: string[];
  /** Explicit statement of what is NOT known or could be wrong. */
  limitations?: string;
  createdAt: string;
}

/** A node in the knowledge graph. */
export interface GraphNode {
  id: string;
  kind:
    | "artifact"
    | "file"
    | "module"
    | "package"
    | "symbol"
    | "import"
    | "export"
    | "section"
    | "string"
    | "indicator"
    | "finding";
  label: string;
  attributes?: Record<string, unknown>;
}

/** A directed relationship between two graph nodes. */
export interface GraphEdge {
  from: string;
  to: string;
  kind:
    | "contains"
    | "imports"
    | "exports"
    | "depends-on"
    | "references"
    | "defines"
    | "derived-from";
  attributes?: Record<string, unknown>;
}

/** The result of analysing one artifact. */
export interface AnalysisReport {
  tool: string;
  version: string;
  artifact: Artifact;
  findings: Finding[];
  evidence: Evidence[];
  /** Capabilities that were requested/applicable but could not run, with reasons. */
  warnings: string[];
  /** Analyses that actually ran. */
  ranAnalyses: string[];
  startedAt: string;
  finishedAt: string;
  durationMs: number;
}

/** Capability descriptor reported by a pluggable provider. */
export interface ProviderInfo {
  name: string;
  description: string;
  /** Whether the backing tool/library is installed and usable right now. */
  available: boolean;
  version?: string;
  /** Artifact formats this provider can act on. */
  supports: ArtifactFormat[];
  /** Named capabilities, e.g. ["scan", "disassemble"]. */
  capabilities: string[];
  /** If unavailable, why, and how to install it. */
  note?: string;
}

/** Options accepted by the static analysis orchestrator. */
export interface AnalyzeOptions {
  /** Limit the analyses that run (default: all applicable). */
  only?: string[];
  /** Minimum length for extracted strings. */
  minStringLength?: number;
  /** Max number of strings to retain. */
  maxStrings?: number;
  /** Walk directories recursively (js-project ingestion). */
  recursive?: boolean;
  /** Cap on files scanned inside a project/archive. */
  maxFiles?: number;
}
