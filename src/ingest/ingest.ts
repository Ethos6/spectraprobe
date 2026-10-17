import { readFile, stat } from "node:fs/promises";
import { basename, resolve } from "node:path";
import type { Artifact, ArtifactFormat } from "../types.js";
import { hashBuffer, shortId } from "../util/hash.js";
import { shannonEntropy } from "../util/entropy.js";
import { identifyBuffer } from "./identify.js";

/** Which named analyses are applicable to each format. */
const CAPABILITY_MAP: Record<ArtifactFormat, string[]> = {
  pe: ["metadata", "strings", "imports", "exports", "symbols", "sections", "resources", "entropy"],
  elf: ["metadata", "strings", "imports", "exports", "symbols", "sections", "dependencies", "entropy"],
  macho: ["metadata", "strings", "symbols", "sections", "dependencies", "entropy"],
  wasm: ["metadata", "strings", "imports", "exports", "sections"],
  zip: ["metadata", "strings", "resources", "entropy"],
  jar: ["metadata", "strings", "resources", "dependencies", "manifest"],
  apk: ["metadata", "strings", "resources", "manifest"],
  "electron-asar": ["metadata", "strings", "resources"],
  dotnet: ["metadata", "strings", "sections", "resources"],
  javascript: ["metadata", "strings", "javascript"],
  "js-project": ["metadata", "javascript", "dependencies"],
  class: ["metadata", "strings"],
  dex: ["metadata", "strings"],
  text: ["metadata", "strings"],
  data: ["metadata", "strings", "entropy"],
  directory: ["metadata"],
  unknown: ["metadata"],
};

const PROJECT_MARKERS = ["package.json"];

/** Largest file we will fully load into memory (bytes). */
export const MAX_INGEST_BYTES = 512 * 1024 * 1024;

export interface IngestResult {
  artifact: Artifact;
  /** File bytes (absent for directories). */
  buffer?: Buffer;
}

/**
 * Identify a path and build an {@link Artifact}. For directories, detects a
 * JS/Node project by the presence of a package.json.
 */
export async function ingestTarget(targetPath: string): Promise<IngestResult> {
  const abs = resolve(targetPath);
  const info = await stat(abs);
  const now = new Date().toISOString();

  if (info.isDirectory()) {
    let format: ArtifactFormat = "directory";
    let description = "Directory";
    for (const marker of PROJECT_MARKERS) {
      try {
        await stat(resolve(abs, marker));
        format = "js-project";
        description = "JavaScript/Node project";
        break;
      } catch {
        /* marker absent */
      }
    }
    const artifact: Artifact = {
      id: shortId(hashBuffer(Buffer.from(abs)).sha256),
      path: abs,
      name: basename(abs),
      format,
      description,
      mime: "inode/directory",
      size: 0,
      isDirectory: true,
      capabilities: CAPABILITY_MAP[format],
      ingestedAt: now,
    };
    return { artifact };
  }

  if (info.size > MAX_INGEST_BYTES) {
    throw new Error(
      `File too large to ingest (${info.size} bytes > ${MAX_INGEST_BYTES}). ` +
        `Increase the limit only on trusted hardware.`,
    );
  }

  const buffer = await readFile(abs);
  const ident = identifyBuffer(buffer, basename(abs));
  const hashes = hashBuffer(buffer);
  const entropy = shannonEntropy(buffer);

  const artifact: Artifact = {
    id: shortId(hashes.sha256),
    path: abs,
    name: basename(abs),
    format: ident.format,
    description: ident.description,
    mime: ident.mime,
    size: buffer.length,
    hashes,
    entropy,
    isDirectory: false,
    capabilities: CAPABILITY_MAP[ident.format] ?? CAPABILITY_MAP.unknown,
    ingestedAt: now,
  };
  return { artifact, buffer };
}

/** Identify an in-memory buffer without touching disk (used by the MCP layer). */
export function ingestBuffer(buffer: Buffer, name: string): IngestResult {
  const ident = identifyBuffer(buffer, name);
  const hashes = hashBuffer(buffer);
  const artifact: Artifact = {
    id: shortId(hashes.sha256),
    path: name,
    name,
    format: ident.format,
    description: ident.description,
    mime: ident.mime,
    size: buffer.length,
    hashes,
    entropy: shannonEntropy(buffer),
    isDirectory: false,
    capabilities: CAPABILITY_MAP[ident.format] ?? CAPABILITY_MAP.unknown,
    ingestedAt: new Date().toISOString(),
  };
  return { artifact, buffer };
}

export { CAPABILITY_MAP };
