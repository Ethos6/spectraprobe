import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import type { AnalysisReport, AnalyzeOptions, Artifact } from "../types.js";
import { VERSION } from "../version.js";
import { EvidenceCollector } from "../evidence/collector.js";
import { entropyHint } from "../util/entropy.js";
import { extractStrings, indicatorsFromText } from "../util/strings.js";
import type { IngestResult } from "../ingest/ingest.js";
import { ingestTarget } from "../ingest/ingest.js";
import { parsePe } from "../formats/pe.js";
import { parseElf } from "../formats/elf.js";
import { parseMacho } from "../formats/macho.js";
import { parseWasm } from "../formats/wasm.js";
import { readZip, readZipText, type ZipListing } from "../formats/zip.js";
import { analyzeJavaScriptSource } from "./javascript.js";

const DEFAULT_MIN_STRING = 4;
const DEFAULT_MAX_STRINGS = 5000;
const DEFAULT_MAX_FILES = 2000;

/** Run every applicable static analysis for an already-ingested artifact. */
export async function analyzeArtifact(
  ingest: IngestResult,
  opts: AnalyzeOptions = {},
): Promise<AnalysisReport> {
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const { artifact, buffer } = ingest;
  const col = new EvidenceCollector(artifact.id);
  const warnings: string[] = [];
  const ran: string[] = [];

  const want = (name: string): boolean =>
    (!opts.only || opts.only.includes(name)) && artifact.capabilities.includes(name);

  try {
    if (buffer) {
      runStrings(buffer, col, opts, want, ran);
      runEntropy(artifact, col, want, ran);
      switch (artifact.format) {
        case "pe":
          runPe(buffer, col, warnings, ran);
          break;
        case "elf":
          runElf(buffer, col, warnings, ran);
          break;
        case "macho":
          runMacho(buffer, col, warnings, ran);
          break;
        case "wasm":
          runWasm(buffer, col, warnings, ran);
          break;
        case "zip":
        case "jar":
        case "apk":
          runArchive(artifact, buffer, col, warnings, ran);
          break;
        case "javascript":
          runSingleJs(artifact, buffer, col, ran);
          break;
        default:
          break;
      }
    } else if (artifact.isDirectory) {
      await runProject(artifact, col, warnings, ran, opts);
    }
  } catch (e) {
    warnings.push(`analysis error: ${(e as Error).message}`);
  }

  const finishedAt = new Date().toISOString();
  return {
    tool: "spectraprobe",
    version: VERSION,
    artifact,
    findings: col.findings,
    evidence: col.evidence,
    warnings,
    ranAnalyses: ran,
    startedAt,
    finishedAt,
    durationMs: Date.now() - t0,
  };
}

/** Convenience: ingest a path then analyse it. */
export async function analyzePath(path: string, opts: AnalyzeOptions = {}): Promise<AnalysisReport> {
  const ingest = await ingestTarget(path);
  return analyzeArtifact(ingest, opts);
}

type WantFn = (name: string) => boolean;

function runStrings(
  buffer: Buffer,
  col: EvidenceCollector,
  opts: AnalyzeOptions,
  want: WantFn,
  ran: string[],
): void {
  if (!want("strings")) return;
  ran.push("strings");
  const strings = extractStrings(buffer, {
    minLength: opts.minStringLength ?? DEFAULT_MIN_STRING,
    max: opts.maxStrings ?? DEFAULT_MAX_STRINGS,
  });
  const values = strings.map((s) => s.value);
  const evId = col.addEvidence("static:strings", { count: strings.length, sample: values.slice(0, 200) });
  col.addFinding({
    category: "strings",
    title: `Extracted ${strings.length} printable strings`,
    certainty: "verified",
    confidence: "high",
    source: "static:strings",
    evidence: [evId],
    ...(strings.length >= (opts.maxStrings ?? DEFAULT_MAX_STRINGS)
      ? { limitations: "string list was capped; rerun with a higher limit for the full set" }
      : {}),
  });

  const ind = indicatorsFromText(values.join("\n"));
  for (const [kind, list] of Object.entries(ind) as [keyof typeof ind, string[]][]) {
    if (list.length === 0) continue;
    col.observe({
      category: "indicator",
      title: `${list.length} ${kind} found in strings`,
      certainty: "verified",
      confidence: "medium",
      source: "static:strings",
      data: { kind, values: list },
      limitations:
        "indicators are extracted literally from embedded strings; presence does not imply behaviour",
    });
  }
}

function runEntropy(artifact: Artifact, col: EvidenceCollector, want: WantFn, ran: string[]): void {
  if (!want("entropy") || artifact.entropy === undefined) return;
  ran.push("entropy");
  const hint = entropyHint(artifact.entropy);
  col.observe({
    category: "integrity",
    title: `File entropy ${artifact.entropy} bits/byte — ${hint}`,
    certainty: "verified",
    confidence: artifact.entropy >= 7.2 ? "medium" : "high",
    source: "static:entropy",
    data: { entropy: artifact.entropy, hint },
    limitations: "high entropy suggests compression/packing but is not conclusive",
  });
}

function runPe(buffer: Buffer, col: EvidenceCollector, warnings: string[], ran: string[]): void {
  ran.push("metadata", "imports", "exports", "sections");
  const pe = parsePe(buffer);
  warnings.push(...pe.warnings);
  col.observe({
    category: "metadata",
    title: `PE ${pe.is64 ? "PE32+" : "PE32"} for ${pe.machine}${pe.isDll ? " (DLL)" : ""}${pe.dotnet ? " [.NET]" : ""}`,
    detail: `subsystem: ${pe.subsystem}; entry RVA 0x${pe.entryPointRva.toString(16)}; image base ${pe.imageBase}; compiled ${pe.timeDateIso ?? "unknown"}`,
    certainty: "verified",
    confidence: "high",
    source: "static:pe",
    data: {
      machine: pe.machine,
      is64: pe.is64,
      isDll: pe.isDll,
      subsystem: pe.subsystem,
      entryPointRva: pe.entryPointRva,
      imageBase: pe.imageBase,
      timeDateIso: pe.timeDateIso,
      dotnet: pe.dotnet,
      dllCharacteristics: pe.dllCharacteristics,
    },
  });
  for (const s of pe.sections) {
    col.addEvidence("static:pe", s, `section:${s.name}`);
  }
  col.observe({
    category: "section",
    title: `${pe.sections.length} PE sections`,
    certainty: "verified",
    confidence: "high",
    source: "static:pe",
    data: pe.sections,
  });
  const importCount = pe.imports.reduce((n, i) => n + i.functions.length, 0);
  if (pe.imports.length > 0) {
    col.observe({
      category: "import",
      title: `Imports ${importCount} functions from ${pe.imports.length} libraries`,
      certainty: "verified",
      confidence: "high",
      source: "static:pe",
      data: pe.imports,
    });
  }
  if (pe.exports.length > 0) {
    col.observe({
      category: "export",
      title: `Exports ${pe.exports.length} symbols`,
      certainty: "verified",
      confidence: "high",
      source: "static:pe",
      data: pe.exports,
    });
  }
  col.observe({
    category: "hardening",
    title: `Security flags: ${pe.dllCharacteristics.join(", ") || "none detected"}`,
    certainty: "verified",
    confidence: "medium",
    source: "static:pe",
    data: pe.dllCharacteristics,
    limitations: "flags reflect declared mitigations; they do not guarantee runtime enforcement",
  });
}

function runElf(buffer: Buffer, col: EvidenceCollector, warnings: string[], ran: string[]): void {
  ran.push("metadata", "sections", "symbols", "dependencies");
  const elf = parseElf(buffer);
  warnings.push(...elf.warnings);
  col.observe({
    category: "metadata",
    title: `${elf.class} ${elf.type} for ${elf.machine}`,
    detail: `entry ${elf.entry}; ${elf.endianness}-endian; ${elf.stripped ? "stripped" : "has symbol table"}`,
    certainty: "verified",
    confidence: "high",
    source: "static:elf",
    data: {
      class: elf.class,
      type: elf.type,
      machine: elf.machine,
      entry: elf.entry,
      stripped: elf.stripped,
      soname: elf.soname,
    },
  });
  col.observe({
    category: "section",
    title: `${elf.sections.length} ELF sections`,
    certainty: "verified",
    confidence: "high",
    source: "static:elf",
    data: elf.sections,
  });
  if (elf.neededLibraries.length > 0) {
    col.observe({
      category: "dependency",
      title: `Links ${elf.neededLibraries.length} shared libraries`,
      detail: elf.neededLibraries.join(", "),
      certainty: "verified",
      confidence: "high",
      source: "static:elf",
      data: { needed: elf.neededLibraries, rpath: elf.rpath },
    });
  }
  if (elf.dynamicSymbols.length > 0) {
    col.observe({
      category: "symbol",
      title: `${elf.dynamicSymbols.length} dynamic symbols`,
      certainty: "verified",
      confidence: "high",
      source: "static:elf",
      data: elf.dynamicSymbols.slice(0, 2000),
      ...(elf.dynamicSymbols.length > 2000 ? { limitations: "symbol list truncated to 2000" } : {}),
    });
  }
}

function runMacho(buffer: Buffer, col: EvidenceCollector, warnings: string[], ran: string[]): void {
  ran.push("metadata", "sections", "dependencies");
  const result = parseMacho(buffer);
  col.addEvidence("static:macho", { fat: result.fat, slices: result.architectures.length });
  result.architectures.forEach((m, i) => {
    warnings.push(...m.warnings);
    const label = result.fat ? ` [slice ${i + 1}/${result.architectures.length}]` : "";
    col.observe({
      category: "metadata",
      title: `Mach-O ${m.is64 ? "64-bit" : "32-bit"} ${m.fileType} for ${m.cpuType}${label}`,
      detail: `${m.loadCommandCount} load commands; UUID ${m.uuid ?? "none"}${m.minOs ? `; min OS ${m.minOs}` : ""}`,
      certainty: "verified",
      confidence: "high",
      source: "static:macho",
      data: { cpuType: m.cpuType, fileType: m.fileType, uuid: m.uuid, is64: m.is64, minOs: m.minOs },
    });
    if (m.linkedLibraries.length > 0) {
      col.observe({
        category: "dependency",
        title: `Links ${m.linkedLibraries.length} dynamic libraries${label}`,
        certainty: "verified",
        confidence: "high",
        source: "static:macho",
        data: m.linkedLibraries,
      });
    }
    if (m.sections.length > 0) {
      col.observe({
        category: "section",
        title: `${m.sections.length} Mach-O sections${label}`,
        certainty: "verified",
        confidence: "high",
        source: "static:macho",
        data: m.sections,
      });
    }
  });
}

function runWasm(buffer: Buffer, col: EvidenceCollector, warnings: string[], ran: string[]): void {
  ran.push("metadata", "imports", "exports", "sections");
  const w = parseWasm(buffer);
  warnings.push(...w.warnings);
  col.observe({
    category: "metadata",
    title: `WebAssembly module (version ${w.version}) with ${w.sections.length} sections`,
    certainty: "verified",
    confidence: "high",
    source: "static:wasm",
    data: { version: w.version, sections: w.sections, customSections: w.customSections },
  });
  if (w.imports.length > 0) {
    col.observe({
      category: "import",
      title: `Imports ${w.imports.length} entries`,
      certainty: "verified",
      confidence: "high",
      source: "static:wasm",
      data: w.imports,
    });
  }
  if (w.exports.length > 0) {
    col.observe({
      category: "export",
      title: `Exports ${w.exports.length} entries`,
      certainty: "verified",
      confidence: "high",
      source: "static:wasm",
      data: w.exports,
    });
  }
}

function runArchive(
  artifact: Artifact,
  buffer: Buffer,
  col: EvidenceCollector,
  warnings: string[],
  ran: string[],
): void {
  ran.push("metadata", "resources");
  let listing: ZipListing;
  try {
    listing = readZip(buffer);
  } catch (e) {
    warnings.push(`archive parse failed: ${(e as Error).message}`);
    return;
  }
  const files = listing.entries.filter((e) => !e.isDirectory);
  col.observe({
    category: "resource",
    title: `Archive contains ${files.length} files`,
    certainty: "verified",
    confidence: "high",
    source: "static:zip",
    data: { entries: files.slice(0, 1000).map((e) => ({ name: e.name, size: e.uncompressedSize })) },
    ...(listing.truncated ? { limitations: "entry list truncated" } : {}),
  });

  if (artifact.format === "jar") {
    const manifest = readZipText(buffer, listing, "META-INF/MANIFEST.MF");
    if (manifest) {
      ran.push("manifest");
      col.observe({
        category: "manifest",
        title: "JAR manifest (META-INF/MANIFEST.MF)",
        certainty: "verified",
        confidence: "high",
        source: "static:jar",
        data: { manifest: manifest.slice(0, 4000) },
      });
    }
    const classes = files.filter((e) => e.name.endsWith(".class")).length;
    col.observe({
      category: "metadata",
      title: `${classes} compiled Java classes`,
      certainty: "verified",
      confidence: "high",
      source: "static:jar",
      data: { classes },
    });
  }

  if (artifact.format === "apk") {
    ran.push("manifest");
    const hasManifest = files.some((e) => e.name === "AndroidManifest.xml");
    const dexCount = files.filter((e) => /^classes\d*\.dex$/.test(e.name)).length;
    col.observe({
      category: "metadata",
      title: `Android package: ${dexCount} DEX file(s), manifest ${hasManifest ? "present" : "missing"}`,
      certainty: "verified",
      confidence: "high",
      source: "static:apk",
      data: { dexCount, hasManifest },
      limitations:
        "AndroidManifest.xml is stored as binary XML; decoding attribute values needs the JADX/aapt provider",
    });
  }
}

function runSingleJs(artifact: Artifact, buffer: Buffer, col: EvidenceCollector, ran: string[]): void {
  ran.push("javascript");
  const analysis = analyzeJavaScriptSource(buffer.toString("utf8"), artifact.name);
  col.observe({
    category: "javascript",
    title: `${analysis.language} source: ${analysis.functionCount} functions, ${analysis.imports.length + analysis.requires.length} module references (${analysis.parser})`,
    detail:
      analysis.capabilityHints.length > 0
        ? `capability references: ${analysis.capabilityHints.join(", ")}`
        : undefined,
    certainty: analysis.parser === "acorn-ast" ? "verified" : "inferred",
    confidence: analysis.parser === "acorn-ast" ? "high" : "medium",
    source: "static:javascript",
    data: analysis,
    ...(analysis.parseError ? { limitations: `AST parse failed, used fallback: ${analysis.parseError}` } : {}),
  });
}

async function runProject(
  artifact: Artifact,
  col: EvidenceCollector,
  warnings: string[],
  ran: string[],
  opts: AnalyzeOptions,
): Promise<void> {
  ran.push("metadata");
  const root = artifact.path;

  // package.json dependencies
  try {
    const pkgRaw = await readFile(resolve(root, "package.json"), "utf8");
    const pkg = JSON.parse(pkgRaw) as Record<string, unknown>;
    ran.push("dependencies");
    const deps = Object.keys((pkg.dependencies as object) ?? {});
    const devDeps = Object.keys((pkg.devDependencies as object) ?? {});
    col.observe({
      category: "dependency",
      title: `package.json: ${deps.length} runtime, ${devDeps.length} dev dependencies`,
      detail: `name: ${String(pkg.name ?? "?")}@${String(pkg.version ?? "?")}`,
      certainty: "verified",
      confidence: "high",
      source: "static:project",
      data: { name: pkg.name, version: pkg.version, dependencies: deps, devDependencies: devDeps },
    });
  } catch (e) {
    warnings.push(`package.json not read: ${(e as Error).message}`);
  }

  // Walk JS/TS sources (bounded)
  const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;
  const sourceFiles = await walkSources(root, maxFiles);
  if (sourceFiles.length === 0) return;
  ran.push("javascript");

  const moduleGraph: Record<string, string[]> = {};
  const capabilityHits: Record<string, string[]> = {};
  let evalUsers = 0;
  for (const file of sourceFiles) {
    try {
      const src = await readFile(file, "utf8");
      const rel = relative(root, file);
      const a = analyzeJavaScriptSource(src, rel);
      moduleGraph[rel] = [...a.imports, ...a.requires];
      if (a.usesEval) evalUsers++;
      for (const h of a.capabilityHints) (capabilityHits[h] ??= []).push(rel);
    } catch {
      /* skip unreadable file */
    }
  }

  col.observe({
    category: "javascript",
    title: `Analysed ${sourceFiles.length} JS/TS source files`,
    certainty: "verified",
    confidence: "high",
    source: "static:project",
    data: { fileCount: sourceFiles.length, moduleGraph },
    ...(sourceFiles.length >= maxFiles ? { limitations: `file walk capped at ${maxFiles}` } : {}),
  });

  for (const [capability, filesUsing] of Object.entries(capabilityHits)) {
    col.observe({
      category: "capability",
      title: `${capability} referenced in ${filesUsing.length} file(s)`,
      certainty: "inferred",
      confidence: "medium",
      source: "static:project",
      data: { capability, files: filesUsing.slice(0, 100) },
      limitations: "a static reference to a module is not evidence that the behaviour occurs at runtime",
    });
  }
  if (evalUsers > 0) {
    col.observe({
      category: "capability",
      title: `Dynamic code evaluation (eval/new Function) in ${evalUsers} file(s)`,
      certainty: "inferred",
      confidence: "medium",
      source: "static:project",
      data: { files: evalUsers },
      limitations: "flagged for review; dynamic evaluation has many legitimate uses",
    });
  }
}

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "out", ".next", "coverage", ".cache"]);
const SOURCE_EXT = new Set(["js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts"]);

async function walkSources(root: string, limit: number): Promise<string[]> {
  const out: string[] = [];
  const stack: string[] = [root];
  while (stack.length > 0 && out.length < limit) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (out.length >= limit) break;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) stack.push(full);
      } else if (entry.isFile()) {
        const ext = entry.name.toLowerCase().split(".").pop() ?? "";
        if (SOURCE_EXT.has(ext)) {
          try {
            const s = await stat(full);
            if (s.size < 5 * 1024 * 1024) out.push(full);
          } catch {
            /* ignore */
          }
        }
      }
    }
  }
  return out;
}
