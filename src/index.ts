/**
 * SpectraProbe — original open-source static software analysis toolkit.
 *
 * Public programmatic API. The same engine backs the CLI and the MCP server.
 */
export { VERSION, TOOL_NAME } from "./version.js";
export * from "./types.js";

export { ingestTarget, ingestBuffer, CAPABILITY_MAP } from "./ingest/ingest.js";
export { identifyBuffer } from "./ingest/identify.js";
export { analyzeArtifact, analyzePath } from "./analyze/static.js";
export { analyzeJavaScriptSource } from "./analyze/javascript.js";
export { diffReports, renderDiff, hasChanges } from "./analyze/diff.js";
export type { ArtifactDiff, SetChange } from "./analyze/diff.js";

export { parsePe } from "./formats/pe.js";
export { parseElf } from "./formats/elf.js";
export { parseMacho } from "./formats/macho.js";
export { parseWasm } from "./formats/wasm.js";
export { readZip, readZipEntry, readZipText } from "./formats/zip.js";

export { extractStrings, indicatorsFromText } from "./util/strings.js";
export { shannonEntropy, entropyHint } from "./util/entropy.js";
export { hashBuffer, crc32 } from "./util/hash.js";

export { EvidenceCollector } from "./evidence/collector.js";
export { buildGraph } from "./evidence/graph.js";
export { Session } from "./evidence/session.js";

export { detectProviders, providersForFormat, PROVIDERS } from "./providers/external.js";
export { renderReport, renderProviders, toJson, toMarkdown, toTerminal } from "./report/report.js";
