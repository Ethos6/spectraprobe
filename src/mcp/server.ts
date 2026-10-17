/**
 * MCP tool layer for SpectraProbe. Each tool is backed by the same static
 * analysis engine used by the CLI, so results are consistent across interfaces.
 * Tools operate on local file paths and perform static analysis only.
 */
import { VERSION } from "../version.js";
import { analyzePath } from "../analyze/static.js";
import { ingestTarget } from "../ingest/ingest.js";
import { extractStrings } from "../util/strings.js";
import { detectProviders, providersForFormat } from "../providers/external.js";
import { Session } from "../evidence/session.js";
import { toMarkdown, toJson } from "../report/report.js";
import type { AnalysisReport, Finding } from "../types.js";

export interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const pathArg = {
  type: "object",
  properties: { path: { type: "string", description: "Local path to the target file or directory" } },
  required: ["path"],
  additionalProperties: false,
};

export const TOOLS: McpTool[] = [
  { name: "probe_target", description: "Identify an artifact: format, hashes, size, entropy, and which analyses apply.", inputSchema: pathArg },
  { name: "inspect_metadata", description: "Structural metadata for an executable/archive (headers, architecture, sections).", inputSchema: pathArg },
  { name: "extract_strings", description: "Extract printable ASCII/UTF-16 strings and embedded indicators (URLs, IPs, paths).", inputSchema: { type: "object", properties: { path: { type: "string" }, minLength: { type: "number", default: 4 }, max: { type: "number", default: 2000 } }, required: ["path"], additionalProperties: false } },
  { name: "inspect_dependencies", description: "List linked libraries (ELF/Mach-O) or package dependencies (Node/JAR).", inputSchema: pathArg },
  { name: "inspect_symbols", description: "List dynamic/exported symbols where the format supports them.", inputSchema: pathArg },
  { name: "inspect_imports", description: "List imported libraries and functions (PE/WASM).", inputSchema: pathArg },
  { name: "analyze_javascript", description: "Analyse a JS/TS file or project: imports, exports, functions, capability references.", inputSchema: pathArg },
  { name: "inspect_resources", description: "List archive entries / embedded resources (ZIP, JAR, APK).", inputSchema: pathArg },
  { name: "search_evidence", description: "Search findings gathered in this session by text, category, or confidence.", inputSchema: { type: "object", properties: { text: { type: "string" }, category: { type: "string" }, minConfidence: { type: "string", enum: ["low", "medium", "high"] } }, additionalProperties: false } },
  { name: "create_report", description: "Produce a full analysis report for a target in markdown or json.", inputSchema: { type: "object", properties: { path: { type: "string" }, format: { type: "string", enum: ["markdown", "json"], default: "markdown" } }, required: ["path"], additionalProperties: false } },
  { name: "list_providers", description: "List external analysis providers (YARA, radare2, Ghidra, …) and their availability.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "get_analysis_status", description: "Report engine version, session statistics, and analysed artifacts.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
];

function categoryFindings(report: AnalysisReport, categories: string[]): Finding[] {
  return report.findings.filter((f) => categories.includes(f.category));
}

/** Expand findings with their cited evidence payloads for a richer tool result. */
function withEvidence(report: AnalysisReport, findings: Finding[]): unknown[] {
  return findings.map((f) => ({
    title: f.title,
    detail: f.detail,
    category: f.category,
    certainty: f.certainty,
    confidence: f.confidence,
    limitations: f.limitations,
    data: f.evidence.map((eid) => report.evidence.find((e) => e.id === eid)?.data).filter(Boolean),
  }));
}

/** Stateful handler set: keeps an in-memory session so search/report tools work. */
export class SpectraMcp {
  private readonly session = Session.create(":memory:");

  listTools(): McpTool[] {
    return TOOLS;
  }

  async call(name: string, args: Record<string, unknown>): Promise<unknown> {
    switch (name) {
      case "probe_target": {
        const { artifact } = await ingestTarget(requirePath(args));
        return artifact;
      }
      case "inspect_metadata": {
        const report = await this.analyze(requirePath(args));
        return { artifact: report.artifact, findings: withEvidence(report, categoryFindings(report, ["metadata", "section", "hardening", "integrity"])), warnings: report.warnings };
      }
      case "extract_strings": {
        const { buffer } = await ingestTarget(requirePath(args));
        if (!buffer) throw new Error("target is a directory");
        const strings = extractStrings(buffer, { minLength: numArg(args.minLength, 4), max: numArg(args.max, 2000) });
        return { count: strings.length, strings: strings.map((s) => ({ value: s.value, offset: s.offset, encoding: s.encoding })) };
      }
      case "inspect_dependencies": {
        const report = await this.analyze(requirePath(args));
        return { artifact: report.artifact.name, dependencies: withEvidence(report, categoryFindings(report, ["dependency"])) };
      }
      case "inspect_symbols": {
        const report = await this.analyze(requirePath(args));
        return { artifact: report.artifact.name, symbols: withEvidence(report, categoryFindings(report, ["symbol", "export"])) };
      }
      case "inspect_imports": {
        const report = await this.analyze(requirePath(args));
        return { artifact: report.artifact.name, imports: withEvidence(report, categoryFindings(report, ["import"])) };
      }
      case "analyze_javascript": {
        const report = await this.analyze(requirePath(args));
        if (!["javascript", "js-project"].includes(report.artifact.format)) {
          return { note: `target is ${report.artifact.format}, not JavaScript`, artifact: report.artifact.name };
        }
        return { artifact: report.artifact.name, javascript: withEvidence(report, categoryFindings(report, ["javascript", "capability", "dependency"])) };
      }
      case "inspect_resources": {
        const report = await this.analyze(requirePath(args));
        return { artifact: report.artifact.name, resources: withEvidence(report, categoryFindings(report, ["resource", "manifest"])) };
      }
      case "search_evidence": {
        const results = this.session.search({
          ...(typeof args.text === "string" ? { text: args.text } : {}),
          ...(typeof args.category === "string" ? { category: args.category } : {}),
          ...(typeof args.minConfidence === "string" ? { minConfidence: args.minConfidence as "low" | "medium" | "high" } : {}),
        });
        return { count: results.length, findings: results.map((f) => ({ id: f.id, title: f.title, category: f.category, confidence: f.confidence, certainty: f.certainty, artifactId: f.artifactId })) };
      }
      case "create_report": {
        const report = await this.analyze(requirePath(args));
        const format = args.format === "json" ? "json" : "markdown";
        return { format, content: format === "json" ? toJson(report) : toMarkdown(report) };
      }
      case "list_providers":
        return { providers: await detectProviders() };
      case "get_analysis_status":
        return {
          tool: "spectraprobe",
          version: VERSION,
          artifactsAnalyzed: this.session.artifacts.length,
          findings: this.session.findings.length,
          artifacts: this.session.artifacts.map((a) => ({ id: a.id, name: a.name, format: a.format })),
          providersApplicable: Object.fromEntries(
            this.session.artifacts.map((a) => [a.name, providersForFormat(a.format).map((p) => p.name)]),
          ),
        };
      default:
        throw new Error(`unknown tool: ${name}`);
    }
  }

  private async analyze(path: string): Promise<AnalysisReport> {
    const report = await analyzePath(path);
    this.session.addReport(report);
    return report;
  }
}

function requirePath(args: Record<string, unknown>): string {
  if (typeof args.path !== "string" || args.path.length === 0) {
    throw new Error("missing required argument: path");
  }
  return args.path;
}

function numArg(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}
