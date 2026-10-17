import type { AnalysisReport, Finding, ProviderInfo } from "../types.js";

export type ReportFormat = "json" | "markdown" | "terminal";

/** Serialise a report to JSON. */
export function toJson(report: AnalysisReport): string {
  return JSON.stringify(report, null, 2);
}

function byCategory(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = map.get(f.category) ?? [];
    list.push(f);
    map.set(f.category, list);
  }
  return map;
}

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** A Markdown report suitable for issues, wikis or archival. */
export function toMarkdown(report: AnalysisReport): string {
  const a = report.artifact;
  const lines: string[] = [];
  lines.push(`# SpectraProbe report: ${a.name}`);
  lines.push("");
  lines.push(`- **Tool:** ${report.tool} v${report.version}`);
  lines.push(`- **Format:** ${a.format} — ${a.description}`);
  lines.push(`- **Size:** ${humanSize(a.size)}`);
  if (a.hashes) {
    lines.push(`- **SHA-256:** \`${a.hashes.sha256}\``);
    lines.push(`- **SHA-1:** \`${a.hashes.sha1}\`  ·  **MD5:** \`${a.hashes.md5}\``);
  }
  if (a.entropy !== undefined) lines.push(`- **Entropy:** ${a.entropy} bits/byte`);
  lines.push(`- **Analyses run:** ${report.ranAnalyses.join(", ") || "none"}`);
  lines.push(`- **Generated:** ${report.finishedAt} (${report.durationMs} ms)`);
  lines.push("");

  if (report.warnings.length > 0) {
    lines.push("## Warnings");
    lines.push("");
    for (const w of report.warnings) lines.push(`- ⚠️ ${w}`);
    lines.push("");
  }

  lines.push(`## Findings (${report.findings.length})`);
  lines.push("");
  for (const [category, findings] of byCategory(report.findings)) {
    lines.push(`### ${category}`);
    lines.push("");
    for (const f of findings) {
      lines.push(`- **${f.title}** _(${f.certainty}, ${f.confidence} confidence)_`);
      if (f.detail) lines.push(`  - ${f.detail}`);
      if (f.limitations) lines.push(`  - _Limitations: ${f.limitations}_`);
      lines.push(`  - Evidence: ${f.evidence.map((e) => `\`${e}\``).join(", ")}`);
    }
    lines.push("");
  }

  lines.push("## Reproducibility");
  lines.push("");
  lines.push("```");
  lines.push(`spectra report "${a.name}"`);
  lines.push("```");
  lines.push("");
  lines.push(
    "_Findings marked `verified` are read directly from file structure. " +
      "`inferred` findings are heuristic and should be confirmed. " +
      "This report describes observed static structure only._",
  );
  return lines.join("\n");
}

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  gray: "\x1b[90m",
};

function color(enabled: boolean, code: string, text: string): string {
  return enabled ? `${code}${text}${C.reset}` : text;
}

/** A compact, human-friendly terminal summary. */
export function toTerminal(report: AnalysisReport, useColor = true): string {
  const a = report.artifact;
  const out: string[] = [];
  const c = (code: string, t: string) => color(useColor, code, t);

  out.push(c(C.bold + C.cyan, `▌ ${a.name}`));
  out.push(`  ${c(C.gray, "format")}   ${a.format} — ${a.description}`);
  out.push(`  ${c(C.gray, "size")}     ${humanSize(a.size)}`);
  if (a.hashes) out.push(`  ${c(C.gray, "sha256")}   ${a.hashes.sha256}`);
  if (a.entropy !== undefined) out.push(`  ${c(C.gray, "entropy")}  ${a.entropy} bits/byte`);
  out.push("");

  const confColor: Record<string, string> = { high: C.green, medium: C.yellow, low: C.red };
  for (const [category, findings] of byCategory(report.findings)) {
    out.push(c(C.bold, category));
    for (const f of findings) {
      const badge = c(confColor[f.confidence] ?? C.gray, `[${f.certainty[0]}${f.confidence[0]}]`);
      out.push(`  ${badge} ${f.title}`);
      if (f.detail) out.push(`       ${c(C.gray, f.detail)}`);
      if (f.limitations) out.push(`       ${c(C.dim, "⚠ " + f.limitations)}`);
    }
    out.push("");
  }

  if (report.warnings.length > 0) {
    out.push(c(C.yellow, "warnings"));
    for (const w of report.warnings) out.push(`  ${c(C.yellow, "⚠")} ${w}`);
    out.push("");
  }

  out.push(
    c(
      C.gray,
      `${report.findings.length} findings · ${report.evidence.length} evidence records · ${report.durationMs} ms`,
    ),
  );
  return out.join("\n");
}

/** Render a report in the requested format. */
export function renderReport(report: AnalysisReport, format: ReportFormat, useColor = true): string {
  switch (format) {
    case "json":
      return toJson(report);
    case "markdown":
      return toMarkdown(report);
    case "terminal":
      return toTerminal(report, useColor);
  }
}

/** Render a provider capability table for the terminal. */
export function renderProviders(providers: ProviderInfo[], useColor = true): string {
  const c = (code: string, t: string) => color(useColor, code, t);
  const out: string[] = [c(C.bold, "Analysis providers")];
  for (const p of providers) {
    const status = p.available
      ? c(C.green, `✓ available${p.version ? " v" + p.version : ""}`)
      : c(C.red, "✗ not installed");
    out.push(`  ${c(C.bold, p.name.padEnd(10))} ${status}`);
    out.push(`    ${c(C.gray, p.description)}`);
    out.push(`    ${c(C.gray, "supports:")} ${p.supports.join(", ")}  ${c(C.gray, "caps:")} ${p.capabilities.join(", ")}`);
    if (!p.available && p.note) out.push(`    ${c(C.dim, p.note)}`);
  }
  return out.join("\n");
}
