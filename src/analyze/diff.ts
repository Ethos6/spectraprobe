/**
 * Compare two analysed artifacts — typically two builds of the same program —
 * and report what changed structurally: imports, exports, sections,
 * dependencies, symbols and embedded indicators. Useful for patch review,
 * release comparison and spotting unexpected new capabilities.
 *
 * The diff is computed only from evidence the static engines actually
 * recorded, so it never claims a change it did not observe.
 */
import type { AnalysisReport, Artifact } from "../types.js";
import { VERSION } from "../version.js";

export interface SetChange {
  added: string[];
  removed: string[];
  unchanged: number;
}

export interface SectionChange {
  name: string;
  sizeA: number;
  sizeB: number;
}

export interface ArtifactSummary {
  name: string;
  format: string;
  size: number;
  sha256?: string;
  entropy?: number;
}

export interface ArtifactDiff {
  tool: string;
  version: string;
  a: ArtifactSummary;
  b: ArtifactSummary;
  identical: boolean;
  formatChanged: boolean;
  sizeDelta: number;
  entropyDelta: number | null;
  sections: { added: string[]; removed: string[]; resized: SectionChange[] };
  imports: SetChange;
  exports: SetChange;
  dependencies: SetChange;
  symbols: SetChange;
  indicators: SetChange;
  /** Categories that could not be compared because neither side recorded them. */
  notCompared: string[];
}

function summary(a: Artifact): ArtifactSummary {
  return {
    name: a.name,
    format: a.format,
    size: a.size,
    ...(a.hashes ? { sha256: a.hashes.sha256 } : {}),
    ...(a.entropy !== undefined ? { entropy: a.entropy } : {}),
  };
}

/** All evidence payloads cited by findings of the given categories. */
function dataFor(report: AnalysisReport, categories: string[]): unknown[] {
  const ids = new Set(
    report.findings.filter((f) => categories.includes(f.category)).flatMap((f) => f.evidence),
  );
  return report.evidence.filter((e) => ids.has(e.id)).map((e) => e.data);
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;

function importsOf(report: AnalysisReport): string[] {
  const out: string[] = [];
  for (const data of dataFor(report, ["import"])) {
    if (!Array.isArray(data)) continue;
    for (const item of data) {
      if (!isObj(item)) continue;
      if (typeof item.dll === "string") {
        const fns = Array.isArray(item.functions) ? item.functions : [];
        if (fns.length === 0) out.push(item.dll.toLowerCase());
        for (const fn of fns) out.push(`${item.dll.toLowerCase()}!${String(fn)}`);
      } else if (typeof item.module === "string") {
        out.push(`${item.module}.${String(item.name ?? "")}`);
      }
    }
  }
  return out;
}

function exportsOf(report: AnalysisReport): string[] {
  const out: string[] = [];
  for (const data of dataFor(report, ["export"])) {
    if (!Array.isArray(data)) continue;
    for (const item of data) {
      if (typeof item === "string") out.push(item);
      else if (isObj(item) && typeof item.name === "string") out.push(item.name);
    }
  }
  return out;
}

function dependenciesOf(report: AnalysisReport): string[] {
  const out: string[] = [];
  for (const data of dataFor(report, ["dependency"])) {
    if (Array.isArray(data)) out.push(...data.filter((x): x is string => typeof x === "string"));
    else if (isObj(data)) {
      for (const key of ["needed", "dependencies", "devDependencies"]) {
        const v = data[key];
        if (Array.isArray(v)) out.push(...v.filter((x): x is string => typeof x === "string"));
      }
    }
  }
  return out;
}

function symbolsOf(report: AnalysisReport): string[] {
  const out: string[] = [];
  for (const data of dataFor(report, ["symbol"])) {
    if (Array.isArray(data)) out.push(...data.filter((x): x is string => typeof x === "string"));
  }
  return out;
}

function indicatorsOf(report: AnalysisReport): string[] {
  const out: string[] = [];
  for (const data of dataFor(report, ["indicator"])) {
    if (isObj(data) && typeof data.kind === "string" && Array.isArray(data.values)) {
      for (const v of data.values) out.push(`${data.kind}:${String(v)}`);
    }
  }
  return out;
}

function sectionsOf(report: AnalysisReport): Map<string, number> {
  const map = new Map<string, number>();
  for (const data of dataFor(report, ["section"])) {
    if (!Array.isArray(data)) continue;
    for (const s of data) {
      if (!isObj(s) || typeof s.name !== "string" || s.name === "") continue;
      const key = typeof s.segment === "string" ? `${s.segment},${s.name}` : s.name;
      const size = Number(s.rawSize ?? s.size ?? 0);
      map.set(key, size);
    }
  }
  return map;
}

function setChange(a: string[], b: string[]): SetChange {
  const sa = new Set(a);
  const sb = new Set(b);
  const added = [...sb].filter((x) => !sa.has(x)).sort();
  const removed = [...sa].filter((x) => !sb.has(x)).sort();
  const unchanged = [...sa].filter((x) => sb.has(x)).length;
  return { added, removed, unchanged };
}

/** Diff two analysis reports. */
export function diffReports(a: AnalysisReport, b: AnalysisReport): ArtifactDiff {
  const secA = sectionsOf(a);
  const secB = sectionsOf(b);
  const resized: SectionChange[] = [];
  for (const [name, sizeA] of secA) {
    const sizeB = secB.get(name);
    if (sizeB !== undefined && sizeB !== sizeA) resized.push({ name, sizeA, sizeB });
  }

  const pairs: [string, string[], string[]][] = [
    ["imports", importsOf(a), importsOf(b)],
    ["exports", exportsOf(a), exportsOf(b)],
    ["dependencies", dependenciesOf(a), dependenciesOf(b)],
    ["symbols", symbolsOf(a), symbolsOf(b)],
    ["indicators", indicatorsOf(a), indicatorsOf(b)],
  ];
  const notCompared = pairs.filter(([, x, y]) => x.length === 0 && y.length === 0).map(([n]) => n);
  if (secA.size === 0 && secB.size === 0) notCompared.push("sections");

  const [imports, exports, dependencies, symbols, indicators] = pairs.map(([, x, y]) => setChange(x, y)) as [
    SetChange,
    SetChange,
    SetChange,
    SetChange,
    SetChange,
  ];

  const shaA = a.artifact.hashes?.sha256;
  const shaB = b.artifact.hashes?.sha256;
  return {
    tool: "spectraprobe",
    version: VERSION,
    a: summary(a.artifact),
    b: summary(b.artifact),
    identical: shaA !== undefined && shaA === shaB,
    formatChanged: a.artifact.format !== b.artifact.format,
    sizeDelta: b.artifact.size - a.artifact.size,
    entropyDelta:
      a.artifact.entropy !== undefined && b.artifact.entropy !== undefined
        ? Math.round((b.artifact.entropy - a.artifact.entropy) * 1000) / 1000
        : null,
    sections: {
      added: [...secB.keys()].filter((k) => !secA.has(k)).sort(),
      removed: [...secA.keys()].filter((k) => !secB.has(k)).sort(),
      resized,
    },
    imports,
    exports,
    dependencies,
    symbols,
    indicators,
    notCompared,
  };
}

/** True when the diff contains any structural change. */
export function hasChanges(d: ArtifactDiff): boolean {
  const sets = [d.imports, d.exports, d.dependencies, d.symbols, d.indicators];
  return (
    !d.identical &&
    (d.formatChanged ||
      d.sizeDelta !== 0 ||
      d.sections.added.length + d.sections.removed.length + d.sections.resized.length > 0 ||
      sets.some((s) => s.added.length + s.removed.length > 0))
  );
}

function listLines(prefix: string, items: string[], cap: number): string[] {
  const shown = items.slice(0, cap).map((x) => `${prefix} ${x}`);
  if (items.length > cap) shown.push(`  … and ${items.length - cap} more (use --format json for all)`);
  return shown;
}

/** Plain-text / Markdown-friendly rendering. `color` adds ANSI colours for terminals. */
export function renderDiff(d: ArtifactDiff, format: "terminal" | "markdown" | "json", color = false): string {
  if (format === "json") return JSON.stringify(d, null, 2);
  const g = (t: string) => (color ? `\x1b[32m${t}\x1b[0m` : t);
  const r = (t: string) => (color ? `\x1b[31m${t}\x1b[0m` : t);
  const b = (t: string) => (color ? `\x1b[1m${t}\x1b[0m` : format === "markdown" ? `**${t}**` : t);
  const out: string[] = [];
  const md = format === "markdown";
  // Terminals get a compact view; Markdown reports keep (almost) everything.
  const cap = md ? 500 : 12;
  const resizedCap = md ? 500 : 8;

  out.push(md ? `# SpectraProbe diff: ${d.a.name} → ${d.b.name}` : b(`${d.a.name}  →  ${d.b.name}`));
  out.push("");
  const sign = d.sizeDelta > 0 ? "+" : "";
  out.push(`${md ? "- " : "  "}format   ${d.a.format}${d.formatChanged ? ` → ${d.b.format}` : ""}`);
  out.push(`${md ? "- " : "  "}size     ${d.a.size} → ${d.b.size} bytes (${sign}${d.sizeDelta})`);
  if (d.entropyDelta !== null) {
    out.push(`${md ? "- " : "  "}entropy  ${d.a.entropy} → ${d.b.entropy} (${d.entropyDelta >= 0 ? "+" : ""}${d.entropyDelta})`);
  }
  if (d.identical) {
    out.push("");
    out.push("Files are byte-for-byte identical.");
    return out.join("\n");
  }

  const section = (title: string, change: SetChange) => {
    if (change.added.length + change.removed.length === 0) return;
    out.push("");
    out.push(md ? `## ${title}` : b(title));
    out.push(...listLines(g("  +"), change.added, cap));
    out.push(...listLines(r("  -"), change.removed, cap));
    out.push(`  (${change.unchanged} unchanged)`);
  };

  if (d.sections.added.length + d.sections.removed.length + d.sections.resized.length > 0) {
    out.push("");
    out.push(md ? "## sections" : b("sections"));
    out.push(...listLines(g("  +"), d.sections.added, cap));
    out.push(...listLines(r("  -"), d.sections.removed, cap));
    const biggest = [...d.sections.resized].sort(
      (x, y) => Math.abs(y.sizeB - y.sizeA) - Math.abs(x.sizeB - x.sizeA),
    );
    for (const s of biggest.slice(0, resizedCap)) {
      const delta = s.sizeB - s.sizeA;
      out.push(`  ~ ${s.name}  ${s.sizeA} → ${s.sizeB} bytes (${delta > 0 ? "+" : ""}${delta})`);
    }
    if (biggest.length > resizedCap) out.push(`  … and ${biggest.length - resizedCap} more resized`);
  }
  section("imports", d.imports);
  section("exports", d.exports);
  section("dependencies", d.dependencies);
  section("symbols", d.symbols);
  section("indicators", d.indicators);

  if (!hasChanges(d)) {
    out.push("");
    out.push("No structural changes detected (contents differ only in ways the static engines do not track).");
  }
  if (d.notCompared.length > 0) {
    out.push("");
    out.push(`not compared (no data on either side): ${d.notCompared.join(", ")}`);
  }
  return out.join("\n");
}
