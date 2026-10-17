import type { AnalysisReport, GraphEdge, GraphNode } from "../types.js";

export interface KnowledgeGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * Build a relationship graph from one or more analysis reports: the artifact at
 * the centre, connected to its sections, imports, exports, dependencies,
 * indicators and findings. Lets an investigator pivot between related facts.
 */
export function buildGraph(reports: AnalysisReport[]): KnowledgeGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  const addNode = (node: GraphNode): string => {
    if (!nodes.has(node.id)) nodes.set(node.id, node);
    return node.id;
  };
  const addEdge = (from: string, to: string, kind: GraphEdge["kind"]): void => {
    edges.push({ from, to, kind });
  };

  for (const report of reports) {
    const artId = `artifact:${report.artifact.id}`;
    addNode({ id: artId, kind: "artifact", label: report.artifact.name, attributes: { format: report.artifact.format } });

    for (const finding of report.findings) {
      const fnId = `finding:${finding.id}`;
      addNode({ id: fnId, kind: "finding", label: finding.title, attributes: { category: finding.category, confidence: finding.confidence } });
      addEdge(artId, fnId, "contains");

      const data = findingData(report, finding.evidence[0]);
      switch (finding.category) {
        case "import": {
          for (const imp of asImports(data)) {
            const id = addNode({ id: `import:${imp}`, kind: "import", label: imp });
            addEdge(artId, id, "imports");
          }
          break;
        }
        case "export": {
          for (const name of asStringArray(data)) {
            const id = addNode({ id: `export:${name}`, kind: "export", label: name });
            addEdge(artId, id, "exports");
          }
          break;
        }
        case "dependency": {
          for (const dep of asDependencies(data)) {
            const id = addNode({ id: `package:${dep}`, kind: "package", label: dep });
            addEdge(artId, id, "depends-on");
          }
          break;
        }
        case "section": {
          for (const name of asSectionNames(data)) {
            const id = addNode({ id: `section:${report.artifact.id}:${name}`, kind: "section", label: name });
            addEdge(artId, id, "contains");
          }
          break;
        }
        case "indicator": {
          const values = asIndicatorValues(data);
          for (const v of values) {
            const id = addNode({ id: `indicator:${v}`, kind: "indicator", label: v });
            addEdge(artId, id, "references");
          }
          break;
        }
        default:
          break;
      }
    }
  }

  return { nodes: [...nodes.values()], edges };
}

function findingData(report: AnalysisReport, evidenceId: string | undefined): unknown {
  if (!evidenceId) return undefined;
  return report.evidence.find((e) => e.id === evidenceId)?.data;
}

function asImports(data: unknown): string[] {
  if (Array.isArray(data)) {
    const out: string[] = [];
    for (const item of data) {
      if (item && typeof item === "object" && "dll" in item) out.push(String((item as { dll: unknown }).dll));
      else if (item && typeof item === "object" && "module" in item)
        out.push(String((item as { module: unknown }).module));
    }
    return out;
  }
  return [];
}

function asStringArray(data: unknown): string[] {
  return Array.isArray(data) ? data.filter((x): x is string => typeof x === "string") : [];
}

function asDependencies(data: unknown): string[] {
  if (data && typeof data === "object") {
    const d = data as Record<string, unknown>;
    if (Array.isArray(d.needed)) return d.needed.filter((x): x is string => typeof x === "string");
    if (Array.isArray(d.dependencies)) return d.dependencies.filter((x): x is string => typeof x === "string");
    if (Array.isArray(d)) return d.filter((x): x is string => typeof x === "string");
  }
  return Array.isArray(data) ? data.filter((x): x is string => typeof x === "string") : [];
}

function asSectionNames(data: unknown): string[] {
  if (!Array.isArray(data)) return [];
  return data
    .map((s) => (s && typeof s === "object" && "name" in s ? String((s as { name: unknown }).name) : null))
    .filter((x): x is string => x !== null && x.length > 0);
}

function asIndicatorValues(data: unknown): string[] {
  if (data && typeof data === "object" && "values" in data) {
    const v = (data as { values: unknown }).values;
    if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string").slice(0, 50);
  }
  return [];
}
