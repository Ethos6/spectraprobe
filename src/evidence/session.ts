import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { AnalysisReport, Artifact, Evidence, Finding } from "../types.js";
import { VERSION } from "../version.js";

/**
 * A persistent investigation session. Backed by a single JSON file (an
 * "embedded store") so no native database build is required; the shape is kept
 * deliberately simple so it can be swapped for SQLite later without changing
 * callers. Stores artifacts, findings and evidence and supports evidence search.
 */
export interface SessionData {
  tool: string;
  version: string;
  createdAt: string;
  updatedAt: string;
  artifacts: Record<string, Artifact>;
  findings: Finding[];
  evidence: Evidence[];
}

export interface EvidenceQuery {
  /** Case-insensitive substring across finding title/detail and evidence source/location. */
  text?: string;
  category?: string;
  artifactId?: string;
  minConfidence?: "high" | "medium" | "low";
}

const CONF_RANK = { low: 0, medium: 1, high: 2 } as const;

export class Session {
  private constructor(
    public readonly path: string,
    private data: SessionData,
  ) {}

  /** Create a fresh in-memory session (not yet written to disk). */
  static create(path: string): Session {
    const now = new Date().toISOString();
    return new Session(resolve(path), {
      tool: "spectraprobe",
      version: VERSION,
      createdAt: now,
      updatedAt: now,
      artifacts: {},
      findings: [],
      evidence: [],
    });
  }

  /** Load an existing session file, or create a new one if it does not exist. */
  static async open(path: string): Promise<Session> {
    const abs = resolve(path);
    try {
      const raw = await readFile(abs, "utf8");
      return new Session(abs, JSON.parse(raw) as SessionData);
    } catch {
      return Session.create(abs);
    }
  }

  /** Merge an analysis report into the session. */
  addReport(report: AnalysisReport): void {
    this.data.artifacts[report.artifact.id] = report.artifact;
    this.data.findings.push(...report.findings);
    this.data.evidence.push(...report.evidence);
    this.data.updatedAt = new Date().toISOString();
  }

  get artifacts(): Artifact[] {
    return Object.values(this.data.artifacts);
  }

  get findings(): Finding[] {
    return this.data.findings;
  }

  getEvidence(id: string): Evidence | undefined {
    return this.data.evidence.find((e) => e.id === id);
  }

  /** Search findings (and their evidence) by text, category, artifact and confidence. */
  search(query: EvidenceQuery): Finding[] {
    const text = query.text?.toLowerCase();
    const minRank = query.minConfidence ? CONF_RANK[query.minConfidence] : 0;
    return this.data.findings.filter((f) => {
      if (query.artifactId && f.artifactId !== query.artifactId) return false;
      if (query.category && f.category !== query.category) return false;
      if (CONF_RANK[f.confidence] < minRank) return false;
      if (text) {
        const hay = [
          f.title,
          f.detail ?? "",
          f.category,
          f.source,
          ...f.evidence.map((eid) => {
            const ev = this.getEvidence(eid);
            return ev ? `${ev.source} ${ev.location ?? ""} ${safeStringify(ev.data)}` : "";
          }),
        ]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
  }

  toJSON(): SessionData {
    return this.data;
  }

  /** Persist the session to its JSON file. */
  async save(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    await writeFile(this.path, JSON.stringify(this.data, null, 2), "utf8");
  }
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}
