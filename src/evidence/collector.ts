import type { Certainty, Confidence, Evidence, Finding } from "../types.js";
import { makeId } from "../util/id.js";

/**
 * Accumulates evidence and findings during analysis while enforcing the
 * invariant that a finding must reference at least one evidence record. This is
 * what keeps conclusions traceable to concrete observations.
 */
export class EvidenceCollector {
  private readonly _evidence: Evidence[] = [];
  private readonly _findings: Finding[] = [];

  constructor(private readonly artifactId: string) {}

  /** Record a raw observation and return its id for citation. */
  addEvidence(source: string, data: unknown, location?: string): string {
    const ev: Evidence = {
      id: makeId("ev"),
      source,
      ...(location !== undefined ? { location } : {}),
      data,
      createdAt: new Date().toISOString(),
    };
    this._evidence.push(ev);
    return ev.id;
  }

  /** Record an interpreted finding; `evidence` must be non-empty. */
  addFinding(input: {
    category: string;
    title: string;
    detail?: string;
    certainty: Certainty;
    confidence: Confidence;
    source: string;
    evidence: string[];
    limitations?: string;
  }): Finding {
    if (input.evidence.length === 0) {
      throw new Error(`finding "${input.title}" has no supporting evidence`);
    }
    const finding: Finding = {
      id: makeId("fn"),
      artifactId: this.artifactId,
      category: input.category,
      title: input.title,
      ...(input.detail !== undefined ? { detail: input.detail } : {}),
      certainty: input.certainty,
      confidence: input.confidence,
      source: input.source,
      evidence: input.evidence,
      ...(input.limitations !== undefined ? { limitations: input.limitations } : {}),
      createdAt: new Date().toISOString(),
    };
    this._findings.push(finding);
    return finding;
  }

  /** Convenience: record evidence and a finding that cites it in one call. */
  observe(input: {
    category: string;
    title: string;
    detail?: string;
    certainty: Certainty;
    confidence: Confidence;
    source: string;
    data: unknown;
    location?: string;
    limitations?: string;
  }): Finding {
    const evId = this.addEvidence(input.source, input.data, input.location);
    return this.addFinding({
      category: input.category,
      title: input.title,
      ...(input.detail !== undefined ? { detail: input.detail } : {}),
      certainty: input.certainty,
      confidence: input.confidence,
      source: input.source,
      evidence: [evId],
      ...(input.limitations !== undefined ? { limitations: input.limitations } : {}),
    });
  }

  get evidence(): Evidence[] {
    return this._evidence;
  }

  get findings(): Finding[] {
    return this._findings;
  }
}
