import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makePe, makeElf, makeWasm, makeJar } from "./fixtures.js";
import { ingestTarget } from "../src/ingest/ingest.js";
import { analyzePath } from "../src/analyze/static.js";
import { buildGraph } from "../src/evidence/graph.js";
import { Session } from "../src/evidence/session.js";
import { renderReport } from "../src/report/report.js";

let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "spectra-"));
  await writeFile(join(dir, "sample.exe"), makePe());
  await writeFile(join(dir, "sample.so"), makeElf());
  await writeFile(join(dir, "mod.wasm"), makeWasm());
  await writeFile(join(dir, "app.jar"), makeJar());
  // a tiny JS project
  const proj = join(dir, "proj");
  await mkdir(join(proj, "src"), { recursive: true });
  await writeFile(
    join(proj, "package.json"),
    JSON.stringify({ name: "demo", version: "1.2.3", dependencies: { acorn: "^8" }, devDependencies: { vitest: "^2" } }),
  );
  await writeFile(join(proj, "src", "index.js"), `import cp from "node:child_process";\nexport const go = () => cp;\n`);
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("ingestion", () => {
  it("hashes files and assigns a stable id and capabilities", async () => {
    const { artifact } = await ingestTarget(join(dir, "sample.exe"));
    expect(artifact.format).toBe("pe");
    expect(artifact.hashes?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(artifact.id).toBe(artifact.hashes!.sha256.slice(0, 16));
    expect(artifact.capabilities).toContain("imports");
  });

  it("detects a JS project directory via package.json", async () => {
    const { artifact } = await ingestTarget(join(dir, "proj"));
    expect(artifact.format).toBe("js-project");
    expect(artifact.isDirectory).toBe(true);
  });
});

describe("static analysis report", () => {
  it("produces evidence-backed findings for a PE", async () => {
    const report = await analyzePath(join(dir, "sample.exe"));
    expect(report.ranAnalyses).toEqual(expect.arrayContaining(["imports", "exports", "sections"]));
    const importFinding = report.findings.find((f) => f.category === "import");
    expect(importFinding).toBeTruthy();
    // every finding must cite evidence that actually exists
    for (const f of report.findings) {
      expect(f.evidence.length).toBeGreaterThan(0);
      for (const eid of f.evidence) {
        expect(report.evidence.find((e) => e.id === eid)).toBeTruthy();
      }
    }
  });

  it("reports ELF dependencies and WASM imports/exports", async () => {
    const elf = await analyzePath(join(dir, "sample.so"));
    expect(elf.findings.some((f) => f.category === "metadata")).toBe(true);

    const wasm = await analyzePath(join(dir, "mod.wasm"));
    expect(wasm.findings.some((f) => f.category === "import")).toBe(true);
    expect(wasm.findings.some((f) => f.category === "export")).toBe(true);
  });

  it("analyses a JS project and flags capability references", async () => {
    const report = await analyzePath(join(dir, "proj"));
    expect(report.findings.some((f) => f.category === "dependency")).toBe(true);
    expect(report.findings.some((f) => f.category === "capability" && f.title.includes("process execution"))).toBe(true);
  });

  it("lists archive resources for a JAR", async () => {
    const report = await analyzePath(join(dir, "app.jar"));
    expect(report.findings.some((f) => f.category === "resource")).toBe(true);
    expect(report.findings.some((f) => f.category === "manifest")).toBe(true);
  });

  it("renders markdown and json reports", async () => {
    const report = await analyzePath(join(dir, "sample.exe"));
    const md = renderReport(report, "markdown");
    expect(md).toContain("# SpectraProbe report");
    expect(md).toContain("SHA-256");
    const json = JSON.parse(renderReport(report, "json"));
    expect(json.tool).toBe("spectraprobe");
  });
});

describe("knowledge graph and session", () => {
  it("builds a graph linking the artifact to imports and sections", async () => {
    const report = await analyzePath(join(dir, "sample.exe"));
    const graph = buildGraph([report]);
    const artNode = graph.nodes.find((n) => n.kind === "artifact");
    expect(artNode).toBeTruthy();
    expect(graph.nodes.some((n) => n.kind === "import")).toBe(true);
    expect(graph.edges.some((e) => e.kind === "imports")).toBe(true);
  });

  it("stores reports in a session and searches evidence", async () => {
    const session = Session.create(join(dir, "session.json"));
    session.addReport(await analyzePath(join(dir, "sample.exe")));
    session.addReport(await analyzePath(join(dir, "sample.so")));
    expect(session.artifacts.length).toBe(2);

    const hits = session.search({ category: "import" });
    expect(hits.length).toBeGreaterThan(0);

    const highOnly = session.search({ minConfidence: "high" });
    expect(highOnly.every((f) => f.confidence === "high")).toBe(true);

    await session.save();
    const reopened = await Session.open(join(dir, "session.json"));
    expect(reopened.artifacts.length).toBe(2);
  });
});
