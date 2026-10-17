import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makePe } from "./fixtures.js";
import { SpectraMcp, TOOLS } from "../src/mcp/server.js";

let dir: string;
let exePath: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "spectra-mcp-"));
  exePath = join(dir, "sample.exe");
  await writeFile(exePath, makePe());
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("MCP tool layer", () => {
  it("declares every advertised tool with an input schema", () => {
    const names = TOOLS.map((t) => t.name);
    expect(names).toEqual(
      expect.arrayContaining([
        "probe_target",
        "inspect_metadata",
        "extract_strings",
        "inspect_dependencies",
        "inspect_symbols",
        "inspect_imports",
        "analyze_javascript",
        "inspect_resources",
        "search_evidence",
        "create_report",
        "list_providers",
        "get_analysis_status",
      ]),
    );
    for (const t of TOOLS) expect(t.inputSchema).toHaveProperty("type", "object");
  });

  it("probe_target identifies and hashes", async () => {
    const mcp = new SpectraMcp();
    const result = (await mcp.call("probe_target", { path: exePath })) as { format: string; hashes: { sha256: string } };
    expect(result.format).toBe("pe");
    expect(result.hashes.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("inspect_imports returns engine results with evidence", async () => {
    const mcp = new SpectraMcp();
    const result = (await mcp.call("inspect_imports", { path: exePath })) as { imports: { data: unknown[] }[] };
    expect(result.imports.length).toBeGreaterThan(0);
    expect(result.imports[0]!.data.length).toBeGreaterThan(0);
  });

  it("accumulates a session so search_evidence and get_analysis_status work", async () => {
    const mcp = new SpectraMcp();
    await mcp.call("inspect_metadata", { path: exePath });
    const status = (await mcp.call("get_analysis_status", {})) as { artifactsAnalyzed: number; findings: number };
    expect(status.artifactsAnalyzed).toBe(1);
    expect(status.findings).toBeGreaterThan(0);

    const search = (await mcp.call("search_evidence", { category: "metadata" })) as { count: number };
    expect(search.count).toBeGreaterThan(0);
  });

  it("create_report returns markdown", async () => {
    const mcp = new SpectraMcp();
    const result = (await mcp.call("create_report", { path: exePath, format: "markdown" })) as { content: string };
    expect(result.content).toContain("# SpectraProbe report");
  });

  it("list_providers reports availability", async () => {
    const mcp = new SpectraMcp();
    const result = (await mcp.call("list_providers", {})) as { providers: { name: string; available: boolean }[] };
    expect(result.providers.some((p) => p.name === "yara")).toBe(true);
  });

  it("errors clearly on a missing path argument", async () => {
    const mcp = new SpectraMcp();
    await expect(mcp.call("probe_target", {})).rejects.toThrow(/path/);
  });
});
