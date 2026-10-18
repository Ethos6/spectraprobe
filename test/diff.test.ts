import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { makePe, makeElf, makeWasm } from "./fixtures.js";
import { analyzePath } from "../src/analyze/static.js";
import { diffReports, hasChanges, renderDiff } from "../src/analyze/diff.js";
import { SpectraMcp } from "../src/mcp/server.js";

let dir: string;
const p = (name: string) => join(dir, name);

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "spectra-diff-"));
  await writeFile(p("v1.exe"), makePe());
  await writeFile(p("v2.exe"), makePe({ exportName: "DoMore", importName: "Sleep" }));
  await writeFile(p("copy.exe"), makePe());
  await writeFile(p("a.wasm"), makeWasm("run"));
  await writeFile(p("b.wasm"), makeWasm("go"));
  await writeFile(p("lib.so"), makeElf());
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("diff", () => {
  it("reports identical files", async () => {
    const d = diffReports(await analyzePath(p("v1.exe")), await analyzePath(p("copy.exe")));
    expect(d.identical).toBe(true);
    expect(hasChanges(d)).toBe(false);
    expect(renderDiff(d, "terminal")).toContain("identical");
  });

  it("finds added and removed PE imports and exports", async () => {
    const d = diffReports(await analyzePath(p("v1.exe")), await analyzePath(p("v2.exe")));
    expect(d.identical).toBe(false);
    expect(d.imports.added).toEqual(["kernel32.dll!Sleep"]);
    expect(d.imports.removed).toEqual(["kernel32.dll!ExitProcess"]);
    expect(d.exports.added).toEqual(["DoMore"]);
    expect(d.exports.removed).toEqual(["DoWork"]);
    expect(hasChanges(d)).toBe(true);
    const md = renderDiff(d, "markdown");
    expect(md).toContain("## imports");
    expect(md).toContain("+ kernel32.dll!Sleep");
  });

  it("diffs WebAssembly exports", async () => {
    const d = diffReports(await analyzePath(p("a.wasm")), await analyzePath(p("b.wasm")));
    expect(d.exports.added).toEqual(["go"]);
    expect(d.exports.removed).toEqual(["run"]);
    expect(d.imports.unchanged).toBe(1);
  });

  it("flags a format change", async () => {
    const d = diffReports(await analyzePath(p("v1.exe")), await analyzePath(p("lib.so")));
    expect(d.formatChanged).toBe(true);
    expect(d.sections.added).toContain(".shstrtab");
  });

  it("is exposed through the CLI with diff-style exit codes", () => {
    const cli = join(process.cwd(), "dist/cli/cli.js");
    const same = execFileSync(process.execPath, [cli, "diff", p("v1.exe"), p("copy.exe"), "--no-color"]).toString();
    expect(same).toContain("identical");
    let code = 0;
    let out = "";
    try {
      execFileSync(process.execPath, [cli, "diff", p("v1.exe"), p("v2.exe"), "--format", "json"]);
    } catch (e) {
      const err = e as { status: number; stdout: Buffer };
      code = err.status;
      out = err.stdout.toString();
    }
    expect(code).toBe(1);
    expect(JSON.parse(out).exports.added).toEqual(["DoMore"]);
  });

  it("is exposed as the diff_targets MCP tool", async () => {
    const mcp = new SpectraMcp();
    const d = (await mcp.call("diff_targets", { a: p("v1.exe"), b: p("v2.exe") })) as { imports: { added: string[] } };
    expect(d.imports.added).toEqual(["kernel32.dll!Sleep"]);
    await expect(mcp.call("diff_targets", { a: p("v1.exe") })).rejects.toThrow(/a, b/);
  });
});
