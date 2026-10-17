import { describe, it, expect } from "vitest";
import { analyzeJavaScriptSource } from "../src/analyze/javascript.js";

describe("JavaScript analysis (AST)", () => {
  it("extracts imports, requires, exports and function counts", () => {
    const src = `
      import fs from "node:fs";
      import { join } from "path";
      const cp = require("child_process");
      export function run() { return 1; }
      export const value = 2;
      const f = () => 3;
    `;
    const a = analyzeJavaScriptSource(src, "sample.js");
    expect(a.parser).toBe("acorn-ast");
    expect(a.imports).toEqual(expect.arrayContaining(["node:fs", "path"]));
    expect(a.requires).toContain("child_process");
    expect(a.exports).toEqual(expect.arrayContaining(["run", "value"]));
    expect(a.functionCount).toBeGreaterThanOrEqual(2);
    expect(a.capabilityHints).toEqual(expect.arrayContaining(["filesystem access", "process execution"]));
  });

  it("flags dynamic import and eval", () => {
    const a = analyzeJavaScriptSource(`eval("1+1"); import("./x.js");`, "d.js");
    expect(a.usesEval).toBe(true);
    expect(a.usesDynamicImport).toBe(true);
    expect(a.capabilityHints).toContain("dynamic code evaluation");
  });

  it("falls back to a regex scan for TypeScript", () => {
    const ts = `
      import type { Foo } from "./foo";
      import { bar } from "./bar";
      const x: number = 1;
      export const y: string = "a";
    `;
    const a = analyzeJavaScriptSource(ts, "sample.ts");
    expect(a.parser).toBe("regex-fallback");
    expect(a.language).toBe("typescript");
    expect(a.imports).toEqual(expect.arrayContaining(["./foo", "./bar"]));
  });

  it("recovers via fallback when JS fails to parse as AST", () => {
    const broken = `import x from "y"; const = = = ;`;
    const a = analyzeJavaScriptSource(broken, "broken.js");
    expect(a.parser).toBe("regex-fallback");
    expect(a.parseError).toBeTruthy();
    expect(a.imports).toContain("y");
  });
});
