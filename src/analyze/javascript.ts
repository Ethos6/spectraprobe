/**
 * JavaScript/TypeScript inspection. Uses acorn for a real AST when the source
 * is plain JS; for TypeScript (which acorn does not parse) it falls back to a
 * conservative regex scan so dependency discovery still works. Nothing is
 * executed — the source is only parsed and read.
 */
import { Parser } from "acorn";
import { ancestor } from "acorn-walk";
import type { Node } from "acorn";

export interface JsAnalysis {
  parser: "acorn-ast" | "regex-fallback";
  language: "javascript" | "typescript";
  imports: string[];
  requires: string[];
  exports: string[];
  functionCount: number;
  classCount: number;
  usesDynamicImport: boolean;
  usesEval: boolean;
  /** Notable runtime capabilities referenced in source (informational, not a verdict). */
  capabilityHints: string[];
  loc: number;
  parseError?: string;
}

const TS_EXT = new Set(["ts", "tsx", "mts", "cts"]);

// Modules/APIs worth surfacing to a reviewer. Presence is informational only.
const CAPABILITY_MODULES: Record<string, string> = {
  child_process: "process execution",
  "node:child_process": "process execution",
  fs: "filesystem access",
  "node:fs": "filesystem access",
  "fs/promises": "filesystem access",
  net: "raw network sockets",
  "node:net": "raw network sockets",
  http: "outbound HTTP",
  https: "outbound HTTP",
  dgram: "UDP sockets",
  dns: "DNS resolution",
  os: "host information",
  vm: "dynamic code evaluation",
  "node:vm": "dynamic code evaluation",
  cluster: "multi-process",
  worker_threads: "worker threads",
};

function extExtension(filename: string): string {
  return filename.toLowerCase().split(".").pop() ?? "";
}

function uniq(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

/** Analyse a single JS/TS source string. */
export function analyzeJavaScriptSource(source: string, filename = "input.js"): JsAnalysis {
  const ext = extExtension(filename);
  const language = TS_EXT.has(ext) ? "typescript" : "javascript";
  const loc = source.split("\n").length;

  if (language === "javascript") {
    try {
      return astAnalysis(source, loc);
    } catch (err) {
      const fallback = regexAnalysis(source, language, loc);
      fallback.parseError = (err as Error).message;
      return fallback;
    }
  }
  // TypeScript: acorn can't parse it; use the conservative scan.
  return regexAnalysis(source, language, loc);
}

function astAnalysis(source: string, loc: number): JsAnalysis {
  const isModule = /\b(import|export)\b/.test(source);
  const ast = Parser.parse(source, {
    ecmaVersion: "latest",
    sourceType: isModule ? "module" : "script",
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    locations: false,
  }) as unknown as Node;

  const imports: string[] = [];
  const requires: string[] = [];
  const exports: string[] = [];
  let functionCount = 0;
  let classCount = 0;
  let usesDynamicImport = false;
  let usesEval = false;

  ancestor(ast, {
    ImportDeclaration(node: any) {
      if (typeof node.source?.value === "string") imports.push(node.source.value);
    },
    ExportNamedDeclaration(node: any) {
      if (node.source && typeof node.source.value === "string") imports.push(node.source.value);
      for (const spec of node.specifiers ?? []) {
        if (spec.exported?.name) exports.push(spec.exported.name);
      }
      const decl = node.declaration;
      if (decl?.id?.name) {
        exports.push(decl.id.name); // function/class declaration
      }
      for (const d of decl?.declarations ?? []) {
        if (d.id?.name) exports.push(d.id.name); // export const/let/var
      }
    },
    ExportDefaultDeclaration() {
      exports.push("default");
    },
    ExportAllDeclaration(node: any) {
      if (typeof node.source?.value === "string") imports.push(node.source.value);
    },
    FunctionDeclaration() {
      functionCount++;
    },
    FunctionExpression() {
      functionCount++;
    },
    ArrowFunctionExpression() {
      functionCount++;
    },
    ClassDeclaration() {
      classCount++;
    },
    ImportExpression() {
      usesDynamicImport = true;
    },
    CallExpression(node: any) {
      const callee = node.callee;
      if (callee?.type === "Identifier" && callee.name === "require") {
        const arg = node.arguments?.[0];
        if (arg?.type === "Literal" && typeof arg.value === "string") requires.push(arg.value);
      }
      if (callee?.type === "Identifier" && callee.name === "eval") usesEval = true;
      if (callee?.type === "Import") usesDynamicImport = true;
    },
  });

  const allModules = uniq([...imports, ...requires]);
  return {
    parser: "acorn-ast",
    language: "javascript",
    imports: uniq(imports),
    requires: uniq(requires),
    exports: uniq(exports),
    functionCount,
    classCount,
    usesDynamicImport,
    usesEval,
    capabilityHints: capabilityHints(allModules, source),
    loc,
  };
}

const IMPORT_RE = /\bimport\s+(?:[^'"]*?\sfrom\s+)?["']([^"']+)["']/g;
const EXPORT_FROM_RE = /\bexport\s+(?:\*|\{[^}]*\})\s+from\s+["']([^"']+)["']/g;
const REQUIRE_RE = /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g;
const DYNIMPORT_RE = /\bimport\s*\(/;

function regexAnalysis(source: string, language: "javascript" | "typescript", loc: number): JsAnalysis {
  const imports: string[] = [];
  const requires: string[] = [];
  for (const m of source.matchAll(IMPORT_RE)) imports.push(m[1]!);
  for (const m of source.matchAll(EXPORT_FROM_RE)) imports.push(m[1]!);
  for (const m of source.matchAll(REQUIRE_RE)) requires.push(m[1]!);
  const allModules = uniq([...imports, ...requires]);
  return {
    parser: "regex-fallback",
    language,
    imports: uniq(imports),
    requires: uniq(requires),
    exports: [],
    functionCount: (source.match(/\bfunction\b/g) ?? []).length,
    classCount: (source.match(/\bclass\s+[A-Za-z_$]/g) ?? []).length,
    usesDynamicImport: DYNIMPORT_RE.test(source),
    usesEval: /\beval\s*\(/.test(source),
    capabilityHints: capabilityHints(allModules, source),
    loc,
  };
}

function capabilityHints(modules: string[], source: string): string[] {
  const hints = new Set<string>();
  for (const m of modules) {
    const hit = CAPABILITY_MODULES[m];
    if (hit) hints.add(hit);
  }
  if (/\beval\s*\(/.test(source) || /new\s+Function\s*\(/.test(source)) {
    hints.add("dynamic code evaluation");
  }
  return Array.from(hints);
}
