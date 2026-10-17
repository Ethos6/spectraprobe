#!/usr/bin/env node
/**
 * SpectraProbe command-line interface. Every command performs real analysis;
 * none display simulated results.
 */
import { writeFile } from "node:fs/promises";
import { VERSION } from "../version.js";
import { analyzePath } from "../analyze/static.js";
import { ingestTarget } from "../ingest/ingest.js";
import { extractStrings } from "../util/strings.js";
import { detectProviders, providersForFormat } from "../providers/external.js";
import { renderProviders, renderReport, type ReportFormat } from "../report/report.js";
import { buildGraph } from "../evidence/graph.js";

const HELP = `spectra ${VERSION} — static software analysis toolkit

USAGE
  spectra <command> [options] <target>

COMMANDS
  inspect <target>         Full static analysis (findings, metadata, structure)
  strings <file>           Extract printable ASCII/UTF-16 strings
  dependencies <target>    Show linked libraries / package dependencies
  symbols <file>           Show exported/dynamic symbols
  imports <file>           Show imported libraries and functions
  js analyze <path>        Analyse a JS/TS file or project
  resources <file>         List archive entries / embedded resources
  providers                List external analysis providers and availability
  report <target>          Write a report (use --format and --out)
  graph <target>           Emit the knowledge graph as JSON
  mcp                      Start the MCP server (stdio)

OPTIONS
  --format <fmt>           terminal | json | markdown        (default: terminal)
  --out <file>             Write output to a file instead of stdout
  --only <a,b>             Restrict analyses (e.g. --only strings,imports)
  --min-length <n>         Minimum string length                (default: 4)
  --max-strings <n>        Cap on strings retained              (default: 5000)
  --no-color               Disable ANSI colour
  -h, --help               Show this help
  -v, --version            Show version

NOTE
  SpectraProbe performs static analysis only. Use it on software you own,
  open-source software, or targets you are authorized to analyse.`;

interface ParsedArgs {
  command: string;
  sub?: string;
  positionals: string[];
  format: ReportFormat;
  out?: string;
  only?: string[];
  minLength?: number;
  maxStrings?: number;
  color: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const res: ParsedArgs = { command: "", positionals, format: "terminal", color: true };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case "--format":
        res.format = (argv[++i] as ReportFormat) ?? "terminal";
        break;
      case "--out":
        res.out = argv[++i];
        break;
      case "--only":
        res.only = (argv[++i] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
        break;
      case "--min-length":
        res.minLength = Number(argv[++i]);
        break;
      case "--max-strings":
        res.maxStrings = Number(argv[++i]);
        break;
      case "--no-color":
        res.color = false;
        break;
      default:
        positionals.push(arg);
    }
  }
  res.command = positionals.shift() ?? "";
  return res;
}

async function output(text: string, out?: string): Promise<void> {
  if (out) {
    await writeFile(out, text, "utf8");
    process.stderr.write(`written: ${out}\n`);
  } else {
    process.stdout.write(text + "\n");
  }
}

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const useColor = args.color && process.stdout.isTTY === true && !process.env.NO_COLOR;

  if (!args.command || args.command === "-h" || args.command === "--help" || args.command === "help") {
    process.stdout.write(HELP + "\n");
    return 0;
  }
  if (args.command === "-v" || args.command === "--version" || args.command === "version") {
    process.stdout.write(VERSION + "\n");
    return 0;
  }

  if (args.command === "providers") {
    const providers = await detectProviders();
    if (args.format === "json") await output(JSON.stringify(providers, null, 2), args.out);
    else await output(renderProviders(providers, useColor), args.out);
    return 0;
  }

  if (args.command === "mcp") {
    await import("../mcp/stdio.js");
    // The stdio server runs until stdin closes, at which point it exits the
    // process itself. Never resolve here, so the CLI does not exit first.
    return new Promise<number>(() => {});
  }

  // Commands below take a target.
  const target =
    args.command === "js" ? args.positionals[1] : args.positionals[0];
  if (args.command === "js") args.sub = args.positionals[0];

  if (!target) {
    process.stderr.write(`error: command "${args.command}" needs a target path\n\n${HELP}\n`);
    return 2;
  }

  try {
    switch (args.command) {
      case "inspect":
      case "report": {
        const report = await analyzePath(target, {
          ...(args.only ? { only: args.only } : {}),
          ...(args.minLength ? { minStringLength: args.minLength } : {}),
          ...(args.maxStrings ? { maxStrings: args.maxStrings } : {}),
        });
        const fmt: ReportFormat = args.command === "report" && args.format === "terminal" ? "markdown" : args.format;
        await output(renderReport(report, fmt, useColor), args.out);
        return 0;
      }
      case "strings": {
        const { buffer } = await ingestTarget(target);
        if (!buffer) throw new Error("target is a directory");
        const strings = extractStrings(buffer, {
          minLength: args.minLength ?? 4,
          max: args.maxStrings ?? 5000,
        });
        if (args.format === "json") await output(JSON.stringify(strings, null, 2), args.out);
        else await output(strings.map((s) => s.value).join("\n"), args.out);
        return 0;
      }
      case "dependencies":
        return analyzeAndFilter(target, ["dependency"], args, useColor);
      case "symbols":
        return analyzeAndFilter(target, ["symbol", "export"], args, useColor);
      case "imports":
        return analyzeAndFilter(target, ["import"], args, useColor);
      case "resources":
        return analyzeAndFilter(target, ["resource", "manifest"], args, useColor);
      case "js": {
        const report = await analyzePath(target, { only: ["javascript", "dependencies", "metadata"] });
        await output(renderReport(report, args.format, useColor), args.out);
        return 0;
      }
      case "graph": {
        const report = await analyzePath(target);
        const graph = buildGraph([report]);
        await output(JSON.stringify(graph, null, 2), args.out);
        return 0;
      }
      default:
        process.stderr.write(`error: unknown command "${args.command}"\n\n${HELP}\n`);
        return 2;
    }
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return 1;
  }
}

async function analyzeAndFilter(
  target: string,
  categories: string[],
  args: ParsedArgs,
  useColor: boolean,
): Promise<number> {
  const report = await analyzePath(target);
  const filtered = { ...report, findings: report.findings.filter((f) => categories.includes(f.category)) };
  if (filtered.findings.length === 0) {
    const applicable = providersForFormat(report.artifact.format);
    process.stderr.write(
      `no ${categories.join("/")} findings for ${report.artifact.format} artifact.` +
        (applicable.length ? ` Providers that could add more: ${applicable.map((p) => p.name).join(", ")}\n` : "\n"),
    );
  }
  await output(renderReport(filtered, args.format, useColor), args.out);
  return 0;
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((e) => {
    process.stderr.write(`fatal: ${(e as Error).message}\n`);
    process.exit(1);
  });
