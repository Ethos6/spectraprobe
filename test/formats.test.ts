import { describe, it, expect } from "vitest";
import { makePe, makeElf, makeMacho, makeWasm, makeZip, makeJar } from "./fixtures.js";
import { identifyBuffer } from "../src/ingest/identify.js";
import { parsePe } from "../src/formats/pe.js";
import { parseElf } from "../src/formats/elf.js";
import { parseMacho } from "../src/formats/macho.js";
import { parseWasm } from "../src/formats/wasm.js";
import { readZip, readZipText } from "../src/formats/zip.js";

describe("identification", () => {
  it("recognises each format from magic bytes", () => {
    expect(identifyBuffer(makePe(), "a.exe").format).toBe("pe");
    expect(identifyBuffer(makeElf(), "a.so").format).toBe("elf");
    expect(identifyBuffer(makeMacho(), "a").format).toBe("macho");
    expect(identifyBuffer(makeWasm(), "a.wasm").format).toBe("wasm");
    expect(identifyBuffer(makeJar(), "a.jar").format).toBe("jar");
    expect(identifyBuffer(makeZip([{ name: "x.txt", content: "hi" }]), "a.zip").format).toBe("zip");
    expect(identifyBuffer(Buffer.from("const x = 1;\n"), "a.js").format).toBe("javascript");
    expect(identifyBuffer(Buffer.from("just some plain text here"), "a.txt").format).toBe("text");
    expect(identifyBuffer(Buffer.from([0, 1, 2, 3, 255, 254]), "a.bin").format).toBe("data");
  });
});

describe("PE parser", () => {
  const pe = parsePe(makePe());
  it("reads machine, bitness and entry point", () => {
    expect(pe.machine).toContain("x86-64");
    expect(pe.is64).toBe(true);
    expect(pe.entryPointRva).toBe(0x1000);
  });
  it("extracts imports with function names", () => {
    expect(pe.imports.length).toBe(1);
    expect(pe.imports[0]!.dll).toBe("KERNEL32.dll");
    expect(pe.imports[0]!.functions).toContain("ExitProcess");
  });
  it("extracts exports and sections and security flags", () => {
    expect(pe.exports).toContain("DoWork");
    expect(pe.sections.map((s) => s.name)).toContain(".text");
    expect(pe.dllCharacteristics).toContain("dynamic-base (ASLR)");
    expect(pe.dllCharacteristics).toContain("control-flow-guard");
  });
  it("rejects non-PE input", () => {
    expect(() => parsePe(Buffer.from("not a pe"))).toThrow();
  });
});

describe("ELF parser", () => {
  const elf = parseElf(makeElf());
  it("reads class, type and machine", () => {
    expect(elf.class).toBe("ELF64");
    expect(elf.type).toContain("shared object");
    expect(elf.machine).toContain("x86-64");
  });
  it("resolves section names", () => {
    expect(elf.sections.map((s) => s.name)).toContain(".text");
    expect(elf.sections.map((s) => s.name)).toContain(".shstrtab");
  });
});

describe("Mach-O parser", () => {
  const mo = parseMacho(makeMacho());
  it("reads a thin 64-bit binary and its linked libraries", () => {
    expect(mo.fat).toBe(false);
    const arch = mo.architectures[0]!;
    expect(arch.is64).toBe(true);
    expect(arch.cpuType).toContain("x86-64");
    expect(arch.linkedLibraries).toContain("/usr/lib/libSystem.B.dylib");
  });
});

describe("WASM parser", () => {
  const w = parseWasm(makeWasm());
  it("reads version, imports and exports", () => {
    expect(w.version).toBe(1);
    expect(w.imports.some((i) => i.module === "env" && i.name === "log")).toBe(true);
    expect(w.exports.some((e) => e.name === "run")).toBe(true);
  });
});

describe("ZIP reader", () => {
  it("lists entries and reads text content", () => {
    const zip = makeZip([
      { name: "hello.txt", content: "hello world" },
      { name: "dir/data.json", content: '{"a":1}' },
    ]);
    const listing = readZip(zip);
    expect(listing.entries.map((e) => e.name)).toEqual(["hello.txt", "dir/data.json"]);
    expect(readZipText(zip, listing, "hello.txt")).toBe("hello world");
    expect(readZipText(zip, listing, "dir/data.json")).toBe('{"a":1}');
  });
  it("reads a JAR manifest", () => {
    const jar = makeJar();
    const listing = readZip(jar);
    const manifest = readZipText(jar, listing, "META-INF/MANIFEST.MF");
    expect(manifest).toContain("Main-Class: com.example.App");
  });
});
