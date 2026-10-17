/**
 * Minimal, original Portable Executable (PE/PE32+) parser.
 *
 * Parses the DOS stub pointer, COFF file header, optional header, section
 * table, and the import/export data directories. This is a reader only; it
 * does not execute or modify anything. Format reference: the public PE/COFF
 * specification.
 */
import { ByteReader, cString } from "../util/reader.js";

export interface PeSection {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  rawSize: number;
  rawPointer: number;
  characteristics: number;
  flags: string[];
}

export interface PeImport {
  dll: string;
  functions: string[];
}

export interface PeInfo {
  machine: string;
  machineRaw: number;
  is64: boolean;
  isDll: boolean;
  subsystem: string;
  numberOfSections: number;
  timeDateStamp: number;
  timeDateIso: string | null;
  entryPointRva: number;
  imageBase: string;
  dotnet: boolean;
  sections: PeSection[];
  imports: PeImport[];
  exports: string[];
  dllCharacteristics: string[];
  warnings: string[];
}

const MACHINE: Record<number, string> = {
  0x014c: "x86 (i386)",
  0x8664: "x86-64 (AMD64)",
  0x01c0: "ARM",
  0xaa64: "ARM64",
  0x01c4: "ARMv7 (Thumb-2)",
  0x0200: "Itanium",
  0x5032: "RISC-V 32",
  0x5064: "RISC-V 64",
};

const SUBSYSTEM: Record<number, string> = {
  1: "native",
  2: "Windows GUI",
  3: "Windows console",
  5: "OS/2 console",
  7: "POSIX console",
  9: "Windows CE GUI",
  10: "EFI application",
  16: "Windows boot application",
};

const SECTION_FLAGS: [number, string][] = [
  [0x00000020, "code"],
  [0x00000040, "initialized-data"],
  [0x00000080, "uninitialized-data"],
  [0x02000000, "discardable"],
  [0x10000000, "shared"],
  [0x20000000, "execute"],
  [0x40000000, "read"],
  [0x80000000, "write"],
];

const DLL_CHARS: [number, string][] = [
  [0x0040, "dynamic-base (ASLR)"],
  [0x0080, "force-integrity"],
  [0x0100, "nx-compatible (DEP)"],
  [0x0200, "no-isolation"],
  [0x0400, "no-seh"],
  [0x0800, "no-bind"],
  [0x1000, "appcontainer"],
  [0x2000, "wdm-driver"],
  [0x4000, "control-flow-guard"],
  [0x8000, "terminal-server-aware"],
];

function flagsFor(value: number, table: [number, string][]): string[] {
  return table.filter(([bit]) => (value & bit) !== 0).map(([, name]) => name);
}

function rvaToOffset(rva: number, sections: PeSection[]): number | null {
  for (const s of sections) {
    const size = Math.max(s.rawSize, s.virtualSize);
    if (rva >= s.virtualAddress && rva < s.virtualAddress + size) {
      return s.rawPointer + (rva - s.virtualAddress);
    }
  }
  return null;
}

export function parsePe(buf: Buffer): PeInfo {
  const warnings: string[] = [];
  const r = new ByteReader(buf);
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) {
    throw new Error("not a PE/MZ file");
  }
  const peOff = buf.readUInt32LE(0x3c);
  if (peOff + 24 > buf.length || buf.readUInt32LE(peOff) !== 0x00004550) {
    throw new Error("missing PE signature");
  }

  r.seek(peOff + 4); // COFF file header
  const machineRaw = r.u16le();
  const numberOfSections = r.u16le();
  const timeDateStamp = r.u32le();
  r.skip(4 + 4); // ptr to symbol table + number of symbols (deprecated)
  const sizeOfOptionalHeader = r.u16le();
  const characteristics = r.u16le();
  const isDll = (characteristics & 0x2000) !== 0;

  const optStart = r.offset;
  const magic = r.u16le();
  const is64 = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) warnings.push(`unusual optional-header magic 0x${magic.toString(16)}`);

  r.skip(2); // major/minor linker version
  r.skip(4 * 3); // sizeOfCode, sizeOfInitData, sizeOfUninitData
  const entryPointRva = r.u32le();
  r.skip(4); // baseOfCode
  let imageBase: bigint;
  if (is64) {
    imageBase = r.u64le();
  } else {
    r.skip(4); // baseOfData (PE32 only)
    imageBase = BigInt(r.u32le());
  }
  r.skip(4 * 2); // section/file alignment
  r.skip(2 * 6); // OS/image/subsystem version fields
  r.skip(4); // win32 version
  r.skip(4 * 2); // sizeOfImage, sizeOfHeaders
  r.skip(4); // checksum
  const subsystemRaw = r.u16le();
  const dllCharacteristics = r.u16le();
  // size-of-stack/heap reserve+commit: 4 words, 8 bytes each on PE32+, 4 on PE32
  r.skip((is64 ? 8 : 4) * 4);
  r.skip(4); // loader flags
  const numberOfRvaAndSizes = r.u32le();

  const dataDirs: { rva: number; size: number }[] = [];
  for (let i = 0; i < Math.min(numberOfRvaAndSizes, 16); i++) {
    if (r.remaining < 8) break;
    dataDirs.push({ rva: r.u32le(), size: r.u32le() });
  }

  // Section table immediately follows the optional header.
  const sections: PeSection[] = [];
  r.seek(optStart + sizeOfOptionalHeader);
  for (let i = 0; i < numberOfSections; i++) {
    if (r.remaining < 40) {
      warnings.push("section table truncated");
      break;
    }
    const name = r.fixedString(8);
    const virtualSize = r.u32le();
    const virtualAddress = r.u32le();
    const rawSize = r.u32le();
    const rawPointer = r.u32le();
    r.skip(4 * 3 + 2 * 2); // relocations/linenumbers pointers and counts
    const flags = r.u32le();
    sections.push({
      name,
      virtualSize,
      virtualAddress,
      rawSize,
      rawPointer,
      characteristics: flags,
      flags: flagsFor(flags, SECTION_FLAGS),
    });
  }

  const dotnet = (dataDirs[14]?.size ?? 0) > 0; // COM descriptor directory
  const imports = parseImports(buf, dataDirs[1], sections, warnings);
  const exports = parseExports(buf, dataDirs[0], sections, warnings);

  return {
    machine: MACHINE[machineRaw] ?? `unknown (0x${machineRaw.toString(16)})`,
    machineRaw,
    is64,
    isDll,
    subsystem: SUBSYSTEM[subsystemRaw] ?? `unknown (${subsystemRaw})`,
    numberOfSections,
    timeDateStamp,
    timeDateIso: timeDateStamp > 0 ? new Date(timeDateStamp * 1000).toISOString() : null,
    entryPointRva,
    imageBase: "0x" + imageBase.toString(16),
    dotnet,
    sections,
    imports,
    exports,
    dllCharacteristics: flagsFor(dllCharacteristics, DLL_CHARS),
    warnings,
  };
}

function parseImports(
  buf: Buffer,
  dir: { rva: number; size: number } | undefined,
  sections: PeSection[],
  warnings: string[],
): PeImport[] {
  if (!dir || dir.rva === 0) return [];
  const base = rvaToOffset(dir.rva, sections);
  if (base === null) return [];
  const imports: PeImport[] = [];
  const is64 = false; // thunk width handled below via magic lookups not needed; names only
  void is64;

  try {
    for (let i = 0; i < 4096; i++) {
      const entry = base + i * 20;
      if (entry + 20 > buf.length) break;
      const r = new ByteReader(buf);
      r.seek(entry);
      const originalFirstThunk = r.u32le();
      r.skip(4 * 2); // timestamp, forwarder chain
      const nameRva = r.u32le();
      const firstThunk = r.u32le();
      if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break; // null terminator

      const nameOff = rvaToOffset(nameRva, sections);
      const dll = nameOff !== null ? cString(buf, nameOff, 256) : `<rva:0x${nameRva.toString(16)}>`;
      const thunkRva = originalFirstThunk || firstThunk;
      const functions = readImportNames(buf, thunkRva, sections);
      imports.push({ dll, functions });
      if (imports.length >= 512) {
        warnings.push("import table truncated at 512 DLLs");
        break;
      }
    }
  } catch (e) {
    warnings.push(`import parse stopped: ${(e as Error).message}`);
  }
  return imports;
}

function readImportNames(buf: Buffer, thunkRva: number, sections: PeSection[]): string[] {
  const names: string[] = [];
  const start = rvaToOffset(thunkRva, sections);
  if (start === null) return names;
  // Try 64-bit thunks first, fall back to 32-bit by probing high bits.
  for (const width of [8, 4] as const) {
    names.length = 0;
    const r = new ByteReader(buf);
    try {
      r.seek(start);
      for (let i = 0; i < 8192; i++) {
        if (r.remaining < width) break;
        const val = width === 8 ? r.u64le() : BigInt(r.u32le());
        if (val === 0n) break;
        const ordinalBit = width === 8 ? 1n << 63n : 1n << 31n;
        if ((val & ordinalBit) !== 0n) {
          names.push(`#${(val & 0xffffn).toString()}`); // import by ordinal
          continue;
        }
        const hintOff = rvaToOffset(Number(val & 0x7fffffffn), sections);
        if (hintOff === null) break;
        const fn = cString(buf, hintOff + 2, 256);
        if (fn) names.push(fn);
      }
      if (names.length > 0) return names;
    } catch {
      /* try the other width */
    }
  }
  return names;
}

function parseExports(
  buf: Buffer,
  dir: { rva: number; size: number } | undefined,
  sections: PeSection[],
  warnings: string[],
): string[] {
  if (!dir || dir.rva === 0) return [];
  const base = rvaToOffset(dir.rva, sections);
  if (base === null) return [];
  const out: string[] = [];
  try {
    const r = new ByteReader(buf);
    r.seek(base + 24); // skip to numberOfNames
    const numberOfNames = r.u32le();
    r.skip(4); // addressOfFunctions
    const addressOfNamesRva = r.u32le();
    const namesOff = rvaToOffset(addressOfNamesRva, sections);
    if (namesOff === null) return out;
    for (let i = 0; i < Math.min(numberOfNames, 8192); i++) {
      const ptr = namesOff + i * 4;
      if (ptr + 4 > buf.length) break;
      const nameRva = buf.readUInt32LE(ptr);
      const off = rvaToOffset(nameRva, sections);
      if (off === null) continue;
      const name = cString(buf, off, 256);
      if (name) out.push(name);
    }
  } catch (e) {
    warnings.push(`export parse stopped: ${(e as Error).message}`);
  }
  return out;
}
