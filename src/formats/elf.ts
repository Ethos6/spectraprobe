/**
 * Minimal, original ELF parser: header, sections, dynamic dependencies
 * (DT_NEEDED), SONAME, and dynamic symbol names. Reader only. Format
 * reference: the public System V ABI / ELF specification.
 */
import { ByteReader, cString } from "../util/reader.js";

export interface ElfSection {
  name: string;
  type: number;
  typeName: string;
  flags: string[];
  addr: string;
  offset: number;
  size: number;
}

export interface ElfInfo {
  class: "ELF32" | "ELF64";
  endianness: "little" | "big";
  type: string;
  machine: string;
  entry: string;
  sections: ElfSection[];
  neededLibraries: string[];
  soname: string | null;
  rpath: string[];
  dynamicSymbols: string[];
  stripped: boolean;
  warnings: string[];
}

const ET: Record<number, string> = {
  0: "none",
  1: "relocatable",
  2: "executable",
  3: "shared object (PIE/library)",
  4: "core dump",
};

const EM: Record<number, string> = {
  3: "x86 (i386)",
  62: "x86-64 (AMD64)",
  40: "ARM",
  183: "AArch64 (ARM64)",
  243: "RISC-V",
  8: "MIPS",
  21: "PowerPC64",
  2: "SPARC",
};

const SHT: Record<number, string> = {
  0: "NULL",
  1: "PROGBITS",
  2: "SYMTAB",
  3: "STRTAB",
  4: "RELA",
  6: "DYNAMIC",
  7: "NOTE",
  8: "NOBITS",
  9: "REL",
  11: "DYNSYM",
  14: "INIT_ARRAY",
  15: "FINI_ARRAY",
};

const SH_FLAGS: [number, string][] = [
  [0x1, "write"],
  [0x2, "alloc"],
  [0x4, "execute"],
  [0x10, "merge"],
  [0x20, "strings"],
  [0x200, "tls"],
];

export function parseElf(buf: Buffer): ElfInfo {
  const warnings: string[] = [];
  if (buf.length < 0x40 || buf.readUInt32BE(0) !== 0x7f454c46) throw new Error("not an ELF file");
  const is64 = buf[4] === 2;
  const little = buf[5] === 1;
  const r = new ByteReader(buf);
  const u16 = () => (little ? r.u16le() : r.u16be());
  const u32 = () => (little ? r.u32le() : r.u32be());
  const uWord = (): bigint => (is64 ? (little ? r.u64le() : r.u64be()) : BigInt(u32()));

  r.seek(16); // skip e_ident
  const eType = u16();
  const eMachine = u16();
  u32(); // e_version
  const entry = uWord();
  uWord(); // e_phoff
  const shoff = uWord();
  u32(); // e_flags
  u16(); // e_ehsize
  u16(); // e_phentsize
  u16(); // e_phnum
  const shentsize = u16();
  const shnum = u16();
  const shstrndx = u16();

  const sections: ElfSection[] = [];
  const rawSections: { nameOff: number; type: number; flags: bigint; addr: bigint; offset: number; size: number; link: number }[] = [];
  const shoffNum = Number(shoff);

  if (shoffNum > 0 && shnum > 0 && shoffNum + shnum * shentsize <= buf.length) {
    for (let i = 0; i < shnum; i++) {
      r.seek(shoffNum + i * shentsize);
      const nameOff = u32();
      const type = u32();
      const flags = uWord();
      const addr = uWord();
      const offset = Number(uWord());
      const size = Number(uWord());
      const link = u32();
      rawSections.push({ nameOff, type, flags, addr, offset, size, link });
    }
    // Resolve section names via the section header string table.
    const shstr = rawSections[shstrndx];
    const strBase = shstr ? shstr.offset : -1;
    for (const s of rawSections) {
      const name = strBase >= 0 ? cString(buf, strBase + s.nameOff, 256) : "";
      sections.push({
        name,
        type: s.type,
        typeName: SHT[s.type] ?? `0x${s.type.toString(16)}`,
        flags: SH_FLAGS.filter(([bit]) => (Number(s.flags) & bit) !== 0).map(([, n]) => n),
        addr: "0x" + s.addr.toString(16),
        offset: s.offset,
        size: s.size,
      });
    }
  } else {
    warnings.push("section header table missing or out of range");
  }

  const { needed, soname, rpath } = parseDynamic(buf, rawSections, sections, is64, little, warnings);
  const dynamicSymbols = parseDynSym(buf, rawSections, sections, is64, little);
  const stripped = !sections.some((s) => s.typeName === "SYMTAB");

  return {
    class: is64 ? "ELF64" : "ELF32",
    endianness: little ? "little" : "big",
    type: ET[eType] ?? `0x${eType.toString(16)}`,
    machine: EM[eMachine] ?? `unknown (${eMachine})`,
    entry: "0x" + entry.toString(16),
    sections,
    neededLibraries: needed,
    soname,
    rpath,
    dynamicSymbols,
    stripped,
    warnings,
  };
}

interface RawSection {
  nameOff: number;
  type: number;
  flags: bigint;
  addr: bigint;
  offset: number;
  size: number;
  link: number;
}

function parseDynamic(
  buf: Buffer,
  raw: RawSection[],
  sections: ElfSection[],
  is64: boolean,
  little: boolean,
  warnings: string[],
): { needed: string[]; soname: string | null; rpath: string[] } {
  const needed: string[] = [];
  const rpath: string[] = [];
  let soname: string | null = null;
  const dynIdx = sections.findIndex((s) => s.typeName === "DYNAMIC");
  if (dynIdx === -1) return { needed, soname, rpath };
  const dyn = raw[dynIdx]!;
  const strtab = raw[dyn.link];
  if (!strtab) {
    warnings.push("dynamic string table not linked");
    return { needed, soname, rpath };
  }

  const r = new ByteReader(buf);
  const uWord = (): bigint => (is64 ? (little ? r.u64le() : r.u64be()) : BigInt(little ? r.u32le() : r.u32be()));
  const entrySize = is64 ? 16 : 8;
  const count = Math.floor(dyn.size / entrySize);
  const strBase = strtab.offset;
  try {
    for (let i = 0; i < count; i++) {
      r.seek(dyn.offset + i * entrySize);
      const tag = Number(uWord());
      const val = Number(uWord());
      if (tag === 0) break; // DT_NULL
      if (tag === 1) needed.push(cString(buf, strBase + val, 256)); // DT_NEEDED
      else if (tag === 14) soname = cString(buf, strBase + val, 256); // DT_SONAME
      else if (tag === 15 || tag === 29) rpath.push(cString(buf, strBase + val, 512)); // DT_RPATH/RUNPATH
    }
  } catch (e) {
    warnings.push(`dynamic section parse stopped: ${(e as Error).message}`);
  }
  return { needed, soname, rpath };
}

function parseDynSym(
  buf: Buffer,
  raw: RawSection[],
  sections: ElfSection[],
  is64: boolean,
  little: boolean,
): string[] {
  const idx = sections.findIndex((s) => s.typeName === "DYNSYM");
  if (idx === -1) return [];
  const sym = raw[idx]!;
  const strtab = raw[sym.link];
  if (!strtab) return [];
  const names: string[] = [];
  const entrySize = is64 ? 24 : 16;
  const count = Math.min(Math.floor(sym.size / entrySize), 20000);
  const r = new ByteReader(buf);
  const u32 = () => (little ? r.u32le() : r.u32be());
  try {
    for (let i = 0; i < count; i++) {
      r.seek(sym.offset + i * entrySize);
      const nameOff = u32();
      if (nameOff === 0) continue;
      const name = cString(buf, strtab.offset + nameOff, 256);
      if (name) names.push(name);
    }
  } catch {
    /* stop on truncation */
  }
  return Array.from(new Set(names));
}
