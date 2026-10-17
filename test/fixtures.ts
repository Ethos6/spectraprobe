/**
 * Deterministic in-memory fixtures for the test suite. Each builder hand-crafts
 * a minimal but structurally valid file of the given format, so tests do not
 * depend on any particular binary being present on the host.
 */
import { deflateRawSync } from "node:zlib";
import { crc32 } from "../src/util/hash.js";

/** Minimal 64-bit PE (PE32+) for x86-64 with one section, one import and one export. */
export function makePe(): Buffer {
  const SIZE = 0x600;
  const buf = Buffer.alloc(SIZE);
  // DOS header
  buf.write("MZ", 0, "latin1");
  const peOff = 0x80;
  buf.writeUInt32LE(peOff, 0x3c);
  // PE signature + COFF header
  buf.write("PE\0\0", peOff, "latin1");
  const coff = peOff + 4;
  buf.writeUInt16LE(0x8664, coff); // machine x86-64
  buf.writeUInt16LE(1, coff + 2); // numberOfSections
  buf.writeUInt32LE(0x66000000, coff + 4); // timeDateStamp
  const sizeOfOptional = 0xf0;
  buf.writeUInt16LE(sizeOfOptional, coff + 16);
  buf.writeUInt16LE(0x2022, coff + 18); // characteristics (executable + large address aware)
  // Optional header (PE32+)
  const opt = coff + 20;
  buf.writeUInt16LE(0x20b, opt); // magic PE32+
  buf.writeUInt32LE(0x1000, opt + 16); // entry point RVA
  buf.writeBigUInt64LE(0x140000000n, opt + 24); // image base
  buf.writeUInt16LE(3, opt + 68); // subsystem = console
  buf.writeUInt16LE(0x4160, opt + 70); // dll characteristics: ASLR | DEP | CFG
  buf.writeUInt32LE(16, opt + 108); // numberOfRvaAndSizes
  const dataDir = opt + 112;
  // Export directory [0] and Import directory [1]. Keep everything inside the
  // single section mapped at RVA 0x1000 (file 0x400), which spans RVA 0x1000..0x1200.
  const importRva = 0x1080;
  const exportRva = 0x10c0;
  buf.writeUInt32LE(exportRva, dataDir + 0 * 8);
  buf.writeUInt32LE(40, dataDir + 0 * 8 + 4);
  buf.writeUInt32LE(importRva, dataDir + 1 * 8);
  buf.writeUInt32LE(40, dataDir + 1 * 8 + 4);
  // Section header ".text" mapping RVA 0x1000.. to file offset 0x400
  const sec = opt + sizeOfOptional;
  buf.write(".text", sec, "latin1");
  buf.writeUInt32LE(0x1000, sec + 8); // virtualSize
  buf.writeUInt32LE(0x1000, sec + 12); // virtualAddress
  buf.writeUInt32LE(0x200, sec + 16); // rawSize
  buf.writeUInt32LE(0x400, sec + 20); // rawPointer
  buf.writeUInt32LE(0x60000020, sec + 36); // code | execute | read

  // Lay out import/export structures inside the mapped section (file off = rva - 0x1000 + 0x400)
  const toFile = (rva: number) => rva - 0x1000 + 0x400;
  // Import descriptor
  const impOff = toFile(importRva);
  const oftRva = 0x1100;
  const dllNameRva = 0x1120;
  const thunkNameRva = 0x1140;
  buf.writeUInt32LE(oftRva, impOff + 0); // OriginalFirstThunk
  buf.writeUInt32LE(dllNameRva, impOff + 12); // Name RVA
  buf.writeUInt32LE(oftRva, impOff + 16); // FirstThunk
  // null descriptor already zero at impOff+20..
  buf.writeBigUInt64LE(BigInt(thunkNameRva), toFile(oftRva)); // thunk -> hint/name
  buf.writeBigUInt64LE(0n, toFile(oftRva) + 8); // terminator
  buf.write("KERNEL32.dll\0", toFile(dllNameRva), "latin1");
  buf.writeUInt16LE(0, toFile(thunkNameRva)); // hint
  buf.write("ExitProcess\0", toFile(thunkNameRva) + 2, "latin1");

  // Export directory
  const expOff = toFile(exportRva);
  buf.writeUInt32LE(1, expOff + 24); // numberOfNames
  const addrOfNamesRva = 0x1160;
  buf.writeUInt32LE(addrOfNamesRva, expOff + 32);
  const expNameRva = 0x1170;
  buf.writeUInt32LE(expNameRva, toFile(addrOfNamesRva));
  buf.write("DoWork\0", toFile(expNameRva), "latin1");

  return buf;
}

/** Minimal 64-bit little-endian ELF shared object with a section header table. */
export function makeElf(): Buffer {
  const buf = Buffer.alloc(0x400);
  buf.writeUInt32BE(0x7f454c46, 0); // magic
  buf[4] = 2; // 64-bit
  buf[5] = 1; // little-endian
  buf[6] = 1; // version
  buf.writeUInt16LE(3, 16); // e_type = DYN (shared object)
  buf.writeUInt16LE(62, 18); // e_machine = x86-64
  buf.writeUInt32LE(1, 20); // e_version
  buf.writeBigUInt64LE(0x1040n, 24); // e_entry
  const shoff = 0x100n;
  buf.writeBigUInt64LE(shoff, 40); // e_shoff
  buf.writeUInt16LE(64, 52); // e_ehsize
  buf.writeUInt16LE(64, 58); // e_shentsize
  buf.writeUInt16LE(3, 60); // e_shnum
  buf.writeUInt16LE(2, 62); // e_shstrndx

  const sh = Number(shoff);
  const entry = 64;
  // Section 0: NULL (all zero)
  // Section 1: .text (PROGBITS)
  const s1 = sh + entry;
  buf.writeUInt32LE(1, s1 + 0); // name offset -> ".text"
  buf.writeUInt32LE(1, s1 + 4); // type PROGBITS
  buf.writeBigUInt64LE(6n, s1 + 8); // flags alloc+execute
  // Section 2: .shstrtab (STRTAB)
  const s2 = sh + 2 * entry;
  const strtabOff = 0x2a0;
  buf.writeUInt32LE(7, s2 + 0); // name offset -> ".shstrtab"
  buf.writeUInt32LE(3, s2 + 4); // type STRTAB
  buf.writeBigUInt64LE(BigInt(strtabOff), s2 + 24); // offset
  buf.writeBigUInt64LE(32n, s2 + 32); // size
  // String table contents
  buf.write("\0.text\0.shstrtab\0", strtabOff, "latin1");
  return buf;
}

/** Minimal 64-bit little-endian Mach-O executable with one LC_LOAD_DYLIB. */
export function makeMacho(): Buffer {
  const buf = Buffer.alloc(0x200);
  buf.writeUInt32LE(0xfeedfacf, 0); // magic 64 LE
  buf.writeUInt32LE(0x01000007, 4); // cputype x86-64
  buf.writeUInt32LE(3, 8); // cpusubtype
  buf.writeUInt32LE(2, 12); // filetype executable
  buf.writeUInt32LE(1, 16); // ncmds
  const sizeofcmds = 0x30;
  buf.writeUInt32LE(sizeofcmds, 20);
  buf.writeUInt32LE(0, 24); // flags
  // reserved at 28 for 64-bit
  const lc = 32;
  const name = "/usr/lib/libSystem.B.dylib\0";
  const cmdSize = 24 + Math.ceil(name.length / 8) * 8;
  buf.writeUInt32LE(0x0c, lc); // LC_LOAD_DYLIB
  buf.writeUInt32LE(cmdSize, lc + 4);
  buf.writeUInt32LE(24, lc + 8); // name offset within command
  buf.write(name, lc + 24, "latin1");
  buf.writeUInt32LE(1, 16); // ensure ncmds=1
  buf.writeUInt32LE(cmdSize, 20); // sizeofcmds exact
  return buf;
}

/** Minimal WASM module: header + a type/import/export section with named entries. */
export function makeWasm(): Buffer {
  const parts: number[] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  const enc = (s: string) => {
    const b = Buffer.from(s, "utf8");
    return [b.length, ...b];
  };
  // import section (id 2): one import env.memory (kind 2 memory, limits flags 0, min 1)
  const imp = [
    1, // count
    ...enc("env"),
    ...enc("log"),
    0x00, // kind = function
    0, // type index
  ];
  parts.push(2, imp.length, ...imp);
  // export section (id 7): one export "run" kind func index 0
  const exp = [1, ...enc("run"), 0x00, 0];
  parts.push(7, exp.length, ...exp);
  return Buffer.from(parts);
}

/** Build a minimal ZIP from entries. Uses deflate; falls back to stored. */
export function makeZip(entries: { name: string; content: string }[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, "utf8");
    const data = Buffer.from(e.content, "utf8");
    const compressed = deflateRawSync(data);
    const useDeflate = compressed.length < data.length;
    const stored = useDeflate ? compressed : data;
    const method = useDeflate ? 8 : 0;
    const crc = parseInt(crc32(data), 16);

    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc >>> 0, 14);
    local.writeUInt32LE(stored.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    nameBuf.copy(local, 30);
    locals.push(local, stored);

    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc >>> 0, 16);
    central.writeUInt32LE(stored.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    nameBuf.copy(central, 46);
    centrals.push(central);

    offset += local.length + stored.length;
  }

  const centralDir = Buffer.concat(centrals);
  const localData = Buffer.concat(locals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(localData.length, 16);
  return Buffer.concat([localData, centralDir, eocd]);
}

/** A JAR is a ZIP with a manifest and at least one .class entry. */
export function makeJar(): Buffer {
  return makeZip([
    { name: "META-INF/MANIFEST.MF", content: "Manifest-Version: 1.0\r\nMain-Class: com.example.App\r\n" },
    { name: "com/example/App.class", content: "\xca\xfe\xba\xbe\x00\x00\x00\x34 fake class bytes for test" },
  ]);
}
