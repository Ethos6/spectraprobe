/**
 * Minimal, original Mach-O parser: header, load commands, segments/sections,
 * linked dynamic libraries (LC_LOAD_DYLIB) and UUID. Handles 32/64-bit and
 * both endiannesses, and reports fat/universal binaries. Reader only.
 */
import { ByteReader } from "../util/reader.js";

export interface MachoSection {
  segment: string;
  name: string;
  addr: string;
  size: number;
  offset: number;
}

export interface MachoInfo {
  is64: boolean;
  endianness: "little" | "big";
  cpuType: string;
  fileType: string;
  uuid: string | null;
  sections: MachoSection[];
  linkedLibraries: string[];
  loadCommandCount: number;
  minOs: string | null;
  warnings: string[];
}

export interface MachoResult {
  fat: boolean;
  /** For a fat binary, one entry per contained architecture. */
  architectures: MachoInfo[];
}

const CPU: Record<number, string> = {
  7: "x86",
  0x01000007: "x86-64",
  12: "ARM",
  0x0100000c: "ARM64",
  18: "PowerPC",
  0x01000012: "PowerPC64",
};

const FILETYPE: Record<number, string> = {
  1: "object",
  2: "executable",
  3: "fixed VM library",
  4: "core dump",
  5: "preloaded executable",
  6: "dynamic library (dylib)",
  7: "dynamic linker",
  8: "bundle",
  9: "dylib stub",
  10: "debug symbols (dSYM)",
  11: "kext bundle",
};

function parseThin(buf: Buffer, start: number): MachoInfo {
  const warnings: string[] = [];
  const magic = buf.readUInt32BE(start);
  const is64 = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const little = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const r = new ByteReader(buf);
  r.seek(start);
  const u32 = () => (little ? r.u32le() : r.u32be());
  u32(); // magic
  const cpuType = u32();
  u32(); // cpuSubType
  const fileType = u32();
  const ncmds = u32();
  u32(); // sizeofcmds
  u32(); // flags
  if (is64) u32(); // reserved

  const sections: MachoSection[] = [];
  const linkedLibraries: string[] = [];
  let uuid: string | null = null;
  let minOs: string | null = null;

  let cmdOffset = r.offset;
  for (let i = 0; i < ncmds; i++) {
    if (cmdOffset + 8 > buf.length) {
      warnings.push("load commands truncated");
      break;
    }
    r.seek(cmdOffset);
    const cmd = u32();
    const cmdSize = u32();
    if (cmdSize < 8) {
      warnings.push("invalid load command size");
      break;
    }

    try {
      if (cmd === 0x19 || cmd === 0x1) {
        // LC_SEGMENT_64 / LC_SEGMENT
        const seg64 = cmd === 0x19;
        const segName = r.fixedString(16);
        r.skip(seg64 ? 8 * 4 : 4 * 4); // vmaddr/vmsize/fileoff/filesize
        r.skip(4 * 4); // maxprot/initprot/nsects/flags  (back up nsects below)
        r.seek(cmdOffset + (seg64 ? 64 : 48)); // nsects field position
        const nsects = u32();
        u32(); // flags
        let secPtr = r.offset;
        const secSize = seg64 ? 80 : 68;
        for (let s = 0; s < nsects; s++) {
          if (secPtr + secSize > buf.length) break;
          r.seek(secPtr);
          const sName = r.fixedString(16);
          const sSeg = r.fixedString(16);
          const addr = seg64 ? r.u64le() : BigInt(u32());
          const size = seg64 ? Number(r.u64le()) : u32();
          const offset = u32();
          sections.push({
            segment: sSeg || segName,
            name: sName,
            addr: "0x" + addr.toString(16),
            size,
            offset,
          });
          secPtr += secSize;
        }
      } else if (cmd === 0x0c || cmd === 0x0d || cmd === 0x1f) {
        // LC_LOAD_DYLIB / LC_ID_DYLIB / LC_REEXPORT_DYLIB
        r.seek(cmdOffset + 8);
        const nameOffset = u32();
        const nameAbs = cmdOffset + nameOffset;
        if (nameAbs < cmdOffset + cmdSize && nameAbs < buf.length) {
          const end = Math.min(cmdOffset + cmdSize, buf.length);
          let e = nameAbs;
          while (e < end && buf[e] !== 0) e++;
          const name = buf.subarray(nameAbs, e).toString("latin1");
          if (name && cmd !== 0x0d) linkedLibraries.push(name);
        }
      } else if (cmd === 0x1b) {
        // LC_UUID
        r.seek(cmdOffset + 8);
        const b = r.bytes(16);
        uuid = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
      } else if (cmd === 0x24 || cmd === 0x25 || cmd === 0x26 || cmd === 0x27) {
        // LC_VERSION_MIN_* / LC_BUILD_VERSION
        r.seek(cmdOffset + 8);
        const ver = u32();
        const major = (ver >> 16) & 0xffff;
        const minor = (ver >> 8) & 0xff;
        minOs = `${major}.${minor}`;
      }
    } catch (e) {
      warnings.push(`load command ${i} parse stopped: ${(e as Error).message}`);
    }

    cmdOffset += cmdSize;
  }

  return {
    is64,
    endianness: little ? "little" : "big",
    cpuType: CPU[cpuType] ?? `unknown (0x${cpuType.toString(16)})`,
    fileType: FILETYPE[fileType] ?? `0x${fileType.toString(16)}`,
    uuid,
    sections,
    linkedLibraries,
    loadCommandCount: ncmds,
    minOs,
    warnings,
  };
}

export function parseMacho(buf: Buffer): MachoResult {
  if (buf.length < 8) throw new Error("file too small for Mach-O");
  const magic = buf.readUInt32BE(0);

  if (magic === 0xcafebabe || magic === 0xbebafeca) {
    // Fat / universal binary: nfat_arch big-endian follows the magic.
    const nfat = buf.readUInt32BE(4);
    const archs: MachoInfo[] = [];
    for (let i = 0; i < Math.min(nfat, 32); i++) {
      const entry = 8 + i * 20;
      if (entry + 20 > buf.length) break;
      const offset = buf.readUInt32BE(entry + 8);
      if (offset + 4 <= buf.length) {
        try {
          archs.push(parseThin(buf, offset));
        } catch {
          /* skip malformed slice */
        }
      }
    }
    return { fat: true, architectures: archs };
  }

  return { fat: false, architectures: [parseThin(buf, 0)] };
}
