import type { ArtifactFormat } from "../types.js";

export interface Identification {
  format: ArtifactFormat;
  description: string;
  mime: string;
}

function startsWith(buf: Buffer, sig: number[], at = 0): boolean {
  if (buf.length < at + sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (buf[at + i] !== sig[i]) return false;
  return true;
}

/** Does the ZIP central directory contain an entry whose name starts with `prefix`? */
function zipHasEntryPrefix(buf: Buffer, prefix: string): boolean {
  // Scan for central directory file headers (PK\x01\x02) and check names.
  const sig = Buffer.from([0x50, 0x4b, 0x01, 0x02]);
  let idx = buf.indexOf(sig);
  let guard = 0;
  while (idx !== -1 && guard++ < 5000) {
    if (idx + 46 <= buf.length) {
      const nameLen = buf.readUInt16LE(idx + 28);
      const name = buf.subarray(idx + 46, idx + 46 + nameLen).toString("latin1");
      if (name.startsWith(prefix)) return true;
    }
    idx = buf.indexOf(sig, idx + 4);
  }
  return false;
}

function looksLikeText(buf: Buffer): boolean {
  const n = Math.min(buf.length, 4096);
  if (n === 0) return false;
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const b = buf[i]!;
    if (b === 0) return false; // NUL => binary
    if (b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b <= 0x7e) || b >= 0x80) printable++;
  }
  return printable / n > 0.85;
}

/**
 * Identify a buffer's format from magic bytes and lightweight structure checks.
 * `filename` is used only as a tie-breaker (e.g. ZIP vs JAR vs APK).
 */
export function identifyBuffer(buf: Buffer, filename = ""): Identification {
  const ext = filename.toLowerCase().split(".").pop() ?? "";

  // ELF: 0x7F 'E' 'L' 'F'
  if (startsWith(buf, [0x7f, 0x45, 0x4c, 0x46])) {
    const is64 = buf[4] === 2;
    return {
      format: "elf",
      description: `ELF ${is64 ? "64-bit" : "32-bit"} object`,
      mime: "application/x-elf",
    };
  }

  // Mach-O (32/64, both endiannesses) and fat/universal binaries
  const be32 = buf.length >= 4 ? buf.readUInt32BE(0) : 0;
  const machoMagics = new Set([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe]);
  const fatMagics = new Set([0xcafebabe, 0xbebafeca]);
  if (machoMagics.has(be32)) {
    const is64 = be32 === 0xfeedfacf || be32 === 0xcffaedfe;
    return {
      format: "macho",
      description: `Mach-O ${is64 ? "64-bit" : "32-bit"} object`,
      mime: "application/x-mach-binary",
    };
  }
  // 0xCAFEBABE collides between Mach-O fat binaries and Java .class files.
  // Java .class has major version >= 45 at bytes 6-7; fat binaries have a small nfat_arch.
  if (be32 === 0xcafebabe) {
    const word2 = buf.length >= 8 ? buf.readUInt32BE(4) : 0;
    const major = buf.length >= 8 ? buf.readUInt16BE(6) : 0;
    if (major >= 45 && ext !== "") {
      // defer; handled below if .class
    }
    if (major >= 45 && (ext === "class" || word2 > 0x2d)) {
      return { format: "class", description: "Java class file", mime: "application/java-vm" };
    }
    return { format: "macho", description: "Mach-O universal (fat) binary", mime: "application/x-mach-binary" };
  }
  if (be32 === 0xcafebabe || fatMagics.has(be32)) {
    return { format: "macho", description: "Mach-O universal (fat) binary", mime: "application/x-mach-binary" };
  }

  // PE / MZ
  if (startsWith(buf, [0x4d, 0x5a])) {
    // Follow e_lfanew to the PE signature.
    if (buf.length >= 0x40) {
      const peOff = buf.readUInt32LE(0x3c);
      if (peOff + 4 <= buf.length && startsWith(buf, [0x50, 0x45, 0x00, 0x00], peOff)) {
        return { format: "pe", description: "PE (Portable Executable)", mime: "application/vnd.microsoft.portable-executable" };
      }
    }
    return { format: "data", description: "DOS/MZ executable (no PE header)", mime: "application/x-dosexec" };
  }

  // WebAssembly: '\0asm' + version
  if (startsWith(buf, [0x00, 0x61, 0x73, 0x6d])) {
    return { format: "wasm", description: "WebAssembly binary module", mime: "application/wasm" };
  }

  // Dalvik .dex
  if (startsWith(buf, [0x64, 0x65, 0x78, 0x0a])) {
    return { format: "dex", description: "Android DEX (Dalvik executable)", mime: "application/octet-stream" };
  }

  // ZIP family: PK\x03\x04 (local) or PK\x05\x06 (empty archive)
  if (startsWith(buf, [0x50, 0x4b, 0x03, 0x04]) || startsWith(buf, [0x50, 0x4b, 0x05, 0x06])) {
    if (ext === "apk" || zipHasEntryPrefix(buf, "AndroidManifest.xml") || zipHasEntryPrefix(buf, "classes.dex")) {
      return { format: "apk", description: "Android package (APK)", mime: "application/vnd.android.package-archive" };
    }
    if (ext === "jar" || ext === "war" || zipHasEntryPrefix(buf, "META-INF/MANIFEST.MF")) {
      return { format: "jar", description: "Java archive (JAR)", mime: "application/java-archive" };
    }
    return { format: "zip", description: "ZIP archive", mime: "application/zip" };
  }

  // Electron asar: header is a pickled UInt32 size then a JSON header.
  if (ext === "asar" && buf.length > 16) {
    return { format: "electron-asar", description: "Electron asar archive", mime: "application/octet-stream" };
  }

  // Source files by extension when they look like text.
  if (looksLikeText(buf)) {
    if (["js", "mjs", "cjs", "jsx", "ts", "tsx"].includes(ext)) {
      return { format: "javascript", description: `JavaScript/TypeScript source (.${ext})`, mime: "text/javascript" };
    }
    return { format: "text", description: "Text", mime: "text/plain" };
  }

  return { format: "data", description: "Unrecognised binary data", mime: "application/octet-stream" };
}
