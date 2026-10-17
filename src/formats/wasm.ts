/**
 * Minimal, original WebAssembly module parser: section table, plus the import
 * and export entries (names and kinds). Reader only. Format reference: the
 * public WebAssembly core specification (binary format).
 */
import { ByteReader } from "../util/reader.js";

export interface WasmImport {
  module: string;
  name: string;
  kind: string;
}

export interface WasmExport {
  name: string;
  kind: string;
}

export interface WasmSection {
  id: number;
  name: string;
  size: number;
}

export interface WasmInfo {
  version: number;
  sections: WasmSection[];
  imports: WasmImport[];
  exports: WasmExport[];
  customSections: string[];
  warnings: string[];
}

const SECTION_NAMES: Record<number, string> = {
  0: "custom",
  1: "type",
  2: "import",
  3: "function",
  4: "table",
  5: "memory",
  6: "global",
  7: "export",
  8: "start",
  9: "element",
  10: "code",
  11: "data",
  12: "data-count",
};

const KIND: Record<number, string> = { 0: "function", 1: "table", 2: "memory", 3: "global" };

/** Read an unsigned LEB128 integer. */
function uleb(r: ByteReader): number {
  let result = 0;
  let shift = 0;
  for (let i = 0; i < 5; i++) {
    const byte = r.u8();
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return result >>> 0;
}

function readName(r: ByteReader): string {
  const len = uleb(r);
  return r.bytes(len).toString("utf8");
}

export function parseWasm(buf: Buffer): WasmInfo {
  const warnings: string[] = [];
  const r = new ByteReader(buf);
  if (buf.length < 8 || r.u32be() !== 0x0061736d) throw new Error("not a WebAssembly module");
  const version = r.u32le();

  const sections: WasmSection[] = [];
  const imports: WasmImport[] = [];
  const exports: WasmExport[] = [];
  const customSections: string[] = [];

  while (r.remaining > 0) {
    let id: number;
    try {
      id = r.u8();
    } catch {
      break;
    }
    let size: number;
    try {
      size = uleb(r);
    } catch {
      warnings.push("truncated section size");
      break;
    }
    const sectionStart = r.offset;
    const sectionEnd = sectionStart + size;
    if (sectionEnd > buf.length) {
      warnings.push(`section ${id} declares size past end of file`);
      break;
    }

    let sectionLabel = SECTION_NAMES[id] ?? `unknown(${id})`;
    try {
      if (id === 0) {
        const name = readName(r);
        customSections.push(name);
        sectionLabel = `custom:${name}`;
      } else if (id === 2) {
        const count = uleb(r);
        for (let i = 0; i < count && r.offset < sectionEnd; i++) {
          const mod = readName(r);
          const nm = readName(r);
          const kind = r.u8();
          imports.push({ module: mod, name: nm, kind: KIND[kind] ?? `kind(${kind})` });
          // skip the type descriptor; we only need names, so jump to section end if ambiguous
          if (kind === 0) uleb(r);
          else r.seek(Math.min(sectionEnd, r.offset + 2));
        }
      } else if (id === 7) {
        const count = uleb(r);
        for (let i = 0; i < count && r.offset < sectionEnd; i++) {
          const nm = readName(r);
          const kind = r.u8();
          uleb(r); // index
          exports.push({ name: nm, kind: KIND[kind] ?? `kind(${kind})` });
        }
      }
    } catch (e) {
      warnings.push(`section ${sectionLabel} parse stopped: ${(e as Error).message}`);
    }

    sections.push({ id, name: sectionLabel, size });
    r.seek(sectionEnd); // always resync to the declared boundary
  }

  return { version, sections, imports, exports, customSections, warnings };
}
