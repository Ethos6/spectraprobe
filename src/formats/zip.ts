/**
 * Minimal, original ZIP reader. Parses the End of Central Directory record and
 * the central directory to list entries, and can inflate a single named entry
 * on demand using Node's zlib. Covers JAR, APK, WAR and other ZIP containers.
 */
import { inflateRawSync } from "node:zlib";
import { ByteReader } from "../util/reader.js";

export interface ZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number;
  crc32: string;
  /** Offset of the local file header. */
  localHeaderOffset: number;
  isDirectory: boolean;
}

export interface ZipListing {
  entries: ZipEntry[];
  comment: string;
  truncated: boolean;
}

const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;

/** Locate and read the central directory. */
export function readZip(buf: Buffer, maxEntries = 20000): ZipListing {
  // Find EOCD by scanning backwards (comment can be up to 64 KiB).
  const minPos = Math.max(0, buf.length - (22 + 0xffff));
  let eocd = -1;
  for (let i = buf.length - 22; i >= minPos; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) throw new Error("not a ZIP archive (no end-of-central-directory record)");

  // EOCD layout: +8 entries-on-disk, +10 total-entries, +12 cd-size, +16 cd-offset, +20 comment-len
  const totalEntries = buf.readUInt16LE(eocd + 10);
  const cenOffset = buf.readUInt32LE(eocd + 16);
  const commentLen = buf.readUInt16LE(eocd + 20);
  const comment = commentLen > 0 ? buf.subarray(eocd + 22, eocd + 22 + commentLen).toString("latin1") : "";

  const entries: ZipEntry[] = [];
  let pos = cenOffset;
  let truncated = false;
  for (let i = 0; i < totalEntries; i++) {
    if (pos + 46 > buf.length || buf.readUInt32LE(pos) !== CEN_SIG) break;
    const c = new ByteReader(buf);
    c.seek(pos + 10);
    const method = c.u16le();
    c.skip(4); // mod time/date
    const crc = c.u32le();
    const compressedSize = c.u32le();
    const uncompressedSize = c.u32le();
    const nameLen = c.u16le();
    const extraLen = c.u16le();
    const commentFieldLen = c.u16le();
    c.skip(2 + 2 + 4); // disk start, internal attrs, external attrs
    const localHeaderOffset = c.u32le();
    const name = buf.subarray(pos + 46, pos + 46 + nameLen).toString("utf8");
    entries.push({
      name,
      compressedSize,
      uncompressedSize,
      compressionMethod: method,
      crc32: (crc >>> 0).toString(16).padStart(8, "0"),
      localHeaderOffset,
      isDirectory: name.endsWith("/"),
    });
    pos += 46 + nameLen + extraLen + commentFieldLen;
    if (entries.length >= maxEntries) {
      truncated = true;
      break;
    }
  }

  return { entries, comment, truncated };
}

/** Inflate a single entry's bytes. Supports stored (0) and deflate (8). */
export function readZipEntry(buf: Buffer, entry: ZipEntry): Buffer | null {
  const lh = entry.localHeaderOffset;
  if (lh + 30 > buf.length || buf.readUInt32LE(lh) !== 0x04034b50) return null;
  const nameLen = buf.readUInt16LE(lh + 26);
  const extraLen = buf.readUInt16LE(lh + 28);
  const dataStart = lh + 30 + nameLen + extraLen;
  const dataEnd = dataStart + entry.compressedSize;
  if (dataEnd > buf.length) return null;
  const raw = buf.subarray(dataStart, dataEnd);
  if (entry.compressionMethod === 0) return Buffer.from(raw);
  if (entry.compressionMethod === 8) {
    try {
      return inflateRawSync(raw);
    } catch {
      return null;
    }
  }
  return null; // unsupported compression method
}

/** Read a named entry as UTF-8 text (returns null if absent or unsupported). */
export function readZipText(buf: Buffer, listing: ZipListing, name: string): string | null {
  const entry = listing.entries.find((e) => e.name === name);
  if (!entry) return null;
  const data = readZipEntry(buf, entry);
  return data ? data.toString("utf8") : null;
}
