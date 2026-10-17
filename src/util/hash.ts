import { createHash } from "node:crypto";
import type { Hashes } from "../types.js";

const CRC_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

/** CRC-32 (IEEE 802.3) of a buffer, returned as an 8-char lowercase hex string. */
export function crc32(data: Uint8Array): string {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    const idx = (crc ^ data[i]!) & 0xff;
    crc = (crc >>> 8) ^ CRC_TABLE[idx]!;
  }
  crc = (crc ^ 0xffffffff) >>> 0;
  return crc.toString(16).padStart(8, "0");
}

/** Compute sha256/sha1/md5/crc32 for a buffer in a single pass of reads. */
export function hashBuffer(data: Uint8Array): Hashes {
  return {
    sha256: createHash("sha256").update(data).digest("hex"),
    sha1: createHash("sha1").update(data).digest("hex"),
    md5: createHash("md5").update(data).digest("hex"),
    crc32: crc32(data),
  };
}

/** Short stable id from a sha256 hex digest. */
export function shortId(sha256: string): string {
  return sha256.slice(0, 16);
}
