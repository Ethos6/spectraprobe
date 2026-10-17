/**
 * Bounds-checked cursor over a Buffer. Every read validates that the requested
 * bytes exist, so a truncated or hostile file produces a thrown error rather
 * than silently reading out of bounds.
 */
export class ByteReader {
  private pos = 0;

  constructor(private readonly buf: Buffer) {}

  get offset(): number {
    return this.pos;
  }

  get length(): number {
    return this.buf.length;
  }

  get remaining(): number {
    return this.buf.length - this.pos;
  }

  seek(offset: number): this {
    if (offset < 0 || offset > this.buf.length) {
      throw new RangeError(`seek out of range: ${offset} (len ${this.buf.length})`);
    }
    this.pos = offset;
    return this;
  }

  skip(n: number): this {
    return this.seek(this.pos + n);
  }

  private ensure(n: number): void {
    if (this.pos + n > this.buf.length) {
      throw new RangeError(`read past end: need ${n} at ${this.pos} (len ${this.buf.length})`);
    }
  }

  u8(): number {
    this.ensure(1);
    return this.buf.readUInt8(this.pos++);
  }

  u16le(): number {
    this.ensure(2);
    const v = this.buf.readUInt16LE(this.pos);
    this.pos += 2;
    return v;
  }

  u16be(): number {
    this.ensure(2);
    const v = this.buf.readUInt16BE(this.pos);
    this.pos += 2;
    return v;
  }

  u32le(): number {
    this.ensure(4);
    const v = this.buf.readUInt32LE(this.pos);
    this.pos += 4;
    return v;
  }

  u32be(): number {
    this.ensure(4);
    const v = this.buf.readUInt32BE(this.pos);
    this.pos += 4;
    return v;
  }

  u64le(): bigint {
    this.ensure(8);
    const v = this.buf.readBigUInt64LE(this.pos);
    this.pos += 8;
    return v;
  }

  u64be(): bigint {
    this.ensure(8);
    const v = this.buf.readBigUInt64BE(this.pos);
    this.pos += 8;
    return v;
  }

  bytes(n: number): Buffer {
    this.ensure(n);
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }

  /** Read a fixed-width field and decode as latin1, trimming at the first NUL. */
  fixedString(n: number): string {
    const b = this.bytes(n);
    const nul = b.indexOf(0);
    return b.subarray(0, nul === -1 ? b.length : nul).toString("latin1");
  }

  /** Peek a byte without advancing; returns -1 if out of range. */
  peek(at = this.pos): number {
    return at >= 0 && at < this.buf.length ? this.buf.readUInt8(at) : -1;
  }
}

/** Read a NUL-terminated latin1 string from a buffer at an absolute offset. */
export function cString(buf: Buffer, offset: number, max = 4096): string {
  if (offset < 0 || offset >= buf.length) return "";
  let end = offset;
  const limit = Math.min(buf.length, offset + max);
  while (end < limit && buf[end] !== 0) end++;
  return buf.subarray(offset, end).toString("latin1");
}
