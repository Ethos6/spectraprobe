/**
 * Printable-string extraction, equivalent in spirit to the classic `strings`
 * utility. Finds runs of printable ASCII and runs of printable UTF-16LE.
 */

export interface ExtractedString {
  value: string;
  /** Byte offset where the run starts. */
  offset: number;
  /** "ascii" or "utf16le". */
  encoding: "ascii" | "utf16le";
}

export interface StringOptions {
  minLength?: number;
  /** Hard cap on the number of strings returned. */
  max?: number;
}

function isPrintableAscii(b: number): boolean {
  // printable range plus tab
  return (b >= 0x20 && b <= 0x7e) || b === 0x09;
}

/** Extract ASCII and UTF-16LE printable strings from a buffer. */
export function extractStrings(data: Uint8Array, opts: StringOptions = {}): ExtractedString[] {
  const minLength = Math.max(1, opts.minLength ?? 4);
  const max = opts.max ?? 50_000;
  const out: ExtractedString[] = [];

  // ASCII runs
  let start = -1;
  for (let i = 0; i <= data.length; i++) {
    const printable = i < data.length && isPrintableAscii(data[i]!);
    if (printable) {
      if (start === -1) start = i;
    } else if (start !== -1) {
      if (i - start >= minLength) {
        out.push({
          value: Buffer.from(data.subarray(start, i)).toString("latin1"),
          offset: start,
          encoding: "ascii",
        });
        if (out.length >= max) return out;
      }
      start = -1;
    }
  }

  // UTF-16LE runs: printable ASCII char followed by a 0x00 high byte
  let u16start = -1;
  let u16chars: number[] = [];
  for (let i = 0; i + 1 < data.length; i += 2) {
    const lo = data[i]!;
    const hi = data[i + 1]!;
    if (hi === 0x00 && isPrintableAscii(lo)) {
      if (u16start === -1) u16start = i;
      u16chars.push(lo);
    } else {
      if (u16start !== -1 && u16chars.length >= minLength) {
        out.push({
          value: String.fromCharCode(...u16chars),
          offset: u16start,
          encoding: "utf16le",
        });
        if (out.length >= max) return out;
      }
      u16start = -1;
      u16chars = [];
    }
  }
  if (u16start !== -1 && u16chars.length >= minLength) {
    out.push({ value: String.fromCharCode(...u16chars), offset: u16start, encoding: "utf16le" });
  }

  return out;
}

const URL_RE = /\bhttps?:\/\/[^\s"'<>)]+/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const PATH_RE = /\b[A-Za-z]:\\[^\s"'<>|?*]+|\/(?:usr|etc|var|home|opt|tmp|bin|lib)\/[^\s"'<>]+/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

// File extensions that the domain pattern would otherwise mistake for TLDs.
const NOT_TLDS = new Set([
  "debug", "so", "dll", "exe", "sys", "txt", "json", "xml", "yml", "yaml", "js", "ts", "py", "rs", "go",
  "c", "h", "cpp", "hpp", "cs", "java", "class", "jar", "png", "jpg", "gif", "svg", "dat", "bin", "log",
  "ini", "cfg", "conf", "tmp", "bak", "md", "html", "htm", "css", "map", "lock", "pdb", "obj", "lib",
]);

function looksLikeDomain(d: string): boolean {
  const tld = d.slice(d.lastIndexOf(".") + 1).toLowerCase();
  return !NOT_TLDS.has(tld) && !/^[0-9a-f]{16,}\./i.test(d);
}

export interface StringIndicators {
  urls: string[];
  ips: string[];
  emails: string[];
  paths: string[];
  domains: string[];
}

function uniq(values: string[], cap = 500): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (!seen.has(v)) {
      seen.add(v);
      out.push(v);
      if (out.length >= cap) break;
    }
  }
  return out;
}

/** Pull common indicators (URLs, IPs, emails, paths, domains) out of text. */
export function indicatorsFromText(text: string): StringIndicators {
  const urls = uniq(text.match(URL_RE) ?? []);
  const urlBlob = urls.join(" ");
  return {
    urls,
    ips: uniq(text.match(IPV4_RE) ?? []),
    emails: uniq(text.match(EMAIL_RE) ?? []),
    paths: uniq(text.match(PATH_RE) ?? []),
    // domains that already appear inside a URL are less interesting on their own
    domains: uniq((text.match(DOMAIN_RE) ?? []).filter((d) => !urlBlob.includes(d) && looksLikeDomain(d))),
  };
}
