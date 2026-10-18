import { describe, it, expect } from "vitest";
import { hashBuffer, crc32 } from "../src/util/hash.js";
import { shannonEntropy, entropyHint } from "../src/util/entropy.js";
import { extractStrings, indicatorsFromText } from "../src/util/strings.js";

describe("hashing", () => {
  it("computes known digests for an empty buffer", () => {
    const h = hashBuffer(Buffer.alloc(0));
    expect(h.sha256).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(h.md5).toBe("d41d8cd98f00b204e9800998ecf8427e");
    expect(h.crc32).toBe("00000000");
  });
  it("computes a known CRC-32", () => {
    // CRC-32 of "123456789" is 0xCBF43926
    expect(crc32(Buffer.from("123456789"))).toBe("cbf43926");
  });
});

describe("entropy", () => {
  it("is 0 for uniform data and ~8 for all-distinct bytes", () => {
    expect(shannonEntropy(Buffer.alloc(1000, 0x41))).toBe(0);
    const allBytes = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    expect(shannonEntropy(allBytes)).toBeCloseTo(8, 5);
  });
  it("labels high entropy as likely packed", () => {
    expect(entropyHint(7.6)).toContain("compressed");
    expect(entropyHint(1)).toContain("low");
  });
});

describe("string extraction", () => {
  it("finds ASCII and UTF-16LE runs above the minimum length", () => {
    const ascii = Buffer.from("hi\x00HELLOworld\x01");
    const strings = extractStrings(ascii, { minLength: 4 });
    expect(strings.some((s) => s.value === "HELLOworld" && s.encoding === "ascii")).toBe(true);

    const u16 = Buffer.from("T\x00e\x00s\x00t\x00i\x00n\x00g\x00", "latin1");
    const u16strings = extractStrings(u16, { minLength: 4 });
    expect(u16strings.some((s) => s.value === "Testing" && s.encoding === "utf16le")).toBe(true);
  });
  it("respects the max cap", () => {
    const many = Buffer.from(Array.from({ length: 50 }, () => "abcd\x00").join(""));
    expect(extractStrings(many, { minLength: 4, max: 10 }).length).toBe(10);
  });
  it("pulls indicators out of text", () => {
    const text = "see https://example.com/a and mail a@b.com from 10.0.0.5 at C:\\Windows\\x.dll";
    const ind = indicatorsFromText(text);
    expect(ind.urls).toContain("https://example.com/a");
    expect(ind.emails).toContain("a@b.com");
    expect(ind.ips).toContain("10.0.0.5");
    expect(ind.paths.some((p) => p.includes("Windows"))).toBe(true);
  });
  it("does not mistake file names for domains", () => {
    const ind = indicatorsFromText("load 4d2960fdd962fc224d77beeb35bb71aa7b115d.debug libc.so config.json via api.example.org");
    expect(ind.domains).toEqual(["api.example.org"]);
  });
});
