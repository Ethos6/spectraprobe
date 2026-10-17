/** Shannon entropy in bits/byte (0..8) for a byte buffer. */
export function shannonEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (let i = 0; i < data.length; i++) {
    const idx = data[i]!;
    counts[idx] = counts[idx]! + 1;
  }
  let entropy = 0;
  const len = data.length;
  for (let b = 0; b < 256; b++) {
    const c = counts[b]!;
    if (c === 0) continue;
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 1000) / 1000;
}

/**
 * Rough interpretation of a file-level entropy value. High entropy (> ~7.2)
 * commonly indicates compression or encryption, which is useful context for a
 * researcher but is not by itself proof of anything.
 */
export function entropyHint(entropy: number): string {
  if (entropy >= 7.5) return "very high (likely compressed, packed or encrypted)";
  if (entropy >= 7.0) return "high (possibly compressed or packed)";
  if (entropy >= 5.0) return "moderate (typical of mixed code/data)";
  if (entropy > 0) return "low (likely text or sparse data)";
  return "empty";
}
