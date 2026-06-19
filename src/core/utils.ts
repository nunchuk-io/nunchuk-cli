import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function combinationIndices(length: number, count: number): number[][] {
  const result: number[][] = [];
  const current: number[] = [];

  const visit = (start: number): void => {
    if (current.length === count) {
      result.push([...current]);
      return;
    }

    const remaining = count - current.length;
    for (let i = start; i <= length - remaining; i++) {
      current.push(i);
      visit(i + 1);
      current.pop();
    }
  };

  visit(0);
  return result;
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && compareBytes(a, b) === 0;
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;

  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}
