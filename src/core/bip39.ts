// BIP39: Mnemonic code for generating deterministic keys
// Spec: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
// Reference: bitcoinjs/bip39, trezor-crypto bip39.c
// Wordlist: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
// Test vectors: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
//
// All cryptographic primitives delegate to Node.js built-in crypto (OpenSSL):
//   - crypto.randomBytes()  → OS CSPRNG (entropy generation)
//   - crypto.createHash()   → SHA-256 (checksum)
//   - crypto.pbkdf2Sync()   → PBKDF2-SHA512 (seed derivation)

import crypto from "node:crypto";
import { wordlist } from "./bip39-wordlist.js";

const INVALID_MNEMONIC = "Invalid mnemonic";
const INVALID_ENTROPY = "Invalid entropy";
const INVALID_CHECKSUM = "Invalid mnemonic checksum";

/** NFKD-normalize a string (BIP39 spec requirement). */
function nfkd(str: string): string {
  return str.normalize("NFKD");
}

/**
 * Compute the checksum bits for an entropy buffer.
 * BIP39: checksum = first (ENT / 32) bits of SHA-256(entropy).
 * For all valid entropy sizes (16-32 bytes), checksum fits in 1 byte (4-8 bits).
 */
function deriveChecksumBits(entropy: Uint8Array): number {
  const hash = crypto.createHash("sha256").update(entropy).digest();
  const checksumBitCount = entropy.length / 4; // ENT_bits / 32
  // Extract the top checksumBitCount bits from the first hash byte
  return hash[0]! >> (8 - checksumBitCount);
}

/**
 * Convert entropy bytes to a BIP39 mnemonic sentence.
 *
 * Algorithm (from BIP39 spec):
 * 1. Validate entropy: 16-32 bytes, divisible by 4
 * 2. SHA-256 the entropy, take first ENT/32 bits as checksum
 * 3. Append checksum bits to entropy bits
 * 4. Split into 11-bit groups, each maps to a wordlist index
 */
export function entropyToMnemonic(entropy: Uint8Array): string {
  if (entropy.length < 16 || entropy.length > 32 || entropy.length % 4 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }

  const checksumBitCount = entropy.length / 4;
  const checksum = deriveChecksumBits(entropy);

  // Build an array of 11-bit indices by walking entropy bits + checksum bits.
  // Total bits = (entropy.length * 8) + checksumBitCount, split into 11-bit words.
  const totalBits = entropy.length * 8 + checksumBitCount;
  const wordCount = totalBits / 11;
  const words: string[] = new Array(wordCount);

  // We accumulate bits into `acc` and track how many bits are in it with `accBits`.
  let acc = 0;
  let accBits = 0;
  let wordIndex = 0;

  // Walk entropy bytes
  for (let i = 0; i < entropy.length; i++) {
    acc = (acc << 8) | entropy[i]!;
    accBits += 8;
    if (accBits >= 11) {
      accBits -= 11;
      words[wordIndex++] = wordlist[(acc >> accBits) & 0x7ff]!;
    }
  }

  // Append checksum bits
  acc = (acc << checksumBitCount) | checksum;
  accBits += checksumBitCount;
  if (accBits >= 11) {
    accBits -= 11;
    words[wordIndex] = wordlist[(acc >> accBits) & 0x7ff]!;
  }

  return words.join(" ");
}

/**
 * Convert a BIP39 mnemonic sentence back to entropy bytes.
 * Validates word count, wordlist membership, and checksum.
 */
export function mnemonicToEntropy(mnemonic: string): Uint8Array {
  const words = nfkd(mnemonic).split(" ");
  if (words.length % 3 !== 0) {
    throw new Error(INVALID_MNEMONIC);
  }

  // Convert words to 11-bit indices
  const bits: number[] = new Array(words.length);
  for (let i = 0; i < words.length; i++) {
    const index = wordlist.indexOf(words[i]!);
    if (index === -1) {
      throw new Error(INVALID_MNEMONIC);
    }
    bits[i] = index;
  }

  // Total bits = words * 11, split into entropy (ENT) and checksum (CS)
  // ENT + CS = words * 11, CS = ENT / 32, so ENT = (words * 11) * 32 / 33
  const totalBits = words.length * 11;
  const checksumBitCount = totalBits / 33;
  const entropyBitCount = totalBits - checksumBitCount;
  const entropyByteCount = entropyBitCount / 8;

  // Validate entropy size: 16-32 bytes, divisible by 4
  if (entropyByteCount < 16 || entropyByteCount > 32 || entropyByteCount % 4 !== 0) {
    throw new Error(INVALID_ENTROPY);
  }

  // Extract entropy bytes from 11-bit word indices.
  // We walk the 11-bit values and extract 8-bit bytes.
  const entropy = new Uint8Array(entropyByteCount);
  let acc = 0;
  let accBits = 0;
  let byteIndex = 0;

  for (let i = 0; i < bits.length; i++) {
    acc = (acc << 11) | bits[i]!;
    accBits += 11;
    while (accBits >= 8 && byteIndex < entropyByteCount) {
      accBits -= 8;
      entropy[byteIndex++] = (acc >> accBits) & 0xff;
    }
  }

  // Remaining bits in acc are the checksum
  const receivedChecksum = acc & ((1 << checksumBitCount) - 1);
  const expectedChecksum = deriveChecksumBits(entropy);

  if (receivedChecksum !== expectedChecksum) {
    throw new Error(INVALID_CHECKSUM);
  }

  return entropy;
}

/**
 * Derive a 64-byte seed from a mnemonic + passphrase using PBKDF2-SHA512.
 * BIP39: PBKDF2(mnemonic, "mnemonic" + passphrase, 2048 rounds, 64 bytes, SHA-512)
 */
export function mnemonicToSeedSync(mnemonic: string, passphrase = ""): Uint8Array {
  const mnemonicBuffer = Buffer.from(nfkd(mnemonic), "utf8");
  const saltBuffer = Buffer.from(nfkd("mnemonic" + passphrase), "utf8");
  const seed = crypto.pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, "sha512");
  return new Uint8Array(seed);
}

/**
 * Generate a BIP39 mnemonic with the given strength.
 * @param strength entropy bits: 128 (12 words) or 256 (24 words)
 */
export function generateMnemonic(strength: number = 128): string {
  if (strength % 32 !== 0 || strength < 128 || strength > 256) {
    throw new TypeError(INVALID_ENTROPY);
  }
  const entropy = crypto.randomBytes(strength / 8);
  return entropyToMnemonic(new Uint8Array(entropy));
}

/** Validate a BIP39 mnemonic (word count, wordlist membership, checksum). */
export function validateMnemonic(mnemonic: string): boolean {
  try {
    mnemonicToEntropy(mnemonic);
    return true;
  } catch {
    return false;
  }
}
