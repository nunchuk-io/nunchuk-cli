// Derive master fingerprint from a BIP32 root key (tprv.../xprv...)
// Usage: npx tsx scripts/fingerprint.ts <root-key>

import crypto from "node:crypto";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(str: string): Buffer {
  let num = BigInt(0);
  for (const char of str) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base58 character: ${char}`);
    num = num * 58n + BigInt(idx);
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  // Preserve leading zeros
  let leadingZeros = 0;
  for (const char of str) {
    if (char === "1") leadingZeros++;
    else break;
  }
  return Buffer.concat([Buffer.alloc(leadingZeros), Buffer.from(hex, "hex")]);
}

function hash160(data: Buffer): Buffer {
  const sha = crypto.createHash("sha256").update(data).digest();
  return crypto.createHash("ripemd160").update(sha).digest();
}

const rootKey = process.argv[2];
if (!rootKey) {
  console.error("Usage: npx tsx scripts/fingerprint.ts <BIP32-root-key>");
  console.error("Example: npx tsx scripts/fingerprint.ts tprv8ZgxMBicQKsPe...");
  process.exit(1);
}

// Base58Check decode: 4 version + 1 depth + 4 parent_fp + 4 child_num + 32 chaincode + 1 prefix + 32 key + 4 checksum = 82 bytes
const decoded = base58Decode(rootKey);
const payload = decoded.subarray(0, decoded.length - 4); // strip checksum

const depth = payload[4];
if (depth !== 0) {
  console.error("Warning: This is not a root key (depth != 0). Fingerprint will be for this key level.");
}

// Private key is at bytes 46-77 (byte 45 is 0x00 prefix for private keys)
const privKey = payload.subarray(46, 78);

// Derive compressed public key using secp256k1
const ecdh = crypto.createECDH("secp256k1");
ecdh.setPrivateKey(privKey);
const uncompressedPub = ecdh.getPublicKey();
// Compress: 02/03 prefix + x coordinate
const x = uncompressedPub.subarray(1, 33);
const y = uncompressedPub.subarray(33, 65);
const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
const compressedPub = Buffer.concat([Buffer.from([prefix]), x]);

// Fingerprint = first 4 bytes of HASH160(compressed public key)
const fingerprint = hash160(compressedPub).subarray(0, 4).toString("hex");

console.log(`Master fingerprint: ${fingerprint}`);
