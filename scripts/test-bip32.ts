// DIY BIP32 derivation test — validates @scure/bip32 output using Node.js crypto only.
// Usage: npx tsx scripts/test-bip32.ts

import crypto from "node:crypto";
import { HDKey } from "@scure/bip32";

const BIP32_SEED_KEY = "Bitcoin seed";

// --- DIY BIP32 implementation using Node.js crypto ---

function hmacSha512(key: string | Uint8Array, data: Uint8Array): Buffer {
  return crypto.createHmac("sha512", key).update(data).digest();
}

function masterKeyFromSeed(seed: Uint8Array): { key: Buffer; chainCode: Buffer } {
  const I = hmacSha512(BIP32_SEED_KEY, seed);
  return { key: I.subarray(0, 32), chainCode: I.subarray(32) };
}

// secp256k1 order
const N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

function privateToPublic(privKey: Uint8Array): Buffer {
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(Buffer.from(privKey));
  return Buffer.from(ecdh.getPublicKey("hex", "compressed"), "hex");
}

function ser32(index: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(index);
  return buf;
}

function deriveChild(
  parentKey: Buffer,
  parentChainCode: Buffer,
  index: number,
  hardened: boolean,
): { key: Buffer; chainCode: Buffer } {
  let data: Buffer;
  if (hardened) {
    // Hardened: 0x00 || parentKey || ser32(index)
    data = Buffer.concat([Buffer.from([0x00]), parentKey, ser32(0x80000000 + index)]);
  } else {
    // Normal: serP(parentPubKey) || ser32(index)
    const pubKey = privateToPublic(parentKey);
    data = Buffer.concat([pubKey, ser32(index)]);
  }

  const I = hmacSha512(parentChainCode, data);
  const IL = I.subarray(0, 32);
  const IR = I.subarray(32);

  // childKey = (IL + parentKey) mod N
  const ilBig = BigInt("0x" + IL.toString("hex"));
  const parentBig = BigInt("0x" + parentKey.toString("hex"));
  const childBig = (ilBig + parentBig) % N;

  const childHex = childBig.toString(16).padStart(64, "0");
  return { key: Buffer.from(childHex, "hex"), chainCode: Buffer.from(IR) };
}

function derivePath(
  seed: Uint8Array,
  path: string,
): { key: Buffer; chainCode: Buffer } {
  const { key, chainCode } = masterKeyFromSeed(seed);

  const segments = path.replace("m/", "").split("/");
  let current = { key, chainCode };

  for (const seg of segments) {
    const hardened = seg.endsWith("'");
    const index = parseInt(seg.replace("'", ""), 10);
    current = deriveChild(current.key, current.chainCode, index, hardened);
  }

  return current;
}

// --- Tests ---

function bufEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function runTests() {
  console.log("=== BIP32 Derivation Validation ===\n");

  // Generate a deterministic seed via PBKDF2 (same as finalize flow)
  const testDescriptor = "wsh(sortedmulti(2,[aabbccdd/48'/0'/0'/2']xpub6ELcKdS,...,[eeff0011/48'/0'/0'/2']xpub6DnT4Z,...))#testchk1";
  const salt = "entropy-from-descriptor";
  const seed = await new Promise<Buffer>((resolve, reject) => {
    crypto.pbkdf2(testDescriptor, salt, 2048, 64, "sha512", (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });

  console.log("Seed (hex):", seed.toString("hex").slice(0, 32) + "...");

  // Test 1: Hardened path m/83696968'/128169'/32'/0'
  const secretPath = "m/83696968'/128169'/32'/0'";
  console.log(`\nTest 1: Derive at ${secretPath} (all hardened)`);

  const diy1 = derivePath(seed, secretPath);
  const lib1 = HDKey.fromMasterSeed(new Uint8Array(seed)).derive(secretPath);

  const match1 = bufEqual(diy1.key, lib1.privateKey!);
  console.log("  DIY privKey:", diy1.key.toString("hex").slice(0, 16) + "...");
  console.log("  Lib privKey:", Buffer.from(lib1.privateKey!).toString("hex").slice(0, 16) + "...");
  console.log("  Match:", match1 ? "PASS" : "FAIL");

  // Test 2: Mixed path m/45'/0'/0'/1/0
  const keypairPath = "m/45'/0'/0'/1/0";
  console.log(`\nTest 2: Derive at ${keypairPath} (mixed hardened + normal)`);

  const diy2 = derivePath(seed, keypairPath);
  const diy2pub = privateToPublic(diy2.key);
  const lib2 = HDKey.fromMasterSeed(new Uint8Array(seed)).derive(keypairPath);

  const match2 = bufEqual(diy2pub, lib2.publicKey!);
  console.log("  DIY pubKey:", diy2pub.toString("hex").slice(0, 16) + "...");
  console.log("  Lib pubKey:", Buffer.from(lib2.publicKey!).toString("hex").slice(0, 16) + "...");
  console.log("  Match:", match2 ? "PASS" : "FAIL");

  // Test 3: Full finalize flow
  console.log("\nTest 3: Full finalize key derivation");

  // BIP85 Secretbox key
  const hmac = crypto.createHmac("sha512", "bip-entropy-from-k")
    .update(diy1.key)
    .digest();
  const diySecretboxKey = hmac.subarray(0, 32);

  const libHmac = crypto.createHmac("sha512", "bip-entropy-from-k")
    .update(lib1.privateKey!)
    .digest();
  const libSecretboxKey = new Uint8Array(libHmac.subarray(0, 32));

  const match3 = bufEqual(diySecretboxKey, libSecretboxKey);
  console.log("  Secretbox key match:", match3 ? "PASS" : "FAIL");

  // GID (P2PKH address)
  const sha256 = crypto.createHash("sha256").update(diy2pub).digest();
  const ripemd = crypto.createHash("ripemd160").update(sha256).digest();
  console.log("  PubKeyHash:", ripemd.toString("hex"));

  const libSha = crypto.createHash("sha256").update(lib2.publicKey!).digest();
  const libRipemd = crypto.createHash("ripemd160").update(libSha).digest();
  const match4 = bufEqual(ripemd, libRipemd);
  console.log("  PubKeyHash match:", match4 ? "PASS" : "FAIL");

  // Summary
  console.log("\n=== Summary ===");
  const allPassed = match1 && match2 && match3 && match4;
  console.log(allPassed ? "All tests PASSED" : "Some tests FAILED");
  process.exit(allPassed ? 0 : 1);
}

runTests().catch(console.error);
