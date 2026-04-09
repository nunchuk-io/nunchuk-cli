// Wallet key derivation for finalize
// Reference: libnunchuk src/softwaresigner.cpp

import crypto from "node:crypto";
import { HDKey } from "@scure/bip32";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { secretBox, secretOpen } from "./crypto.js";
import { buildAnyDescriptorForParsed, parseDescriptor } from "./descriptor.js";
import type { WalletData } from "./storage.js";

const BIP85_HASH_KEY = "bip-entropy-from-k";
const SECRET_PATH = "m/83696968'/128169'/32'/0'";
const KEYPAIR_PATH = "m/45'/0'/0'/1/0";

// Derive BIP32 root key from wallet descriptor using PBKDF2
// Reference: SoftwareSigner(Wallet) in softwaresigner.cpp:96-110
export async function deriveRootKeyFromDescriptor(descriptor: string): Promise<HDKey> {
  const salt = "entropy-from-descriptor";
  const seed = await new Promise<Buffer>((resolve, reject) => {
    crypto.pbkdf2(descriptor, salt, 2048, 64, "sha512", (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
  return HDKey.fromMasterSeed(new Uint8Array(seed));
}

// Derive 32-byte Secretbox key via BIP85
// Reference: SetupBoxKey in softwaresigner.cpp:114-123
export function deriveSecretboxKey(rootKey: HDKey): Uint8Array {
  const derived = rootKey.derive(SECRET_PATH);
  if (!derived.privateKey) throw new Error("Failed to derive private key at SECRET_PATH");

  const hmac = crypto.createHmac("sha512", BIP85_HASH_KEY).update(derived.privateKey).digest();

  return new Uint8Array(hmac.subarray(0, 32));
}

// Derive GID (server wallet ID) as a P2PKH Bitcoin address
// Reference: GetAddressAtPath in softwaresigner.cpp:178-181
export function deriveGID(rootKey: HDKey, network: "mainnet" | "testnet"): string {
  const derived = rootKey.derive(KEYPAIR_PATH);
  if (!derived.publicKey) throw new Error("Failed to derive public key at KEYPAIR_PATH");

  // hash160(compressedPubKey)
  const sha = crypto.createHash("sha256").update(derived.publicKey).digest();
  const pubKeyHash = crypto.createHash("ripemd160").update(sha).digest();

  // P2PKH address: version byte + pubKeyHash + checksum
  const version = network === "mainnet" ? 0x00 : 0x6f;
  const payload = Buffer.concat([Buffer.from([version]), pubKeyHash]);
  const checksum = crypto
    .createHash("sha256")
    .update(crypto.createHash("sha256").update(payload).digest())
    .digest()
    .subarray(0, 4);

  return base58Encode(Buffer.concat([payload, checksum]));
}

// Base58 encoding
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// HMAC-SHA512 hash for computing txGid from txId
// Reference: SoftwareSigner::HashMessage in softwaresigner.cpp:125-134
export function hashMessage(key: Uint8Array, message: string): string {
  const data = new TextEncoder().encode(message);
  return Buffer.from(hmac(sha512, key, data)).toString("hex");
}

// Bitcoin message signing with wallet's KEYPAIR_PATH private key
// Reference: SoftwareSigner::SignMessage in softwaresigner.cpp:362-368
// Protocol: SHA256(SHA256("\x18Bitcoin Signed Message:\n" + compactSize(len) + message))
// Output: base64(1-byte-flag + 32-byte-r + 32-byte-s)
export async function signWalletMessage(descriptor: string, message: string): Promise<string> {
  const rootKey = await deriveRootKeyFromDescriptor(descriptor);
  const derived = rootKey.derive(KEYPAIR_PATH);
  if (!derived.privateKey) throw new Error("Failed to derive private key at KEYPAIR_PATH");

  // Build prefixed message (Bitcoin message signing standard)
  const prefix = Buffer.from("\x18Bitcoin Signed Message:\n");
  const msgBuf = Buffer.from(message);
  const lenBuf = compactSize(msgBuf.length);
  const full = Buffer.concat([prefix, lenBuf, msgBuf]);

  // Double SHA256
  const hash = sha256(sha256(full));

  // Sign with recoverable ECDSA (prehash: false since we already double-SHA256'd)
  const sigBytes = secp256k1.sign(hash, derived.privateKey, {
    prehash: false,
    format: "recovered",
  });
  const sig = secp256k1.Signature.fromBytes(sigBytes, "recovered");

  // Encode as 65-byte compact recoverable signature
  // Flag: 27 + recovery + 4 (compressed pubkey)
  const flag = 27 + sig.recovery! + 4;
  const result = Buffer.alloc(65);
  result[0] = flag;
  result.set(sig.toBytes("compact"), 1);
  return result.toString("base64");
}

// Bitcoin compact size encoding (varint)
function compactSize(n: number): Buffer {
  if (n < 253) {
    return Buffer.from([n]);
  } else if (n <= 0xffff) {
    const buf = Buffer.alloc(3);
    buf[0] = 0xfd;
    buf.writeUInt16LE(n, 1);
    return buf;
  } else if (n <= 0xffffffff) {
    const buf = Buffer.alloc(5);
    buf[0] = 0xfe;
    buf.writeUInt32LE(n, 1);
    return buf;
  } else {
    const buf = Buffer.alloc(9);
    buf[0] = 0xff;
    buf.writeBigUInt64LE(BigInt(n), 1);
    return buf;
  }
}

function base58Encode(data: Buffer): string {
  let num = BigInt("0x" + data.toString("hex"));
  let result = "";
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = BASE58_ALPHABET[remainder] + result;
  }
  // Preserve leading zeros
  for (const byte of data) {
    if (byte === 0) result = "1" + result;
    else break;
  }
  return result;
}

// -- Wallet payload encryption/decryption --
// Reference: GroupService::EncryptWalletPayload (groupservice.cpp:882-892)
// Pattern: secretBox(plaintext, key) → msg, signWalletMessage(descriptor, msg) → sig
// Returns { version: 1, msg, sig }

export async function encryptWalletPayload(
  wallet: WalletData,
  plaintext: unknown,
): Promise<{ version: number; msg: string; sig: string }> {
  const secretboxKey = new Uint8Array(Buffer.from(wallet.secretboxKey, "base64"));
  const descriptor = buildAnyDescriptorForParsed(parseDescriptor(wallet.descriptor));
  const msg = secretBox(JSON.stringify(plaintext), secretboxKey);
  const sig = await signWalletMessage(descriptor, msg);
  return { version: 1, msg, sig };
}

// Reference: GroupService::DecryptWalletPayload (groupservice.cpp:894-915)
// Extracts msg from response (may be nested under "data"), decrypts with secretbox
export function decryptWalletPayload<T = unknown>(wallet: WalletData, payload: unknown): T {
  const secretboxKey = new Uint8Array(Buffer.from(wallet.secretboxKey, "base64"));
  const obj = payload as Record<string, unknown>;
  const data = (obj?.data ?? obj) as Record<string, unknown>;
  if (!data?.msg || typeof data.msg !== "string") {
    throw new Error("Invalid wallet payload: missing msg");
  }
  const plain = secretOpen(data.msg as string, secretboxKey);
  return JSON.parse(plain) as T;
}
