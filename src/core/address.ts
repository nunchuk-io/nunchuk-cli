// Bitcoin address derivation for multisig descriptors
// Reference: libnunchuk CoreUtils::DeriveAddresses

import { HDKey } from "@scure/bip32";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { bech32, createBase58check } from "@scure/base";
import { p2ms, p2wsh, p2sh, bip32Path, NETWORK, TEST_NETWORK } from "@scure/btc-signer";
import { parseSignerDescriptor } from "./descriptor.js";
import type { Network } from "./config.js";

const base58check = createBase58check(sha256);

export const MAINNET_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };
export const TESTNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

// Build multisig redeem script: OP_m <pubkey1> ... <pubkeyn> OP_n OP_CHECKMULTISIG
export function buildMultisigScript(pubkeys: Uint8Array[], m: number): Uint8Array {
  const n = pubkeys.length;
  // OP_m + (1+33)*n + OP_n + OP_CHECKMULTISIG
  const script = new Uint8Array(1 + n * 34 + 1 + 1);
  let offset = 0;

  script[offset++] = 0x50 + m; // OP_m
  for (const pk of pubkeys) {
    script[offset++] = 0x21; // push 33 bytes
    script.set(pk, offset);
    offset += 33;
  }
  script[offset++] = 0x50 + n; // OP_n
  script[offset] = 0xae; // OP_CHECKMULTISIG

  return script;
}

// Compare Uint8Arrays lexicographically
export function comparePubkeys(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

// Derive the first receive address (index 0) from a multisig wallet
export function deriveFirstAddress(
  signers: string[],
  m: number,
  addressType: number,
  network: Network,
): string {
  // Derive child pubkeys at receive path /0/0
  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  const pubkeys: Uint8Array[] = signers.map((desc) => {
    const { xpub } = parseSignerDescriptor(desc);
    const key = HDKey.fromExtendedKey(xpub, versions);
    const child = key.deriveChild(0).deriveChild(0);
    if (!child.publicKey) throw new Error("Failed to derive public key");
    return child.publicKey;
  });

  // Sort lexicographically (sortedmulti)
  pubkeys.sort(comparePubkeys);

  const redeemScript = buildMultisigScript(pubkeys, m);
  const isMainnet = network === "mainnet";

  if (addressType === 3) {
    // NATIVE_SEGWIT: P2WSH — bech32(witness_v0, SHA256(script))
    const scriptHash = sha256(redeemScript);
    const prefix = isMainnet ? "bc" : "tb";
    const words = bech32.toWords(scriptHash);
    return bech32.encode(prefix, [0, ...words]);
  } else if (addressType === 2) {
    // NESTED_SEGWIT: P2SH-P2WSH — base58check(0x05, HASH160(0x0020 || SHA256(script)))
    const scriptHash = sha256(redeemScript);
    const witnessProgram = new Uint8Array(34);
    witnessProgram[0] = 0x00; // OP_0
    witnessProgram[1] = 0x20; // push 32 bytes
    witnessProgram.set(scriptHash, 2);
    const h160 = hash160(witnessProgram);
    const version = isMainnet ? 0x05 : 0xc4;
    const payload = new Uint8Array(21);
    payload[0] = version;
    payload.set(h160, 1);
    return base58check.encode(payload);
  } else if (addressType === 1) {
    // LEGACY: P2SH — base58check(0x05, HASH160(script))
    const h160 = hash160(redeemScript);
    const version = isMainnet ? 0x05 : 0xc4;
    const payload = new Uint8Array(21);
    payload[0] = version;
    payload.set(h160, 1);
    return base58check.encode(payload);
  } else {
    throw new Error("Taproot address derivation not yet supported");
  }
}

// Derive multiple addresses from a multisig wallet descriptor
// Reference: libnunchuk src/backend/electrum/synchronizer.cpp:349-384
export function deriveAddresses(
  signers: string[],
  m: number,
  addressType: number,
  network: Network,
  chain: 0 | 1, // 0 = receive, 1 = change
  startIndex: number,
  count: number,
): string[] {
  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  const isMainnet = network === "mainnet";

  // Pre-derive the chain-level keys for each signer
  const chainKeys = signers.map((desc) => {
    const { xpub } = parseSignerDescriptor(desc);
    const key = HDKey.fromExtendedKey(xpub, versions);
    return key.deriveChild(chain);
  });

  const addresses: string[] = [];
  for (let idx = startIndex; idx < startIndex + count; idx++) {
    const pubkeys: Uint8Array[] = chainKeys.map((chainKey) => {
      const child = chainKey.deriveChild(idx);
      if (!child.publicKey) throw new Error("Failed to derive public key");
      return child.publicKey;
    });
    pubkeys.sort(comparePubkeys);

    const redeemScript = buildMultisigScript(pubkeys, m);

    if (addressType === 3) {
      const scriptHash = sha256(redeemScript);
      const prefix = isMainnet ? "bc" : "tb";
      const words = bech32.toWords(scriptHash);
      addresses.push(bech32.encode(prefix, [0, ...words]));
    } else if (addressType === 2) {
      const scriptHash = sha256(redeemScript);
      const witnessProgram = new Uint8Array(34);
      witnessProgram[0] = 0x00;
      witnessProgram[1] = 0x20;
      witnessProgram.set(scriptHash, 2);
      const h160 = hash160(witnessProgram);
      const version = isMainnet ? 0x05 : 0xc4;
      const payload = new Uint8Array(21);
      payload[0] = version;
      payload.set(h160, 1);
      addresses.push(base58check.encode(payload));
    } else if (addressType === 1) {
      const h160 = hash160(redeemScript);
      const version = isMainnet ? 0x05 : 0xc4;
      const payload = new Uint8Array(21);
      payload[0] = version;
      payload.set(h160, 1);
      addresses.push(base58check.encode(payload));
    } else {
      throw new Error("Taproot address derivation not yet supported");
    }
  }
  return addresses;
}

// PSBT input metadata for a specific multisig address
// Reference: libnunchuk FillPsbt() populates hd_keypaths (bip32Derivation)
export interface MultisigPayment {
  address: string;
  script: Uint8Array;
  witnessScript?: Uint8Array;
  redeemScript?: Uint8Array;
  bip32Derivation: Array<[Uint8Array, { fingerprint: number; path: number[] }]>;
}

// Derive full PSBT input metadata for a multisig address at chain/index
// Uses @scure/btc-signer payment helpers (p2ms, p2wsh, p2sh)
export function deriveMultisigPayment(
  signers: string[],
  m: number,
  addressType: number,
  network: Network,
  chain: 0 | 1,
  index: number,
): MultisigPayment {
  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  const btcNet = network === "mainnet" ? NETWORK : TEST_NETWORK;

  // Derive child pubkeys and track signer info for bip32Derivation
  const signerInfos = signers.map((desc) => {
    const parsed = parseSignerDescriptor(desc);
    const key = HDKey.fromExtendedKey(parsed.xpub, versions);
    const child = key.deriveChild(chain).deriveChild(index);
    if (!child.publicKey) throw new Error("Failed to derive public key");
    // Full BIP32 path from master: signerPath + /chain/index
    const fullPath = bip32Path("m" + parsed.derivationPath + "/" + chain + "/" + index);
    const fingerprint = parseInt(parsed.masterFingerprint, 16);
    return { pubkey: child.publicKey, fingerprint, path: fullPath };
  });

  // Sort pubkeys lexicographically (sortedmulti) — keep track of original mapping
  const sorted = [...signerInfos].sort((a, b) => comparePubkeys(a.pubkey, b.pubkey));
  const sortedPubkeys = sorted.map((s) => s.pubkey);

  // Build bip32Derivation for ALL signers (sorted order)
  const bip32Derivation: MultisigPayment["bip32Derivation"] = sorted.map((s) => [
    s.pubkey,
    { fingerprint: s.fingerprint, path: s.path },
  ]);

  // Use @scure/btc-signer payment helpers
  const ms = p2ms(m, sortedPubkeys);

  if (addressType === 3) {
    // P2WSH
    const payment = p2wsh(ms, btcNet);
    return {
      address: payment.address!,
      script: payment.script,
      witnessScript: payment.witnessScript,
      bip32Derivation,
    };
  } else if (addressType === 2) {
    // P2SH-P2WSH
    const inner = p2wsh(ms, btcNet);
    const payment = p2sh(inner, btcNet);
    return {
      address: payment.address!,
      script: payment.script,
      witnessScript: payment.witnessScript,
      redeemScript: payment.redeemScript,
      bip32Derivation,
    };
  } else if (addressType === 1) {
    // P2SH
    const payment = p2sh(ms, btcNet);
    return {
      address: payment.address!,
      script: payment.script,
      redeemScript: payment.redeemScript,
      bip32Derivation,
    };
  } else {
    throw new Error("Taproot multisig not yet supported");
  }
}
