// Bitcoin address/payment derivation for multisig and miniscript descriptors
// Reference: libnunchuk CoreUtils::DeriveAddresses

import { HDKey } from "@scure/bip32";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { bech32, createBase58check, hex } from "@scure/base";
import { p2ms, p2wsh, p2sh, bip32Path, NETWORK, TEST_NETWORK } from "@scure/btc-signer";
import { Script, type ScriptOP } from "@scure/btc-signer/script.js";
import { parseDescriptor, parseSignerDescriptor, type ParsedDescriptor } from "./descriptor.js";
import { parseMiniscript, type MiniscriptFragment } from "./miniscript.js";
import type { Network } from "./config.js";

const base58check = createBase58check(sha256);

export const MAINNET_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };
export const TESTNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };
const COMPRESSED_PUBKEY = /^(02|03)[0-9a-fA-F]{64}$/;

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;

  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

function encodeScript(parts: ScriptOP[]): Uint8Array {
  return Script.encode(parts);
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
export interface WalletPayment {
  address: string;
  script: Uint8Array;
  witnessScript?: Uint8Array;
  redeemScript?: Uint8Array;
  bip32Derivation: Array<[Uint8Array, { fingerprint: number; path: number[] }]>;
}

export type MultisigPayment = WalletPayment;

// Derive full PSBT input metadata for a multisig address at chain/index
// Uses @scure/btc-signer payment helpers (p2ms, p2wsh, p2sh)
export function deriveMultisigPayment(
  signers: string[],
  m: number,
  addressType: number,
  network: Network,
  chain: 0 | 1,
  index: number,
): WalletPayment {
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
  const bip32Derivation: WalletPayment["bip32Derivation"] = sorted.map((s) => [
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

interface DerivedKeyInfo {
  bip32?: { fingerprint: number; path: number[] };
  pubkey: Uint8Array;
}

export interface DescriptorMiniscriptKeyInfo extends DerivedKeyInfo {
  keyExpression: string;
}

function requireMiniscriptBody(parsed: ParsedDescriptor): string {
  if (parsed.kind !== "miniscript" || !parsed.miniscript) {
    throw new Error("Parsed descriptor does not contain a miniscript body");
  }
  return parsed.miniscript;
}

function resolveChildPath(pathExpression: string, chain: 0 | 1, index: number): number[] {
  const trimmed = pathExpression.trim();

  const multipath = trimmed.match(/\/<([^>]+)>\/\*$/);
  if (multipath) {
    const branches = multipath[1].split(";").map((branch) => Number.parseInt(branch, 10));
    if (branches.some((branch) => !Number.isSafeInteger(branch) || branch < 0)) {
      throw new Error(`Unsupported miniscript child path: ${pathExpression}`);
    }
    if (chain >= branches.length) {
      throw new Error(`Missing miniscript branch ${chain} in child path: ${pathExpression}`);
    }
    return [branches[chain], index];
  }

  const fixedChain = trimmed.match(/\/(\d+)\/\*$/);
  if (fixedChain) {
    return [Number.parseInt(fixedChain[1], 10), index];
  }

  if (trimmed.endsWith("/*")) {
    return [index];
  }

  return [];
}

function stripChildPath(keyExpression: string): string {
  if (keyExpression.includes("/<") && keyExpression.endsWith("/*")) {
    const suffixStart = keyExpression.lastIndexOf("/<");
    return keyExpression.slice(0, suffixStart);
  }
  if (keyExpression.endsWith("/*")) {
    const suffixStart = keyExpression.lastIndexOf("/");
    const maybeFixedChain = keyExpression.slice(0, suffixStart);
    const previousSlash = maybeFixedChain.lastIndexOf("/");
    if (previousSlash !== -1 && /^[0-9]+$/.test(maybeFixedChain.slice(previousSlash + 1))) {
      return maybeFixedChain.slice(0, previousSlash);
    }
    return keyExpression.slice(0, suffixStart);
  }
  return keyExpression;
}

function deriveKeyExpression(
  keyExpression: string,
  versions: typeof MAINNET_VERSIONS,
  chain: 0 | 1,
  index: number,
): DerivedKeyInfo {
  const childPath = resolveChildPath(keyExpression, chain, index);
  const baseKey = stripChildPath(keyExpression);

  if (COMPRESSED_PUBKEY.test(baseKey)) {
    if (childPath.length > 0) {
      throw new Error(`Raw public keys cannot use wildcard child paths: ${keyExpression}`);
    }
    return { pubkey: hex.decode(baseKey) };
  }

  const parsed = parseSignerDescriptor(baseKey);
  let current = HDKey.fromExtendedKey(parsed.xpub, versions);
  for (const child of childPath) {
    current = current.deriveChild(child);
  }
  if (!current.publicKey) {
    throw new Error("Failed to derive public key");
  }

  const pathSuffix = childPath.length > 0 ? `/${childPath.join("/")}` : "";
  return {
    pubkey: current.publicKey,
    bip32: {
      fingerprint: parseInt(parsed.masterFingerprint, 16),
      path: bip32Path(`m${parsed.derivationPath}${pathSuffix}`),
    },
  };
}

function compileMiniscriptFragment(
  node: MiniscriptFragment,
  resolveKey: (keyExpression: string) => DerivedKeyInfo,
  verify = false,
): Uint8Array {
  switch (node.fragment) {
    case "JUST_0":
      return encodeScript([0]);
    case "JUST_1":
      return encodeScript([1]);
    case "PK": {
      const { pubkey } = resolveKey(node.key);
      return encodeScript([pubkey, verify ? "CHECKSIGVERIFY" : "CHECKSIG"]);
    }
    case "OLDER":
      return encodeScript([node.k, "CHECKSEQUENCEVERIFY"]);
    case "AFTER":
      return encodeScript([node.k, "CHECKLOCKTIMEVERIFY"]);
    case "HASH160":
      return encodeScript([
        "SIZE",
        32,
        "EQUALVERIFY",
        "HASH160",
        hex.decode(node.data),
        verify ? "EQUALVERIFY" : "EQUAL",
      ]);
    case "HASH256":
      return encodeScript([
        "SIZE",
        32,
        "EQUALVERIFY",
        "HASH256",
        hex.decode(node.data),
        verify ? "EQUALVERIFY" : "EQUAL",
      ]);
    case "RIPEMD160":
      return encodeScript([
        "SIZE",
        32,
        "EQUALVERIFY",
        "RIPEMD160",
        hex.decode(node.data),
        verify ? "EQUALVERIFY" : "EQUAL",
      ]);
    case "SHA256":
      return encodeScript([
        "SIZE",
        32,
        "EQUALVERIFY",
        "SHA256",
        hex.decode(node.data),
        verify ? "EQUALVERIFY" : "EQUAL",
      ]);
    case "MULTI": {
      const keys = node.keys.map((key) => resolveKey(key).pubkey);
      return encodeScript([
        node.k,
        ...keys,
        keys.length,
        verify ? "CHECKMULTISIGVERIFY" : "CHECKMULTISIG",
      ]);
    }
    case "MULTI_A":
      throw new Error("Taproot miniscript payment derivation is not supported yet");
    case "WRAP_A":
      return concatBytes([
        encodeScript(["TOALTSTACK"]),
        compileMiniscriptFragment(node.sub, resolveKey),
        encodeScript(["FROMALTSTACK"]),
      ]);
    case "WRAP_S":
      return concatBytes([
        encodeScript(["SWAP"]),
        compileMiniscriptFragment(node.sub, resolveKey, verify),
      ]);
    case "WRAP_C":
      if (node.sub.fragment === "PK") {
        const { pubkey } = resolveKey(node.sub.key);
        return encodeScript([pubkey, verify ? "CHECKSIGVERIFY" : "CHECKSIG"]);
      }
      return concatBytes([
        compileMiniscriptFragment(node.sub, resolveKey),
        encodeScript([verify ? "CHECKSIGVERIFY" : "CHECKSIG"]),
      ]);
    case "WRAP_D":
      return concatBytes([
        encodeScript(["DUP", "IF"]),
        compileMiniscriptFragment(node.sub, resolveKey),
        encodeScript(["ENDIF"]),
      ]);
    case "WRAP_V":
      return compileMiniscriptFragment(node.sub, resolveKey, true);
    case "WRAP_J":
      return concatBytes([
        encodeScript(["SIZE", "0NOTEQUAL", "IF"]),
        compileMiniscriptFragment(node.sub, resolveKey),
        encodeScript(["ENDIF"]),
      ]);
    case "WRAP_N":
      return concatBytes([
        compileMiniscriptFragment(node.sub, resolveKey),
        encodeScript(["0NOTEQUAL"]),
      ]);
    case "AND_V":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey),
        compileMiniscriptFragment(node.subs[1], resolveKey, verify),
      ]);
    case "AND_B":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey),
        compileMiniscriptFragment(node.subs[1], resolveKey),
        encodeScript(["BOOLAND"]),
      ]);
    case "OR_B":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey),
        compileMiniscriptFragment(node.subs[1], resolveKey),
        encodeScript(["BOOLOR"]),
      ]);
    case "OR_C":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey),
        encodeScript(["NOTIF"]),
        compileMiniscriptFragment(node.subs[1], resolveKey),
        encodeScript(["ENDIF"]),
      ]);
    case "OR_D":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey),
        encodeScript(["IFDUP", "NOTIF"]),
        compileMiniscriptFragment(node.subs[1], resolveKey),
        encodeScript(["ENDIF"]),
      ]);
    case "OR_I":
      return concatBytes([
        encodeScript(["IF"]),
        compileMiniscriptFragment(node.subs[0], resolveKey),
        encodeScript(["ELSE"]),
        compileMiniscriptFragment(node.subs[1], resolveKey),
        encodeScript(["ENDIF"]),
      ]);
    case "ANDOR":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey),
        encodeScript(["NOTIF"]),
        compileMiniscriptFragment(node.subs[2], resolveKey),
        encodeScript(["ELSE"]),
        compileMiniscriptFragment(node.subs[1], resolveKey),
        encodeScript(["ENDIF"]),
      ]);
    case "THRESH": {
      let script = compileMiniscriptFragment(node.subs[0], resolveKey);
      for (let i = 1; i < node.subs.length; i++) {
        script = concatBytes([
          script,
          compileMiniscriptFragment(node.subs[i], resolveKey),
          encodeScript(["ADD"]),
        ]);
      }
      return concatBytes([script, encodeScript([node.k, verify ? "EQUALVERIFY" : "EQUAL"])]);
    }
  }
}

function collectMiniscriptKeyExpressions(node: MiniscriptFragment): string[] {
  switch (node.fragment) {
    case "PK":
      return [node.key];
    case "MULTI":
    case "MULTI_A":
      return [...node.keys];
    case "WRAP_A":
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_D":
    case "WRAP_V":
    case "WRAP_J":
    case "WRAP_N":
      return collectMiniscriptKeyExpressions(node.sub);
    case "AND_V":
    case "AND_B":
    case "OR_B":
    case "OR_C":
    case "OR_D":
    case "OR_I":
      return node.subs.flatMap((sub) => collectMiniscriptKeyExpressions(sub));
    case "ANDOR":
      return node.subs.flatMap((sub) => collectMiniscriptKeyExpressions(sub));
    case "THRESH":
      return node.subs.flatMap((sub) => collectMiniscriptKeyExpressions(sub));
    default:
      return [];
  }
}

function deriveMiniscriptPaymentFromParsed(
  parsed: ParsedDescriptor,
  network: Network,
  chain: 0 | 1,
  index: number,
  fragment = parseMiniscript(requireMiniscriptBody(parsed), parsed.addressType as 3),
): WalletPayment {
  if (parsed.addressType !== 3) {
    throw new Error("Only native segwit miniscript wallets are currently supported");
  }

  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  const cache = new Map<string, DerivedKeyInfo>();
  const resolveKey = (keyExpression: string): DerivedKeyInfo => {
    const cached = cache.get(keyExpression);
    if (cached) {
      return cached;
    }
    const derived = deriveKeyExpression(keyExpression, versions, chain, index);
    cache.set(keyExpression, derived);
    return derived;
  };

  const witnessScript = compileMiniscriptFragment(fragment, resolveKey);
  const witnessScriptHash = sha256(witnessScript);
  const prefix = network === "mainnet" ? "bc" : "tb";
  const bip32Derivation: WalletPayment["bip32Derivation"] = [];
  const seenPubkeys = new Set<string>();

  for (const keyExpression of collectMiniscriptKeyExpressions(fragment)) {
    const info = resolveKey(keyExpression);
    if (!info.bip32) {
      continue;
    }
    const pubkeyHex = hex.encode(info.pubkey);
    if (seenPubkeys.has(pubkeyHex)) {
      continue;
    }
    seenPubkeys.add(pubkeyHex);
    bip32Derivation.push([info.pubkey, info.bip32]);
  }

  return {
    address: bech32.encode(prefix, [0, ...bech32.toWords(witnessScriptHash)]),
    script: encodeScript([0, witnessScriptHash]),
    witnessScript,
    bip32Derivation,
  };
}

function deriveDescriptorMiniscriptKeysFromParsed(
  parsed: ParsedDescriptor,
  network: Network,
  chain: 0 | 1,
  index: number,
  fragment = parseMiniscript(requireMiniscriptBody(parsed), parsed.addressType as 3),
): DescriptorMiniscriptKeyInfo[] {
  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  const cache = new Map<string, DerivedKeyInfo>();
  const resolveKey = (keyExpression: string): DerivedKeyInfo => {
    const cached = cache.get(keyExpression);
    if (cached) {
      return cached;
    }
    const derived = deriveKeyExpression(keyExpression, versions, chain, index);
    cache.set(keyExpression, derived);
    return derived;
  };

  const seen = new Set<string>();
  const keys: DescriptorMiniscriptKeyInfo[] = [];
  for (const keyExpression of collectMiniscriptKeyExpressions(fragment)) {
    if (seen.has(keyExpression)) {
      continue;
    }
    seen.add(keyExpression);
    keys.push({
      keyExpression,
      ...resolveKey(keyExpression),
    });
  }
  return keys;
}

function deriveDescriptorPaymentFromParsed(
  parsed: ParsedDescriptor,
  network: Network,
  chain: 0 | 1,
  index: number,
  miniscriptFragment?: MiniscriptFragment,
): WalletPayment {
  if (parsed.kind === "multisig") {
    return deriveMultisigPayment(
      parsed.signers,
      parsed.m,
      parsed.addressType,
      network,
      chain,
      index,
    );
  }

  return deriveMiniscriptPaymentFromParsed(parsed, network, chain, index, miniscriptFragment);
}

export function deriveDescriptorFirstAddress(descriptor: string, network: Network): string {
  return deriveDescriptorAddresses(descriptor, network, 0, 0, 1)[0];
}

export function deriveDescriptorAddresses(
  descriptor: string,
  network: Network,
  chain: 0 | 1,
  startIndex: number,
  count: number,
): string[] {
  const parsed = parseDescriptor(descriptor);
  if (parsed.kind === "multisig") {
    return deriveAddresses(
      parsed.signers,
      parsed.m,
      parsed.addressType,
      network,
      chain,
      startIndex,
      count,
    );
  }

  const fragment = parseMiniscript(requireMiniscriptBody(parsed), parsed.addressType as 3);
  const addresses: string[] = [];
  for (let index = startIndex; index < startIndex + count; index++) {
    addresses.push(
      deriveDescriptorPaymentFromParsed(parsed, network, chain, index, fragment).address,
    );
  }
  return addresses;
}

export function deriveDescriptorPayment(
  descriptor: string,
  network: Network,
  chain: 0 | 1,
  index: number,
): WalletPayment {
  const parsed = parseDescriptor(descriptor);
  return deriveDescriptorPaymentFromParsed(parsed, network, chain, index);
}

export function deriveDescriptorMiniscriptKeys(
  descriptor: string,
  network: Network,
  chain: 0 | 1,
  index: number,
): DescriptorMiniscriptKeyInfo[] {
  const parsed = parseDescriptor(descriptor);
  if (parsed.kind !== "miniscript") {
    throw new Error("Descriptor does not contain miniscript keys");
  }
  return deriveDescriptorMiniscriptKeysFromParsed(parsed, network, chain, index);
}
