// Bitcoin address/payment derivation for multisig and miniscript descriptors
// Reference: libnunchuk CoreUtils::DeriveAddresses

import { HDKey } from "@scure/bip32";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32, createBase58check, hex } from "@scure/base";
import {
  p2ms,
  p2wsh,
  p2sh,
  p2tr,
  p2tr_ms,
  p2tr_pk,
  bip32Path,
  NETWORK,
  TEST_NETWORK,
  TAPROOT_UNSPENDABLE_KEY,
} from "@scure/btc-signer";
import type { TaprootScriptTree } from "@scure/btc-signer/payment.js";
import type { TransactionInput } from "@scure/btc-signer/psbt.js";
import { Script, type ScriptOP } from "@scure/btc-signer/script.js";
import {
  getUnspendableXpub,
  parseDescriptor,
  parseSignerDescriptor,
  requireMiniscriptBody,
  sortTaprootDisableKeyPathSigners,
  type ParsedDescriptor,
  type TaprootWalletTemplate,
} from "./descriptor.js";
import {
  isValidMusigTemplate,
  miniscriptNeedsExplicitVerify,
  parseMiniscript,
  parseMusigTemplateKeys,
  parseTapscriptTemplate,
  type MiniscriptFragment,
} from "./miniscript.js";
import type { Network } from "./config.js";
import type { AddressType } from "./address-type.js";
import { aggregateMusigPubkey, toXOnlyPubkey } from "./taproot.js";
import { combinationIndices, concatBytes, hash160 } from "./utils.js";

const base58check = createBase58check(sha256);

export const MAINNET_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };
export const TESTNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };
const COMPRESSED_PUBKEY = /^(02|03)[0-9a-fA-F]{64}$/;
const TAPROOT_MUSIG_MAX_KEYS = 5;

function encodeScript(parts: ScriptOP[]): Uint8Array {
  return Script.encode(parts);
}

function buildTaprootMultiAScript(m: number, pubkeys: Uint8Array[], verify = false): Uint8Array {
  const script = p2tr_ms(m, pubkeys).script;
  if (!verify) {
    return script;
  }

  const parts = Script.decode(script);
  if (parts[parts.length - 1] !== "NUMEQUAL") {
    throw new Error("Invalid taproot multi_a script");
  }
  return encodeScript([...parts.slice(0, -1), "NUMEQUALVERIFY"]);
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
  addressType: AddressType,
  network: Network,
): string {
  if (addressType === "TAPROOT") {
    return deriveTaprootMultisigPayment(signers, m, network, 0, 0).address;
  }

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

  if (addressType === "NATIVE_SEGWIT") {
    // NATIVE_SEGWIT: P2WSH — bech32(witness_v0, SHA256(script))
    const scriptHash = sha256(redeemScript);
    const prefix = isMainnet ? "bc" : "tb";
    const words = bech32.toWords(scriptHash);
    return bech32.encode(prefix, [0, ...words]);
  } else if (addressType === "NESTED_SEGWIT") {
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
  } else if (addressType === "LEGACY") {
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
  addressType: AddressType,
  network: Network,
  chain: 0 | 1, // 0 = receive, 1 = change
  startIndex: number,
  count: number,
  taprootWalletTemplate: TaprootWalletTemplate = "DISABLE_KEY_PATH",
): string[] {
  if (addressType === "TAPROOT") {
    const descriptorSigners = sortTaprootDisableKeyPathSigners(
      signers,
      "TAPROOT",
      taprootWalletTemplate,
    );
    const chainInfos = deriveTaprootSignerChainInfos(descriptorSigners, network, chain);
    return Array.from(
      { length: count },
      (_, offset) =>
        buildTaprootMultisigPaymentFromSignerInfos(
          deriveTaprootSignerInfosFromChainInfos(chainInfos, startIndex + offset),
          m,
          network,
          taprootWalletTemplate,
        ).address,
    );
  }

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

    if (addressType === "NATIVE_SEGWIT") {
      const scriptHash = sha256(redeemScript);
      const prefix = isMainnet ? "bc" : "tb";
      const words = bech32.toWords(scriptHash);
      addresses.push(bech32.encode(prefix, [0, ...words]));
    } else if (addressType === "NESTED_SEGWIT") {
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
    } else if (addressType === "LEGACY") {
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
  tapLeafScript?: TransactionInput["tapLeafScript"];
  tapBip32Derivation?: Array<
    [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]
  >;
  tapKeyBip32Derivation?: Array<
    [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]
  >;
  tapInternalKey?: Uint8Array;
  tapMerkleRoot?: Uint8Array;
}

export type MultisigPayment = WalletPayment;

interface TaprootSignerInfo {
  pubkey: Uint8Array;
  xOnlyPubkey: Uint8Array;
  fingerprint: number;
  path: number[];
}

interface TaprootSignerChainInfo {
  chainKey: HDKey;
  fingerprint: number;
  pathPrefix: number[];
}

function deriveTaprootSignerChainInfos(
  signers: string[],
  network: Network,
  chain: 0 | 1,
): TaprootSignerChainInfo[] {
  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  return signers.map((desc) => {
    const parsed = parseSignerDescriptor(desc);
    const chainKey = HDKey.fromExtendedKey(parsed.xpub, versions).deriveChild(chain);
    return {
      chainKey,
      fingerprint: parseInt(parsed.masterFingerprint, 16),
      pathPrefix: bip32Path(`m${parsed.derivationPath}/${chain}`),
    };
  });
}

function deriveTaprootSignerInfosFromChainInfos(
  chainInfos: TaprootSignerChainInfo[],
  index: number,
): TaprootSignerInfo[] {
  return chainInfos.map(({ chainKey, fingerprint, pathPrefix }) => {
    const child = chainKey.deriveChild(index);
    if (!child.publicKey) {
      throw new Error("Failed to derive public key");
    }
    return {
      pubkey: child.publicKey,
      xOnlyPubkey: toXOnlyPubkey(child.publicKey),
      fingerprint,
      path: [...pathPrefix, index],
    };
  });
}

function deriveTaprootSignerInfos(
  signers: string[],
  network: Network,
  chain: 0 | 1,
  index: number,
): TaprootSignerInfo[] {
  return deriveTaprootSignerInfosFromChainInfos(
    deriveTaprootSignerChainInfos(signers, network, chain),
    index,
  );
}

function buildTaprootScriptTree(nodes: TaprootScriptTree[]): TaprootScriptTree {
  if (nodes.length === 1) {
    return nodes[0];
  }

  const next: TaprootScriptTree[] = [];
  for (let i = 0; i < nodes.length; i += 2) {
    if (i === nodes.length - 1) {
      next.push(nodes[i]);
    } else {
      next.push([nodes[i], nodes[i + 1]]);
    }
  }
  return buildTaprootScriptTree(next);
}

interface TaprootMusigLeafData {
  indices: number[];
  script: Uint8Array;
}

function buildTaprootMusigLeafData(
  signerInfos: TaprootSignerInfo[],
  m: number,
  skipFirst: boolean,
): TaprootMusigLeafData[] {
  const combinations = combinationIndices(signerInfos.length, m);
  const leafCombinations = skipFirst ? combinations.slice(1) : combinations;
  return leafCombinations.map((indices) => {
    const aggregatePubkey = aggregateMusigPubkey(indices.map((i) => signerInfos[i].pubkey));
    return { indices, script: p2tr_pk(aggregatePubkey).script };
  });
}

function taprootLeafHash(payment: { leaves?: Array<{ hash: Uint8Array }> }): Uint8Array[] {
  const leaves = (payment as { leaves?: Array<{ hash: Uint8Array }> }).leaves ?? [];
  return leaves.length === 1 ? [leaves[0].hash] : [];
}

function taprootLeafHashesByScript(payment: {
  leaves?: Array<{ script: Uint8Array; hash: Uint8Array }>;
}): Map<string, Uint8Array[]> {
  const hashesByScript = new Map<string, Uint8Array[]>();
  const leaves =
    (payment as { leaves?: Array<{ script: Uint8Array; hash: Uint8Array }> }).leaves ?? [];
  for (const leaf of leaves) {
    const scriptHex = hex.encode(leaf.script);
    const hashes = hashesByScript.get(scriptHex) ?? [];
    hashes.push(leaf.hash);
    hashesByScript.set(scriptHex, hashes);
  }
  return hashesByScript;
}

function addUniqueHashes(target: Uint8Array[], hashes: Uint8Array[]): void {
  for (const hash of hashes) {
    if (!target.some((existing) => hex.encode(existing) === hex.encode(hash))) {
      target.push(hash);
    }
  }
}

function buildTaprootMusigDerivations(
  signerInfos: TaprootSignerInfo[],
  leafData: TaprootMusigLeafData[],
  payment: { leaves?: Array<{ script: Uint8Array; hash: Uint8Array }> },
): WalletPayment["tapBip32Derivation"] {
  const hashesByScript = taprootLeafHashesByScript(payment);
  const derivations = new Map<
    string,
    [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]
  >();

  for (const leaf of leafData) {
    const hashes = hashesByScript.get(hex.encode(leaf.script)) ?? [];
    for (const signerIndex of leaf.indices) {
      const signer = signerInfos[signerIndex];
      const pubkeyHex = hex.encode(signer.xOnlyPubkey);
      const existing = derivations.get(pubkeyHex);
      if (existing) {
        addUniqueHashes(existing[1].hashes, hashes);
        continue;
      }
      derivations.set(pubkeyHex, [
        signer.xOnlyPubkey,
        {
          hashes: [...hashes],
          der: { fingerprint: signer.fingerprint, path: signer.path },
        },
      ]);
    }
  }

  return [...derivations.values()];
}

function buildTaprootKeypathDerivations(
  signerInfos: TaprootSignerInfo[],
  indices: number[],
): WalletPayment["tapBip32Derivation"] {
  return indices.map((signerIndex) => {
    const signer = signerInfos[signerIndex];
    return [
      signer.xOnlyPubkey,
      { hashes: [], der: { fingerprint: signer.fingerprint, path: signer.path } },
    ];
  });
}

function mergeTaprootDerivations(
  ...groups: Array<WalletPayment["tapBip32Derivation"] | undefined>
): WalletPayment["tapBip32Derivation"] {
  const merged = new Map<
    string,
    [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]
  >();

  for (const group of groups) {
    for (const entry of group ?? []) {
      const [pubkey, data] = entry;
      const pubkeyHex = hex.encode(pubkey);
      const existing = merged.get(pubkeyHex);
      if (existing) {
        addUniqueHashes(existing[1].hashes, data.hashes);
        continue;
      }
      merged.set(pubkeyHex, [
        pubkey,
        {
          hashes: [...data.hashes],
          der: data.der,
        },
      ]);
    }
  }

  return [...merged.values()];
}

function buildTaprootMultisigPaymentFromSignerInfos(
  signerInfos: TaprootSignerInfo[],
  m: number,
  network: Network,
  taprootWalletTemplate: TaprootWalletTemplate = "DISABLE_KEY_PATH",
): WalletPayment {
  if (signerInfos.length < 2) {
    throw new Error("Taproot multisig requires at least two signers");
  }
  if (m < 1 || m > signerInfos.length) {
    throw new Error("Invalid taproot multisig m/n");
  }

  const btcNet = network === "mainnet" ? NETWORK : TEST_NETWORK;
  const useMusigLeaves = signerInfos.length <= TAPROOT_MUSIG_MAX_KEYS || signerInfos.length === m;

  if (useMusigLeaves) {
    if (taprootWalletTemplate === "DEFAULT") {
      const keypathIndices = combinationIndices(signerInfos.length, m)[0];
      const internalKey = aggregateMusigPubkey(keypathIndices.map((i) => signerInfos[i].pubkey));
      const leafData = buildTaprootMusigLeafData(signerInfos, m, true);
      const keypathDerivations = buildTaprootKeypathDerivations(signerInfos, keypathIndices);
      const leaves = leafData.map(({ script }) => ({ script }));
      const payment =
        leaves.length > 0
          ? p2tr(internalKey, buildTaprootScriptTree(leaves), btcNet)
          : p2tr(internalKey, undefined, btcNet);
      const treePayment = payment as {
        tapLeafScript?: TransactionInput["tapLeafScript"];
        tapMerkleRoot?: Uint8Array;
      };
      return {
        address: payment.address!,
        script: payment.script,
        bip32Derivation: [],
        tapInternalKey: payment.tapInternalKey,
        tapMerkleRoot: treePayment.tapMerkleRoot,
        tapLeafScript: treePayment.tapLeafScript,
        tapBip32Derivation: mergeTaprootDerivations(
          keypathDerivations,
          leafData.length > 0
            ? buildTaprootMusigDerivations(
                signerInfos,
                leafData,
                payment as { leaves?: Array<{ script: Uint8Array; hash: Uint8Array }> },
              )
            : [],
        ),
        tapKeyBip32Derivation: keypathDerivations,
      };
    }

    const leafData = buildTaprootMusigLeafData(signerInfos, m, false);
    const payment = p2tr(
      TAPROOT_UNSPENDABLE_KEY,
      buildTaprootScriptTree(leafData.map(({ script }) => ({ script }))),
      btcNet,
    );
    return {
      address: payment.address!,
      script: payment.script,
      bip32Derivation: [],
      tapInternalKey: payment.tapInternalKey,
      tapMerkleRoot: payment.tapMerkleRoot,
      tapLeafScript: payment.tapLeafScript,
      tapBip32Derivation: buildTaprootMusigDerivations(signerInfos, leafData, payment),
    };
  }

  const keypathDerivations =
    taprootWalletTemplate === "DEFAULT"
      ? buildTaprootKeypathDerivations(
          signerInfos,
          Array.from({ length: m }, (_, signerIndex) => signerIndex),
        )
      : undefined;
  const internalKey =
    taprootWalletTemplate === "DEFAULT"
      ? aggregateMusigPubkey(signerInfos.slice(0, m).map((s) => s.pubkey))
      : TAPROOT_UNSPENDABLE_KEY;
  const sorted = [...signerInfos].sort((a, b) => comparePubkeys(a.xOnlyPubkey, b.xOnlyPubkey));
  const payment = p2tr(
    internalKey,
    {
      script: p2tr_ms(
        m,
        sorted.map((s) => s.xOnlyPubkey),
      ).script,
    },
    btcNet,
  );
  const hashes = taprootLeafHash(payment);

  const scriptDerivations: WalletPayment["tapBip32Derivation"] = sorted.map((s) => [
    s.xOnlyPubkey,
    { hashes, der: { fingerprint: s.fingerprint, path: s.path } },
  ]);

  return {
    address: payment.address!,
    script: payment.script,
    bip32Derivation: [],
    tapInternalKey: payment.tapInternalKey,
    tapMerkleRoot: payment.tapMerkleRoot,
    tapLeafScript: payment.tapLeafScript,
    tapBip32Derivation: mergeTaprootDerivations(keypathDerivations, scriptDerivations),
    tapKeyBip32Derivation: keypathDerivations,
  };
}

export function deriveTaprootMultisigPayment(
  signers: string[],
  m: number,
  network: Network,
  chain: 0 | 1,
  index: number,
  taprootWalletTemplate: TaprootWalletTemplate = "DISABLE_KEY_PATH",
): WalletPayment {
  const descriptorSigners = sortTaprootDisableKeyPathSigners(
    signers,
    "TAPROOT",
    taprootWalletTemplate,
  );
  return buildTaprootMultisigPaymentFromSignerInfos(
    deriveTaprootSignerInfos(descriptorSigners, network, chain, index),
    m,
    network,
    taprootWalletTemplate,
  );
}

// Derive full PSBT input metadata for a multisig address at chain/index
// Uses @scure/btc-signer payment helpers (p2ms, p2wsh, p2sh)
export function deriveMultisigPayment(
  signers: string[],
  m: number,
  addressType: AddressType,
  network: Network,
  chain: 0 | 1,
  index: number,
  taprootWalletTemplate: TaprootWalletTemplate = "DISABLE_KEY_PATH",
): WalletPayment {
  if (addressType === "TAPROOT") {
    return deriveTaprootMultisigPayment(signers, m, network, chain, index, taprootWalletTemplate);
  }

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

  if (addressType === "NATIVE_SEGWIT") {
    // P2WSH
    const payment = p2wsh(ms, btcNet);
    return {
      address: payment.address!,
      script: payment.script,
      witnessScript: payment.witnessScript,
      bip32Derivation,
    };
  } else if (addressType === "NESTED_SEGWIT") {
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
  } else if (addressType === "LEGACY") {
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

export interface DescriptorTaprootMiniscriptLeafScript {
  leaf: string;
  script: Uint8Array;
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
  addressType: AddressType,
  verify = false,
): Uint8Array {
  const scriptPubkey = (keyExpression: string): Uint8Array => {
    const { pubkey } = resolveKey(keyExpression);
    return addressType === "TAPROOT" ? toXOnlyPubkey(pubkey) : pubkey;
  };

  switch (node.fragment) {
    case "JUST_0":
      return encodeScript([0]);
    case "JUST_1":
      return encodeScript([1]);
    case "PK": {
      return encodeScript([scriptPubkey(node.key), verify ? "CHECKSIGVERIFY" : "CHECKSIG"]);
    }
    case "PK_K": {
      return encodeScript([scriptPubkey(node.key)]);
    }
    case "PK_H": {
      const { pubkey } = resolveKey(node.key);
      return encodeScript(["DUP", "HASH160", hash160(pubkey), "EQUALVERIFY"]);
    }
    case "PKH": {
      const { pubkey } = resolveKey(node.key);
      return encodeScript([
        "DUP",
        "HASH160",
        hash160(pubkey),
        "EQUALVERIFY",
        verify ? "CHECKSIGVERIFY" : "CHECKSIG",
      ]);
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
    case "MULTI_A": {
      const keys = node.keys.map((key) => toXOnlyPubkey(resolveKey(key).pubkey));
      return buildTaprootMultiAScript(node.k, keys, verify);
    }
    case "WRAP_A":
      return concatBytes([
        encodeScript(["TOALTSTACK"]),
        compileMiniscriptFragment(node.sub, resolveKey, addressType),
        encodeScript(["FROMALTSTACK"]),
      ]);
    case "WRAP_S":
      return concatBytes([
        encodeScript(["SWAP"]),
        compileMiniscriptFragment(node.sub, resolveKey, addressType, verify),
      ]);
    case "WRAP_C":
      if (node.sub.fragment === "PK") {
        return encodeScript([scriptPubkey(node.sub.key), verify ? "CHECKSIGVERIFY" : "CHECKSIG"]);
      }
      if (node.sub.fragment === "PK_K" || node.sub.fragment === "PK_H") {
        return concatBytes([
          compileMiniscriptFragment(node.sub, resolveKey, addressType),
          encodeScript([verify ? "CHECKSIGVERIFY" : "CHECKSIG"]),
        ]);
      }
      return concatBytes([
        compileMiniscriptFragment(node.sub, resolveKey, addressType),
        encodeScript([verify ? "CHECKSIGVERIFY" : "CHECKSIG"]),
      ]);
    case "WRAP_D":
      return concatBytes([
        encodeScript(["DUP", "IF"]),
        compileMiniscriptFragment(node.sub, resolveKey, addressType),
        encodeScript(["ENDIF"]),
      ]);
    case "WRAP_V":
      return miniscriptNeedsExplicitVerify(node.sub, addressType)
        ? concatBytes([
            compileMiniscriptFragment(node.sub, resolveKey, addressType),
            encodeScript(["VERIFY"]),
          ])
        : compileMiniscriptFragment(node.sub, resolveKey, addressType, true);
    case "WRAP_J":
      return concatBytes([
        encodeScript(["SIZE", "0NOTEQUAL", "IF"]),
        compileMiniscriptFragment(node.sub, resolveKey, addressType),
        encodeScript(["ENDIF"]),
      ]);
    case "WRAP_N":
      return concatBytes([
        compileMiniscriptFragment(node.sub, resolveKey, addressType),
        encodeScript(["0NOTEQUAL"]),
      ]);
    case "AND_V":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey, addressType),
        compileMiniscriptFragment(node.subs[1], resolveKey, addressType, verify),
      ]);
    case "AND_B":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey, addressType),
        compileMiniscriptFragment(node.subs[1], resolveKey, addressType),
        encodeScript(["BOOLAND"]),
      ]);
    case "OR_B":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey, addressType),
        compileMiniscriptFragment(node.subs[1], resolveKey, addressType),
        encodeScript(["BOOLOR"]),
      ]);
    case "OR_C":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey, addressType),
        encodeScript(["NOTIF"]),
        compileMiniscriptFragment(node.subs[1], resolveKey, addressType),
        encodeScript(["ENDIF"]),
      ]);
    case "OR_D":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey, addressType),
        encodeScript(["IFDUP", "NOTIF"]),
        compileMiniscriptFragment(node.subs[1], resolveKey, addressType),
        encodeScript(["ENDIF"]),
      ]);
    case "OR_I":
      return concatBytes([
        encodeScript(["IF"]),
        compileMiniscriptFragment(node.subs[0], resolveKey, addressType),
        encodeScript(["ELSE"]),
        compileMiniscriptFragment(node.subs[1], resolveKey, addressType),
        encodeScript(["ENDIF"]),
      ]);
    case "ANDOR":
      return concatBytes([
        compileMiniscriptFragment(node.subs[0], resolveKey, addressType),
        encodeScript(["NOTIF"]),
        compileMiniscriptFragment(node.subs[2], resolveKey, addressType),
        encodeScript(["ELSE"]),
        compileMiniscriptFragment(node.subs[1], resolveKey, addressType),
        encodeScript(["ENDIF"]),
      ]);
    case "THRESH": {
      let script = compileMiniscriptFragment(node.subs[0], resolveKey, addressType);
      for (let i = 1; i < node.subs.length; i++) {
        script = concatBytes([
          script,
          compileMiniscriptFragment(node.subs[i], resolveKey, addressType),
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
    case "PKH":
    case "PK_H":
    case "PK_K":
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

function buildTaprootScriptTreeFromDepths(
  nodes: TaprootScriptTree[],
  depths: number[],
): TaprootScriptTree {
  if (nodes.length !== depths.length || nodes.length === 0) {
    throw new Error("Invalid taproot script tree");
  }

  const stack: Array<{ depth: number; node: TaprootScriptTree }> = [];
  for (let i = 0; i < nodes.length; i++) {
    stack.push({ depth: depths[i], node: nodes[i] });
    while (
      stack.length >= 2 &&
      stack[stack.length - 1].depth === stack[stack.length - 2].depth &&
      stack[stack.length - 1].depth > 0
    ) {
      const right = stack.pop()!;
      const left = stack.pop()!;
      stack.push({ depth: left.depth - 1, node: [left.node, right.node] });
    }
  }

  if (stack.length !== 1 || stack[0].depth !== 0) {
    throw new Error("Invalid taproot script tree depths");
  }
  return stack[0].node;
}

function collectTaprootLeafKeyExpressions(leaf: string): string[] {
  if (isValidMusigTemplate(leaf)) {
    return parseMusigTemplateKeys(leaf);
  }
  return collectMiniscriptKeyExpressions(parseMiniscript(leaf, "TAPROOT"));
}

function compileTaprootLeaf(
  leaf: string,
  resolveKey: (keyExpression: string) => DerivedKeyInfo,
): Uint8Array {
  if (isValidMusigTemplate(leaf)) {
    const pubkeys = parseMusigTemplateKeys(leaf).map((key) => resolveKey(key).pubkey);
    return p2tr_pk(aggregateMusigPubkey(pubkeys)).script;
  }
  return compileMiniscriptFragment(parseMiniscript(leaf, "TAPROOT"), resolveKey, "TAPROOT");
}

function deriveTaprootMiniscriptInternalKey(
  parsed: ParsedDescriptor,
  versions: typeof MAINNET_VERSIONS,
  chain: 0 | 1,
  index: number,
): Uint8Array {
  if (parsed.m === 0) {
    const key = HDKey.fromExtendedKey(getUnspendableXpub(parsed.signers), versions)
      .deriveChild(chain)
      .deriveChild(index);
    if (!key.publicKey) {
      throw new Error("Failed to derive taproot unspendable internal key");
    }
    return toXOnlyPubkey(key.publicKey);
  }

  if (parsed.m < 0 || parsed.m > parsed.signers.length) {
    throw new Error("Invalid taproot miniscript keypath");
  }

  const pubkeys = parsed.signers.slice(0, parsed.m).map((signer) => {
    const derived = deriveKeyExpression(`${signer}/<0;1>/*`, versions, chain, index);
    return derived.pubkey;
  });

  return parsed.m === 1 ? toXOnlyPubkey(pubkeys[0]) : aggregateMusigPubkey(pubkeys);
}

function deriveMiniscriptPaymentFromParsed(
  parsed: ParsedDescriptor,
  network: Network,
  chain: 0 | 1,
  index: number,
  fragment?: MiniscriptFragment,
): WalletPayment {
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

  if (parsed.addressType === "TAPROOT") {
    const parsedTapscript = parseTapscriptTemplate(requireMiniscriptBody(parsed));
    if (parsedTapscript.subscripts.length === 0) {
      throw new Error("Taproot miniscript descriptor is missing tapscript");
    }

    const leafScripts = parsedTapscript.subscripts.map((leaf) =>
      compileTaprootLeaf(leaf, resolveKey),
    );
    const tree = buildTaprootScriptTreeFromDepths(
      leafScripts.map((script) => ({ script })),
      parsedTapscript.depths,
    );
    const internalKey = deriveTaprootMiniscriptInternalKey(parsed, versions, chain, index);
    const btcNet = network === "mainnet" ? NETWORK : TEST_NETWORK;
    const payment = p2tr(internalKey, tree, btcNet, true);
    const leafHashesByScript = new Map<string, Uint8Array[]>();
    for (const leaf of payment.leaves) {
      const scriptHex = hex.encode(leaf.script);
      const hashes = leafHashesByScript.get(scriptHex) ?? [];
      hashes.push(leaf.hash);
      leafHashesByScript.set(scriptHex, hashes);
    }

    const tapDerivations = new Map<
      string,
      [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]
    >();
    const tapKeyDerivations: WalletPayment["tapBip32Derivation"] = [];
    if (parsed.m > 0) {
      for (const signer of parsed.signers.slice(0, parsed.m)) {
        const info = resolveKey(`${signer}/<0;1>/*`);
        if (!info.bip32) {
          continue;
        }
        const xOnlyPubkey = toXOnlyPubkey(info.pubkey);
        const pubkeyHex = hex.encode(xOnlyPubkey);
        tapKeyDerivations.push([xOnlyPubkey, { hashes: [], der: info.bip32 }]);
        if (!tapDerivations.has(pubkeyHex)) {
          tapDerivations.set(pubkeyHex, [xOnlyPubkey, { hashes: [], der: info.bip32 }]);
        }
      }
    }
    for (let i = 0; i < parsedTapscript.subscripts.length; i++) {
      const hashes = leafHashesByScript.get(hex.encode(leafScripts[i])) ?? [];
      for (const keyExpression of collectTaprootLeafKeyExpressions(parsedTapscript.subscripts[i])) {
        const info = resolveKey(keyExpression);
        if (!info.bip32) {
          continue;
        }
        const xOnlyPubkey = toXOnlyPubkey(info.pubkey);
        const pubkeyHex = hex.encode(xOnlyPubkey);
        const existing = tapDerivations.get(pubkeyHex);
        if (existing) {
          for (const hash of hashes) {
            if (!existing[1].hashes.some((item) => hex.encode(item) === hex.encode(hash))) {
              existing[1].hashes.push(hash);
            }
          }
          continue;
        }
        tapDerivations.set(pubkeyHex, [xOnlyPubkey, { hashes: [...hashes], der: info.bip32 }]);
      }
    }

    return {
      address: payment.address!,
      script: payment.script,
      bip32Derivation: [],
      tapInternalKey: payment.tapInternalKey,
      tapMerkleRoot: payment.tapMerkleRoot,
      tapLeafScript: payment.tapLeafScript,
      tapBip32Derivation: [...tapDerivations.values()],
      tapKeyBip32Derivation: tapKeyDerivations.length > 0 ? tapKeyDerivations : undefined,
    };
  }

  if (parsed.addressType !== "NATIVE_SEGWIT") {
    throw new Error("Only native segwit and taproot miniscript wallets are supported");
  }

  const resolvedFragment =
    fragment ?? parseMiniscript(requireMiniscriptBody(parsed), parsed.addressType);
  const witnessScript = compileMiniscriptFragment(resolvedFragment, resolveKey, parsed.addressType);
  const witnessScriptHash = sha256(witnessScript);
  const prefix = network === "mainnet" ? "bc" : "tb";
  const bip32Derivation: WalletPayment["bip32Derivation"] = [];
  const seenPubkeys = new Set<string>();

  for (const keyExpression of collectMiniscriptKeyExpressions(resolvedFragment)) {
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
  fragment?: MiniscriptFragment,
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
  const keyExpressions =
    parsed.addressType === "TAPROOT"
      ? parseTapscriptTemplate(requireMiniscriptBody(parsed)).subscripts.flatMap(
          collectTaprootLeafKeyExpressions,
        )
      : collectMiniscriptKeyExpressions(
          fragment ?? parseMiniscript(requireMiniscriptBody(parsed), parsed.addressType),
        );

  for (const keyExpression of keyExpressions) {
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

export function compileDescriptorTaprootMiniscriptLeafScripts(
  descriptor: string,
  network: Network,
  chain: 0 | 1,
  index: number,
): DescriptorTaprootMiniscriptLeafScript[] {
  const parsed = parseDescriptor(descriptor);
  if (parsed.kind !== "miniscript" || parsed.addressType !== "TAPROOT" || !parsed.miniscript) {
    return [];
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

  const parsedTapscript = parseTapscriptTemplate(requireMiniscriptBody(parsed));
  return parsedTapscript.subscripts.map((leaf) => ({
    leaf,
    script: compileTaprootLeaf(leaf, resolveKey),
  }));
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
      parsed.taprootWalletTemplate,
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
      parsed.taprootWalletTemplate,
    );
  }

  const fragment =
    parsed.addressType === "TAPROOT"
      ? undefined
      : parseMiniscript(requireMiniscriptBody(parsed), parsed.addressType);
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
