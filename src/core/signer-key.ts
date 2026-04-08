import { HDKey } from "@scure/bip32";
import type { Network } from "./config.js";
import { parseSignerDescriptor } from "./descriptor.js";
import { MAINNET_VERSIONS, TESTNET_VERSIONS } from "./address.js";
import { loadKey, listKeys } from "./storage.js";
import { mnemonicToRootKey } from "./keygen.js";

export interface MatchedSignerKey {
  signerKey: HDKey;
  signerXfp: string;
  keyName?: string; // name from stored key, if resolved from local storage
}

export function matchSignerKey(
  xprv: string,
  signers: string[],
  network: Network,
): MatchedSignerKey | null {
  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  const inputKey = HDKey.fromExtendedKey(xprv, versions);
  const inputXpub = inputKey.publicExtendedKey;

  for (const desc of signers) {
    const parsed = parseSignerDescriptor(desc);
    if (parsed.xpub === inputXpub) {
      return {
        signerKey: inputKey,
        signerXfp: parsed.masterFingerprint.toLowerCase(),
      };
    }
  }

  const inputFingerprint = inputKey.fingerprint.toString(16).padStart(8, "0").toLowerCase();
  for (const desc of signers) {
    const parsed = parseSignerDescriptor(desc);
    if (parsed.masterFingerprint.toLowerCase() !== inputFingerprint) {
      continue;
    }

    const derivedSignerKey = inputKey.derive(`m${parsed.derivationPath}`);
    if (derivedSignerKey.publicExtendedKey === parsed.xpub) {
      return {
        signerKey: derivedSignerKey,
        signerXfp: parsed.masterFingerprint.toLowerCase(),
      };
    }
  }

  return null;
}

/**
 * Resolve signer keys from command options. Three modes:
 * 1. --xprv: match against wallet signers directly
 * 2. --fingerprint: load stored key, derive xprv, match
 * 3. Neither: auto-detect by trying all stored keys
 */
export function resolveSignerKeys(
  opts: { xprv?: string; fingerprint?: string },
  email: string,
  network: Network,
  walletSigners: string[],
): { matched: MatchedSignerKey[] } | { error: string } {
  if (opts.xprv && opts.fingerprint) {
    return { error: "Provide --xprv or --fingerprint, not both" };
  }

  // Mode 1: explicit xprv
  if (opts.xprv) {
    const match = matchSignerKey(opts.xprv, walletSigners, network);
    if (!match) {
      return { error: "Private key does not match any signer in this wallet" };
    }
    return { matched: [match] };
  }

  // Mode 2: explicit fingerprint
  if (opts.fingerprint) {
    const stored = loadKey(email, network, opts.fingerprint);
    if (!stored) {
      return { error: `Key ${opts.fingerprint} not found in local storage` };
    }
    const rootKey = mnemonicToRootKey(stored.mnemonic, network);
    const match = matchSignerKey(rootKey.privateExtendedKey!, walletSigners, network);
    if (!match) {
      return { error: `Stored key ${opts.fingerprint} does not match any signer in this wallet` };
    }
    match.keyName = stored.name;
    return { matched: [match] };
  }

  // Mode 3: auto-detect from all stored keys
  const storedKeys = listKeys(email, network);
  if (storedKeys.length === 0) {
    return { error: "No stored keys. Please provide --xprv" };
  }

  const matched: MatchedSignerKey[] = [];
  for (const stored of storedKeys) {
    const rootKey = mnemonicToRootKey(stored.mnemonic, network);
    const match = matchSignerKey(rootKey.privateExtendedKey!, walletSigners, network);
    if (match) {
      match.keyName = stored.name;
      matched.push(match);
    }
  }

  if (matched.length === 0) {
    return { error: "No stored key matches any signer in this wallet. Please provide --xprv" };
  }

  return { matched };
}
