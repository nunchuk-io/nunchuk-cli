// Key generation and derivation
// Reference: libnunchuk src/softwaresigner.cpp, src/utils/bip32.hpp

import {
  generateMnemonic as _generateMnemonic,
  validateMnemonic,
  mnemonicToSeedSync,
} from "./bip39.js";
import { HDKey } from "@scure/bip32";
import { MAINNET_VERSIONS, TESTNET_VERSIONS } from "./address.js";
import type { Network } from "./config.js";
import type { AddressType } from "./address-type.js";

function getVersions(network: Network) {
  return network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
}

// -- Mnemonic generation --

/** Generate a 24-word BIP39 mnemonic (256 bits entropy). */
export function generateMnemonic24(): string {
  return _generateMnemonic(256);
}

/** Generate a 12-word BIP39 mnemonic (128 bits entropy). */
export function generateMnemonic12(): string {
  return _generateMnemonic(128);
}

/** Validate a BIP39 mnemonic. */
export function checkMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic);
}

// -- Key derivation --

/** Derive BIP32 root key from mnemonic + optional passphrase.
 *  Network determines version bytes: mainnet → xprv/xpub, testnet → tprv/tpub.
 *  Reference: SoftwareSigner::GetBip32RootKey (softwaresigner.cpp:370-386) */
export function mnemonicToRootKey(mnemonic: string, network: Network, passphrase = ""): HDKey {
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  return HDKey.fromMasterSeed(seed, getVersions(network));
}

/** Get master fingerprint as 8-char lowercase hex.
 *  Reference: SoftwareSigner::GetMasterFingerprint (softwaresigner.cpp:183-190) */
export function getMasterFingerprint(rootKey: HDKey): string {
  // libnunchuk: derive child at index 0, read its parentFingerprint (which is the master's fingerprint)
  const child = rootKey.deriveChild(0);
  return (child.parentFingerprint >>> 0).toString(16).padStart(8, "0");
}

/** Get xpub at a derivation path.
 *  Reference: SoftwareSigner::GetXpubAtPath (softwaresigner.cpp:173-176) */
export function getXpubAtPath(rootKey: HDKey, path: string): string {
  const derived = rootKey.derive(path);
  const xpub = derived.publicExtendedKey;
  if (!xpub) throw new Error(`Failed to derive xpub at ${path}`);
  return xpub;
}

/** Get xprv at a derivation path. */
export function getXprvAtPath(rootKey: HDKey, path: string): string {
  const derived = rootKey.derive(path);
  const xprv = derived.privateExtendedKey;
  if (!xprv) throw new Error(`Failed to derive xprv at ${path}`);
  return xprv;
}

// -- BIP32 standard paths (multi-sig only) --
// CLI is for group wallets which are always multi-sig.
// Reference: GetBip32Path in src/utils/bip32.hpp:81-107

/** Get standard BIP32 multi-sig derivation path.
 *  Reference: GetBip32Path (bip32.hpp:81-107) */
export function getBip32Path(network: Network, addressType: AddressType, index = 0): string {
  const coinType = network === "mainnet" ? 0 : 1;

  switch (addressType) {
    case "LEGACY":
      return "m/45'";
    case "NESTED_SEGWIT":
      return `m/48'/${coinType}'/${index}'/1'`;
    case "NATIVE_SEGWIT":
      return `m/48'/${coinType}'/${index}'/2'`;
    case "TAPROOT":
      return `m/87'/${coinType}'/${index}'`;
  }
}

/** Signer info returned by getSignerInfo. */
export interface SignerInfo {
  fingerprint: string;
  path: string;
  xpub: string;
  xprv: string;
  descriptor: string; // "[xfp/path]xpub"
}

/** Get multi-sig signer info for a given address type.
 *  Returns fingerprint, path, xpub, xprv, and descriptor "[xfp/path']xpub".
 *  Reference: GetUnusedSignerFromMasterSigner (nunchukimpl.cpp:768-794) */
export function getSignerInfo(
  rootKey: HDKey,
  network: Network,
  addressType: AddressType,
  index = 0,
): SignerInfo {
  const fingerprint = getMasterFingerprint(rootKey);
  const path = getBip32Path(network, addressType, index);
  const xpub = getXpubAtPath(rootKey, path);
  const xprv = getXprvAtPath(rootKey, path);
  // Strip leading "m" for descriptor format
  const normalizedPath = path.slice(1);
  const descriptor = `[${fingerprint}${normalizedPath}]${xpub}`;
  return { fingerprint, path, xpub, xprv, descriptor };
}
