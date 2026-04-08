import { describe, it, expect } from "vitest";
import { HDKey } from "@scure/bip32";
import {
  generateMnemonic24,
  generateMnemonic12,
  checkMnemonic,
  mnemonicToRootKey,
  getMasterFingerprint,
  getXpubAtPath,
  getXprvAtPath,
  getBip32Path,
  getSignerInfo,
} from "../keygen.js";
import { MAINNET_VERSIONS, TESTNET_VERSIONS } from "../address.js";

// BIP39 test vector from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
// Vector #0: entropy 00000000000000000000000000000000
const TEST_MNEMONIC_12 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Vector #12 (24 words): entropy 00000000000000000000000000000000000000000000000000000000000000000
const TEST_MNEMONIC_24 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

// Known fingerprint for TEST_MNEMONIC_12 (no passphrase)
const TEST_FINGERPRINT_12 = "73c5da0a";

// ─── generateMnemonic ──────────────────────────────────────────────

describe("generateMnemonic24", () => {
  it("generates a valid 24-word mnemonic", () => {
    const mnemonic = generateMnemonic24();
    const words = mnemonic.split(" ");
    expect(words).toHaveLength(24);
    expect(checkMnemonic(mnemonic)).toBe(true);
  });

  it("generates different mnemonics each time", () => {
    const a = generateMnemonic24();
    const b = generateMnemonic24();
    expect(a).not.toBe(b);
  });
});

describe("generateMnemonic12", () => {
  it("generates a valid 12-word mnemonic", () => {
    const mnemonic = generateMnemonic12();
    const words = mnemonic.split(" ");
    expect(words).toHaveLength(12);
    expect(checkMnemonic(mnemonic)).toBe(true);
  });
});

// ─── checkMnemonic ─────────────────────────────────────────────────

describe("checkMnemonic", () => {
  it("accepts valid mnemonics", () => {
    expect(checkMnemonic(TEST_MNEMONIC_12)).toBe(true);
    expect(checkMnemonic(TEST_MNEMONIC_24)).toBe(true);
  });

  it("rejects invalid mnemonics", () => {
    expect(checkMnemonic("abandon abandon abandon")).toBe(false);
    expect(checkMnemonic("not a valid mnemonic at all")).toBe(false);
    expect(checkMnemonic("")).toBe(false);
  });
});

// ─── mnemonicToRootKey ─────────────────────────────────────────────

describe("mnemonicToRootKey", () => {
  it("derives a root key with valid private key", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    expect(rootKey.privateKey).toBeDefined();
    expect(rootKey.publicKey).toBeDefined();
  });

  it("derives different keys with different passphrases", () => {
    const a = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    const b = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet", "my passphrase");
    expect(Buffer.from(a.privateKey!).toString("hex")).not.toBe(
      Buffer.from(b.privateKey!).toString("hex"),
    );
  });

  it("produces xprv prefix for mainnet and tprv for testnet", () => {
    const mainnet = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    const testnet = mnemonicToRootKey(TEST_MNEMONIC_12, "testnet");
    expect(mainnet.privateExtendedKey).toMatch(/^xprv/);
    expect(testnet.privateExtendedKey).toMatch(/^tprv/);
  });
});

// ─── getMasterFingerprint ──────────────────────────────────────────

describe("getMasterFingerprint", () => {
  it("returns known fingerprint for test mnemonic", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    expect(getMasterFingerprint(rootKey)).toBe(TEST_FINGERPRINT_12);
  });

  it("returns 8-char lowercase hex", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_24, "mainnet");
    const fp = getMasterFingerprint(rootKey);
    expect(fp).toMatch(/^[0-9a-f]{8}$/);
  });

  it("returns different fingerprint with passphrase", () => {
    const a = getMasterFingerprint(mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet"));
    const b = getMasterFingerprint(mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet", "test"));
    expect(a).not.toBe(b);
  });

  it("returns same fingerprint regardless of network", () => {
    const mainnet = getMasterFingerprint(mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet"));
    const testnet = getMasterFingerprint(mnemonicToRootKey(TEST_MNEMONIC_12, "testnet"));
    expect(mainnet).toBe(testnet);
  });
});

// ─── getXpubAtPath ─────────────────────────────────────────────────

describe("getXpubAtPath", () => {
  it("derives xpub for mainnet root key", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    const xpub = getXpubAtPath(rootKey, "m/48'/0'/0'/2'");
    expect(xpub).toMatch(/^xpub/);
  });

  it("derives tpub for testnet root key", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "testnet");
    const xpub = getXpubAtPath(rootKey, "m/48'/1'/0'/2'");
    expect(xpub).toMatch(/^tpub/);
  });

  it("returns same xpub for same path", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    const a = getXpubAtPath(rootKey, "m/84'/0'/0'");
    const b = getXpubAtPath(rootKey, "m/84'/0'/0'");
    expect(a).toBe(b);
  });

  it("returns different xpub for different paths", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    const a = getXpubAtPath(rootKey, "m/84'/0'/0'");
    const b = getXpubAtPath(rootKey, "m/84'/0'/1'");
    expect(a).not.toBe(b);
  });
});

// ─── getXprvAtPath ─────────────────────────────────────────────────

describe("getXprvAtPath", () => {
  it("derives xprv and round-trips to same xpub", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "testnet");
    const path = "m/84'/1'/0'";
    const xprv = getXprvAtPath(rootKey, path);
    const xpub = getXpubAtPath(rootKey, path);

    // Reconstruct from xprv and verify xpub matches
    const restored = HDKey.fromExtendedKey(xprv, TESTNET_VERSIONS);
    expect(restored.publicExtendedKey).toBe(xpub);
  });

  it("produces tprv for testnet and xprv for mainnet", () => {
    const testRoot = mnemonicToRootKey(TEST_MNEMONIC_12, "testnet");
    const mainRoot = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    expect(getXprvAtPath(testRoot, "m/84'/1'/0'")).toMatch(/^tprv/);
    expect(getXprvAtPath(mainRoot, "m/84'/0'/0'")).toMatch(/^xprv/);
  });
});

// ─── getBip32Path (multi-sig only) ─────────────────────────────────

describe("getBip32Path", () => {
  it("returns correct multi-sig native segwit path (BIP48)", () => {
    expect(getBip32Path("mainnet", "NATIVE_SEGWIT", 0)).toBe("m/48'/0'/0'/2'");
    expect(getBip32Path("testnet", "NATIVE_SEGWIT", 0)).toBe("m/48'/1'/0'/2'");
    expect(getBip32Path("mainnet", "NATIVE_SEGWIT", 1)).toBe("m/48'/0'/1'/2'");
  });

  it("returns correct multi-sig nested segwit path (BIP48)", () => {
    expect(getBip32Path("mainnet", "NESTED_SEGWIT", 0)).toBe("m/48'/0'/0'/1'");
  });

  it("returns correct multi-sig legacy path (BIP45)", () => {
    expect(getBip32Path("mainnet", "LEGACY", 0)).toBe("m/45'");
    expect(getBip32Path("testnet", "LEGACY", 0)).toBe("m/45'");
  });

  it("returns correct multi-sig taproot path (BIP87)", () => {
    expect(getBip32Path("mainnet", "TAPROOT", 0)).toBe("m/87'/0'/0'");
  });
});

// ─── getSignerInfo ─────────────────────────────────────────────────

describe("getSignerInfo", () => {
  it("returns correct descriptor format for testnet multi-sig native segwit", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "testnet");
    const info = getSignerInfo(rootKey, "testnet", "NATIVE_SEGWIT");
    expect(info.fingerprint).toBe(TEST_FINGERPRINT_12);
    expect(info.path).toBe("m/48'/1'/0'/2'");
    expect(info.xpub).toMatch(/^tpub/);
    expect(info.xprv).toMatch(/^tprv/);
    expect(info.descriptor).toBe(`[${TEST_FINGERPRINT_12}/48'/1'/0'/2']${info.xpub}`);
  });

  it("returns xpub/xprv prefixes for mainnet", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    const info = getSignerInfo(rootKey, "mainnet", "NATIVE_SEGWIT");
    expect(info.xpub).toMatch(/^xpub/);
    expect(info.xprv).toMatch(/^xprv/);
  });

  it("includes xprv that round-trips to same xpub", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "testnet");
    const info = getSignerInfo(rootKey, "testnet", "NATIVE_SEGWIT");
    const restored = HDKey.fromExtendedKey(info.xprv, TESTNET_VERSIONS);
    expect(restored.publicExtendedKey).toBe(info.xpub);
  });

  it("uses correct coin type for mainnet vs testnet", () => {
    const mainRoot = mnemonicToRootKey(TEST_MNEMONIC_12, "mainnet");
    const testRoot = mnemonicToRootKey(TEST_MNEMONIC_12, "testnet");
    const mainnet = getSignerInfo(mainRoot, "mainnet", "NATIVE_SEGWIT");
    const testnet = getSignerInfo(testRoot, "testnet", "NATIVE_SEGWIT");
    expect(mainnet.path).toBe("m/48'/0'/0'/2'");
    expect(testnet.path).toBe("m/48'/1'/0'/2'");
    expect(mainnet.xpub).not.toBe(testnet.xpub);
  });

  it("uses account index", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "testnet");
    const idx0 = getSignerInfo(rootKey, "testnet", "NATIVE_SEGWIT", 0);
    const idx1 = getSignerInfo(rootKey, "testnet", "NATIVE_SEGWIT", 1);
    expect(idx0.path).toBe("m/48'/1'/0'/2'");
    expect(idx1.path).toBe("m/48'/1'/1'/2'");
    expect(idx0.xpub).not.toBe(idx1.xpub);
  });

  it("descriptor is compatible with sandbox addkey", () => {
    const rootKey = mnemonicToRootKey(TEST_MNEMONIC_12, "testnet");
    const info = getSignerInfo(rootKey, "testnet", "NATIVE_SEGWIT");
    // Descriptor must match format: [xfp/path]xpub
    const match = info.descriptor.match(/^\[([0-9a-f]{8})(\/[^\]]+)\](.+)$/);
    expect(match).not.toBeNull();
    expect(match![1]).toBe(TEST_FINGERPRINT_12);
    expect(match![3]).toBe(info.xpub);
  });
});

// ─── Cross-verification: xprv → HDKey → same fingerprint ──────────

describe("cross-verification", () => {
  it("xprv round-trip produces same fingerprint and xpubs", () => {
    const mnemonic = generateMnemonic24();
    const rootKey = mnemonicToRootKey(mnemonic, "testnet");
    const fp1 = getMasterFingerprint(rootKey);

    // Derive master xprv, reconstruct, and verify
    const xprv = rootKey.privateExtendedKey;
    const restored = HDKey.fromExtendedKey(xprv!, TESTNET_VERSIONS);
    const fp2 = getMasterFingerprint(restored);

    expect(fp1).toBe(fp2);

    // Same xpub at a derived path
    const path = "m/48'/1'/0'/2'";
    expect(getXpubAtPath(rootKey, path)).toBe(getXpubAtPath(restored, path));
  });
});
