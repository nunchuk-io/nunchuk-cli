import { describe, it, expect } from "vitest";
import {
  parseDescriptor,
  parseBsmsRecord,
  buildAnyDescriptor,
  buildExternalDescriptor,
  buildWalletDescriptor,
  buildAnyDescriptorForParsed,
  buildExternalDescriptorForParsed,
  buildWalletDescriptorForParsed,
  getWalletId,
  getWalletIdForParsed,
  descriptorChecksum,
  parseSignerDescriptor,
} from "../descriptor.js";

// Test signers in [xfp/path]xpub format (using ' notation, matching libnunchuk)
const TEST_SIGNERS = [
  "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
];

// Pre-computed descriptors from build functions for roundtrip tests
const EXTERNAL_DESC = buildExternalDescriptor(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
const ANY_DESC = buildAnyDescriptor(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
const WALLET_DESC = buildWalletDescriptor(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
const WALLET_ID = getWalletId(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
const MINISCRIPT_EXTERNAL_BODY = `wsh(and_v(v:pk(${TEST_SIGNERS[0]}/0/*),pk(${TEST_SIGNERS[1]}/0/*)))`;
const MINISCRIPT_EXTERNAL_DESC = `${MINISCRIPT_EXTERNAL_BODY}#${descriptorChecksum(MINISCRIPT_EXTERNAL_BODY)}`;
const MINISCRIPT_ANY_BODY = `wsh(and_v(v:pk(${TEST_SIGNERS[0]}/*),pk(${TEST_SIGNERS[1]}/*)))`;
const MINISCRIPT_ANY_DESC = `${MINISCRIPT_ANY_BODY}#${descriptorChecksum(MINISCRIPT_ANY_BODY)}`;
const MINISCRIPT_WALLET_BODY = `wsh(and_v(v:pk(${TEST_SIGNERS[0]}/<0;1>/*),pk(${TEST_SIGNERS[1]}/<0;1>/*)))`;
const MINISCRIPT_WALLET_DESC = `${MINISCRIPT_WALLET_BODY}#${descriptorChecksum(MINISCRIPT_WALLET_BODY)}`;

describe("parseDescriptor", () => {
  it("parses NATIVE_SEGWIT (wsh) descriptor with /0/* child path", () => {
    const result = parseDescriptor(EXTERNAL_DESC);
    expect(result.m).toBe(2);
    expect(result.n).toBe(2);
    expect(result.addressType).toBe("NATIVE_SEGWIT");
    expect(result.signers).toEqual(TEST_SIGNERS);
  });

  it("parses descriptor with /* child path (ANY)", () => {
    const result = parseDescriptor(ANY_DESC);
    expect(result.m).toBe(2);
    expect(result.n).toBe(2);
    expect(result.addressType).toBe("NATIVE_SEGWIT");
    expect(result.signers).toEqual(TEST_SIGNERS);
  });

  it("parses descriptor with /<0;1>/* child path (BIP-389)", () => {
    const result = parseDescriptor(WALLET_DESC);
    expect(result.m).toBe(2);
    expect(result.n).toBe(2);
    expect(result.addressType).toBe("NATIVE_SEGWIT");
    expect(result.signers).toEqual(TEST_SIGNERS);
  });

  it("parses NESTED_SEGWIT (sh(wsh)) descriptor", () => {
    const desc = buildExternalDescriptor(TEST_SIGNERS, 2, "NESTED_SEGWIT");
    const result = parseDescriptor(desc);
    expect(result.addressType).toBe("NESTED_SEGWIT");
    expect(result.m).toBe(2);
    expect(result.signers).toEqual(TEST_SIGNERS);
  });

  it("parses LEGACY (sh) descriptor", () => {
    const desc = buildExternalDescriptor(TEST_SIGNERS, 2, "LEGACY");
    const result = parseDescriptor(desc);
    expect(result.addressType).toBe("LEGACY");
    expect(result.m).toBe(2);
    expect(result.signers).toEqual(TEST_SIGNERS);
  });

  it("normalizes h to ' in derivation paths", () => {
    // Build a descriptor using h notation
    const body =
      "wsh(sortedmulti(2," +
      "[534a4a82/48h/1h/0h/2h]tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ/*," +
      "[4bda0966/48h/1h/0h/2h]tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s/*))";
    const checksum = descriptorChecksum(body);
    const desc = `${body}#${checksum}`;

    const result = parseDescriptor(desc);
    // Paths should be normalized to ' notation
    for (const signer of result.signers) {
      const parsed = parseSignerDescriptor(signer);
      expect(parsed.derivationPath).toContain("'");
      expect(parsed.derivationPath).not.toContain("h");
    }
    // Signers should match the canonical form
    expect(result.signers).toEqual(TEST_SIGNERS);
  });

  it("rejects descriptor with invalid checksum", () => {
    const desc = EXTERNAL_DESC.slice(0, -4) + "xxxx";
    expect(() => parseDescriptor(desc)).toThrow("checksum mismatch");
  });

  it("rejects descriptor without checksum", () => {
    const body = EXTERNAL_DESC.split("#")[0];
    expect(() => parseDescriptor(body)).toThrow("missing checksum");
  });

  it("rejects unsupported wrapper (single-sig)", () => {
    const body = "wpkh([534a4a82/84'/1'/0']tpubXXX/0/*)";
    const checksum = descriptorChecksum(body);
    expect(() => parseDescriptor(`${body}#${checksum}`)).toThrow("unsupported wrapper");
  });

  it("roundtrip: walletId matches after parse", () => {
    const result = parseDescriptor(EXTERNAL_DESC);
    const recomputedId = getWalletId(result.signers, result.m, result.addressType);
    expect(recomputedId).toBe(WALLET_ID);
  });

  it("roundtrip: rebuild descriptor matches after parse", () => {
    const result = parseDescriptor(ANY_DESC);
    const rebuilt = buildAnyDescriptor(result.signers, result.m, result.addressType);
    expect(rebuilt).toBe(ANY_DESC);
  });

  it("handles descriptor without child path on keys", () => {
    // Some tools produce descriptors without trailing child path
    const body =
      "wsh(sortedmulti(2," +
      "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ," +
      "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s))";
    const checksum = descriptorChecksum(body);
    const result = parseDescriptor(`${body}#${checksum}`);
    expect(result.signers).toEqual(TEST_SIGNERS);
  });

  it("parses signer descriptor without derivation path", () => {
    const signer = parseSignerDescriptor(
      "[534a4a82]tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
    );

    expect(signer.masterFingerprint).toBe("534a4a82");
    expect(signer.derivationPath).toBe("");
  });

  it("parses miniscript descriptor and normalizes it to wallet form", () => {
    const result = parseDescriptor(MINISCRIPT_EXTERNAL_DESC);
    expect(result.kind).toBe("miniscript");
    expect(result.addressType).toBe("NATIVE_SEGWIT");
    expect(result.m).toBe(0);
    expect(result.n).toBe(2);
    expect(result.signers).toEqual(TEST_SIGNERS);
    expect(result.miniscript).toBe(
      `and_v(v:pk(${TEST_SIGNERS[0]}/<0;1>/*),pk(${TEST_SIGNERS[1]}/<0;1>/*))`,
    );
    expect(result.descriptor).toBe(MINISCRIPT_WALLET_DESC);
  });

  it("rebuilds miniscript descriptors for wallet, external, and any paths", () => {
    const result = parseDescriptor(MINISCRIPT_EXTERNAL_DESC);
    expect(buildWalletDescriptorForParsed(result)).toBe(MINISCRIPT_WALLET_DESC);
    expect(buildExternalDescriptorForParsed(result)).toBe(MINISCRIPT_EXTERNAL_DESC);
    expect(buildAnyDescriptorForParsed(result)).toBe(MINISCRIPT_ANY_DESC);
    expect(getWalletIdForParsed(result)).toBe(descriptorChecksum(MINISCRIPT_EXTERNAL_BODY));
  });
});

describe("parseBsmsRecord", () => {
  async function buildBsmsContent(network: "mainnet" | "testnet"): Promise<string> {
    const { deriveFirstAddress } = await import("../address.js");
    const desc = buildAnyDescriptor(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
    const firstAddr = deriveFirstAddress(TEST_SIGNERS, 2, "NATIVE_SEGWIT", network);
    return `BSMS 1.0\n${desc}\nNo path restrictions\n${firstAddr}`;
  }

  it("parses valid BSMS record (testnet)", async () => {
    const content = await buildBsmsContent("testnet");
    const result = await parseBsmsRecord(content, "testnet");
    expect(result.m).toBe(2);
    expect(result.n).toBe(2);
    expect(result.addressType).toBe("NATIVE_SEGWIT");
    expect(result.signers).toEqual(TEST_SIGNERS);
  });

  it("parses BSMS with /0/*,/1/* path restriction", async () => {
    const { deriveFirstAddress } = await import("../address.js");
    const desc = buildAnyDescriptor(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
    const firstAddr = deriveFirstAddress(TEST_SIGNERS, 2, "NATIVE_SEGWIT", "testnet");
    const content = `BSMS 1.0\n${desc}\n/0/*,/1/*\n${firstAddr}`;
    const result = await parseBsmsRecord(content, "testnet");
    expect(result.m).toBe(2);
  });

  it("rejects invalid version", async () => {
    const content = "BSMS 2.0\nwsh(sortedmulti(2,...))#xxx\nNo path restrictions\nbc1q...";
    await expect(parseBsmsRecord(content, "testnet")).rejects.toThrow("unsupported version");
  });

  it("rejects invalid path restriction", async () => {
    const desc = buildAnyDescriptor(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
    const content = `BSMS 1.0\n${desc}\ninvalid restriction\ntb1q...`;
    await expect(parseBsmsRecord(content, "testnet")).rejects.toThrow("invalid path restriction");
  });

  it("rejects address mismatch", async () => {
    const desc = buildAnyDescriptor(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
    const content = `BSMS 1.0\n${desc}\nNo path restrictions\ntb1qwrongaddress`;
    await expect(parseBsmsRecord(content, "testnet")).rejects.toThrow(
      "first address does not match",
    );
  });

  it("rejects record with too few lines", async () => {
    const content = "BSMS 1.0\nwsh(sortedmulti(2,...))#xxx";
    await expect(parseBsmsRecord(content, "testnet")).rejects.toThrow("at least 4 lines");
  });

  it("parses miniscript descriptors in BSMS records", async () => {
    const { deriveDescriptorFirstAddress } = await import("../address.js");
    const firstAddr = deriveDescriptorFirstAddress(MINISCRIPT_ANY_DESC, "testnet");
    const content = `BSMS 1.0\n${MINISCRIPT_ANY_DESC}\nNo path restrictions\n${firstAddr}`;
    const result = await parseBsmsRecord(content, "testnet");
    expect(result.kind).toBe("miniscript");
    expect(result.signers).toEqual(TEST_SIGNERS);
    expect(result.descriptor).toBe(MINISCRIPT_WALLET_DESC);
  });
});

describe("walletId and key derivation consistency", () => {
  it("walletId is deterministic for same signers/m/addressType", () => {
    const id1 = getWalletId(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
    const id2 = getWalletId(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
    expect(id1).toBe(id2);
    expect(id1.length).toBe(8); // descriptor checksum is always 8 chars
  });

  it("walletId differs for different m", () => {
    const id1 = getWalletId(TEST_SIGNERS, 1, "NATIVE_SEGWIT");
    const id2 = getWalletId(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
    expect(id1).not.toBe(id2);
  });

  it("walletId matches after roundtrip parse", () => {
    const desc = buildExternalDescriptor(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
    const parsed = parseDescriptor(desc);
    const id = getWalletId(parsed.signers, parsed.m, parsed.addressType);
    expect(id).toBe(WALLET_ID);
  });

  it("parsed signers produce same ANY descriptor for PBKDF2", () => {
    const desc = buildExternalDescriptor(TEST_SIGNERS, 2, "NATIVE_SEGWIT");
    const parsed = parseDescriptor(desc);
    const anyDesc = buildAnyDescriptor(parsed.signers, parsed.m, parsed.addressType);
    expect(anyDesc).toBe(ANY_DESC);
  });
});
