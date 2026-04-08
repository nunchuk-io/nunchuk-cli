import { describe, expect, it } from "vitest";
import { HDKey } from "@scure/bip32";
import { matchSignerKey } from "../signer-key.js";
import { TESTNET_VERSIONS } from "../address.js";

const ROOT_TPRV =
  "tprv8ZgxMBicQKsPcsrtKiH9QjEKETBYXnT7hc5Rqcr4jmRDSxguKdSXKSdkBkPRk43YtBML3U2xJEj4dMo1832UwM46AnyVRNwnVNJHxBknYRs";

const SIGNERS = [
  "[9db7aeb5/48'/1'/1'/2']tpubDDwwhnmFsR8B6exiKFNZ7UghngGL28PipLSzEgRHGmNjTrQ58tx6AUHueacfegb7cnup1uqLQbrkrwJYQUE2MgiRs2TBEpAhA9dfhmp8UBa",
  "[f6ea98cd/48'/1'/0'/2']tpubDEweaGRxsUjZF1Rvgw1e8k42yZKSLWdhmapWtWaAuoaBk958WEGYrmSj9Zm2XBUSnq2YFDMUNmu2Ud19DjEqoG7oqgbVkg6SNS3eTGccvhE",
  "[ecfed4c1/48'/1'/61'/2']tpubDEV85D8gGFPRBoxosoKjSy67rsVzrjDtTqFRejZpKNUu4s3hYF1Gmo5HdHbYtGimaMZcBZSKuohd5NMCheUMSusUhqoYbbmGyDwvPLn9EYX",
];

describe("matchSignerKey", () => {
  it("matches a root tprv by fingerprint and signer derivation path", () => {
    const matched = matchSignerKey(ROOT_TPRV, SIGNERS, "testnet");

    expect(matched).not.toBeNull();
    expect(matched!.signerXfp).toBe("f6ea98cd");
    expect(matched!.signerKey.publicExtendedKey).toBe(
      "tpubDEweaGRxsUjZF1Rvgw1e8k42yZKSLWdhmapWtWaAuoaBk958WEGYrmSj9Zm2XBUSnq2YFDMUNmu2Ud19DjEqoG7oqgbVkg6SNS3eTGccvhE",
    );
  });

  it("matches an already-derived signer tprv directly", () => {
    const root = HDKey.fromExtendedKey(ROOT_TPRV, TESTNET_VERSIONS);
    const signerTprv = root.derive("m/48'/1'/0'/2'").privateExtendedKey;
    const matched = matchSignerKey(signerTprv, SIGNERS, "testnet");

    expect(matched).not.toBeNull();
    expect(matched!.signerXfp).toBe("f6ea98cd");
    expect(matched!.signerKey.publicExtendedKey).toBe(
      "tpubDEweaGRxsUjZF1Rvgw1e8k42yZKSLWdhmapWtWaAuoaBk958WEGYrmSj9Zm2XBUSnq2YFDMUNmu2Ud19DjEqoG7oqgbVkg6SNS3eTGccvhE",
    );
  });

  it("returns null for an unrelated signer key", () => {
    const unrelated = HDKey.fromExtendedKey(ROOT_TPRV, TESTNET_VERSIONS).derive(
      "m/48'/1'/99'/2'",
    ).privateExtendedKey;

    expect(matchSignerKey(unrelated, SIGNERS, "testnet")).toBeNull();
  });
});
