import { describe, expect, it } from "vitest";
import { HDKey } from "@scure/bip32";
import { Transaction, TEST_NETWORK } from "@scure/btc-signer";
import { TESTNET_VERSIONS, deriveDescriptorPayment } from "../address.js";
import { descriptorChecksum } from "../descriptor.js";
import { signWalletPsbtWithKey } from "../psbt-sign.js";

const ROOT_TPRV =
  "tprv8ZgxMBicQKsPcsrtKiH9QjEKETBYXnT7hc5Rqcr4jmRDSxguKdSXKSdkBkPRk43YtBML3U2xJEj4dMo1832UwM46AnyVRNwnVNJHxBknYRs";
const SIGNER_DERIVATION_PATH = "m/48'/1'/0'/2'";
const rootKey = HDKey.fromExtendedKey(ROOT_TPRV, TESTNET_VERSIONS);
const signerKey = rootKey.derive(SIGNER_DERIVATION_PATH);
const masterFingerprint = rootKey.fingerprint.toString(16).padStart(8, "0");
const signerDescriptor = `[${masterFingerprint}/48'/1'/0'/2']${signerKey.publicExtendedKey}`;

function buildDescriptor(miniscript: string): string {
  const body = `wsh(${miniscript})`;
  return `${body}#${descriptorChecksum(body)}`;
}

function createSigningPsbt(descriptor: string, chain: 0 | 1, index: number): Transaction {
  const payment = deriveDescriptorPayment(descriptor, "testnet", chain, index);
  const tx = new Transaction();
  tx.addInput({
    txid: "00".repeat(32),
    index: 0,
    sequence: 0xfffffffd,
    witnessUtxo: {
      amount: 50_000n,
      script: payment.script,
    },
    bip32Derivation: payment.bip32Derivation,
    witnessScript: payment.witnessScript,
  });
  tx.addOutputAddress(payment.address, 49_000n, TEST_NETWORK);
  return tx;
}

describe("signWalletPsbtWithKey", () => {
  it("signs inputs whose descriptor key is the signer xpub node itself", () => {
    const descriptor = buildDescriptor(`pk(${signerDescriptor})`);
    const tx = createSigningPsbt(descriptor, 0, 0);

    const signed = signWalletPsbtWithKey(
      tx,
      signerKey,
      parseInt(masterFingerprint, 16),
      descriptor,
    );

    expect(signed).toBe(1);
    expect((tx.getInput(0).partialSig ?? []).length).toBe(1);
  });

  it("signs inputs whose descriptor uses a single wildcard suffix", () => {
    const descriptor = buildDescriptor(`pk(${signerDescriptor}/*)`);
    const tx = createSigningPsbt(descriptor, 0, 7);

    const signed = signWalletPsbtWithKey(
      tx,
      signerKey,
      parseInt(masterFingerprint, 16),
      descriptor,
    );

    expect(signed).toBe(1);
    expect((tx.getInput(0).partialSig ?? []).length).toBe(1);
  });

  it("still signs inputs whose descriptor uses multipath receive/change suffixes", () => {
    const descriptor = buildDescriptor(`pk(${signerDescriptor}/<0;1>/*)`);
    const tx = createSigningPsbt(descriptor, 1, 3);

    const signed = signWalletPsbtWithKey(
      tx,
      signerKey,
      parseInt(masterFingerprint, 16),
      descriptor,
    );

    expect(signed).toBe(1);
    expect((tx.getInput(0).partialSig ?? []).length).toBe(1);
  });
});
