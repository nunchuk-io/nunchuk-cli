import { afterAll, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { HDKey } from "@scure/bip32";
import { Transaction, TEST_NETWORK } from "@scure/btc-signer";
import { SignatureHash } from "@scure/btc-signer/transaction.js";
import { TESTNET_VERSIONS, deriveDescriptorPayment } from "../address.js";
import { buildWalletDescriptor, descriptorChecksum, getUnspendableXpub } from "../descriptor.js";
import { hasWalletSignerSignedPsbt, signWalletPsbtWithKey } from "../psbt-sign.js";
import { _clearMasterKeyCache, _closeDatabase } from "../storage.js";

const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a;
const PSBT_IN_MUSIG2_PUB_NONCE = 0x1b;
const PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c;
const ROOT_TPRV =
  "tprv8ZgxMBicQKsPcsrtKiH9QjEKETBYXnT7hc5Rqcr4jmRDSxguKdSXKSdkBkPRk43YtBML3U2xJEj4dMo1832UwM46AnyVRNwnVNJHxBknYRs";
const SIGNER_DERIVATION_PATH = "m/48'/1'/0'/2'";
const rootKey = HDKey.fromExtendedKey(ROOT_TPRV, TESTNET_VERSIONS);
const signerKey = rootKey.derive(SIGNER_DERIVATION_PATH);
const masterFingerprint = rootKey.fingerprint.toString(16).padStart(8, "0");
const signerDescriptor = `[${masterFingerprint}/48'/1'/0'/2']${signerKey.publicExtendedKey}`;
const TEST_HOME = path.join(
  os.tmpdir(),
  "nunchuk-cli-psbt-sign-tests",
  crypto.randomBytes(4).toString("hex"),
);
process.env.NUNCHUK_CLI_HOME = TEST_HOME;

beforeEach(() => {
  _closeDatabase();
  _clearMasterKeyCache();
});

afterAll(() => {
  _closeDatabase();
  fs.rmSync(TEST_HOME, { recursive: true, force: true });
  delete process.env.NUNCHUK_CLI_HOME;
});

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

function makeTaprootSigner(seedByte: number): {
  accountKey: HDKey;
  descriptor: string;
  fingerprint: number;
} {
  const root = HDKey.fromMasterSeed(new Uint8Array(32).fill(seedByte), TESTNET_VERSIONS);
  const accountKey = root.derive("m/87'/1'/0'");
  const fingerprint = root.fingerprint;
  return {
    accountKey,
    descriptor: `[${fingerprint.toString(16).padStart(8, "0")}/87'/1'/0']${
      accountKey.publicExtendedKey
    }`,
    fingerprint,
  };
}

function createTaprootSigningPsbt(
  descriptor: string,
  options: { taprootKeyPath?: boolean } = {},
): Transaction {
  const payment = deriveDescriptorPayment(descriptor, "testnet", 0, 0);
  const tx = new Transaction();
  tx.addInput({
    txid: "11".repeat(32),
    index: 0,
    sequence: 0xfffffffd,
    witnessUtxo: {
      amount: 50_000n,
      script: payment.script,
    },
    tapInternalKey: payment.tapInternalKey,
    tapMerkleRoot: payment.tapMerkleRoot,
    tapLeafScript: options.taprootKeyPath ? undefined : payment.tapLeafScript,
    tapBip32Derivation: payment.tapBip32Derivation,
  });
  tx.addOutputAddress(payment.address, 49_000n, TEST_NETWORK);
  return tx;
}

function roundtripPsbt(tx: Transaction): Transaction {
  return Transaction.fromPSBT(tx.toPSBT(), { allowUnknown: true });
}

function musigContext(signerIndex: number) {
  return {
    email: `musig-signer-${signerIndex}@test.local`,
    network: "testnet" as const,
    walletId: "taproot-musig-wallet",
    txId: "taproot-musig-tx",
  };
}

function expectCoreMusig2Fields(tx: Transaction, keyPath: boolean): void {
  const input = tx.getInput(0);
  const unknown = (input.unknown as Array<[{ type: number; key: Uint8Array }, Uint8Array]>) ?? [];
  const participantFields = unknown.filter(
    ([key]) => key.type === PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
  );
  const nonceFields = unknown.filter(([key]) => key.type === PSBT_IN_MUSIG2_PUB_NONCE);
  const partialSigFields = unknown.filter(([key]) => key.type === PSBT_IN_MUSIG2_PARTIAL_SIG);
  const signerKeyLength = keyPath ? 66 : 98;

  expect((input.proprietary ?? []).length).toBe(0);
  expect(participantFields).toHaveLength(1);
  expect(participantFields[0][0].key).toHaveLength(33);
  expect(participantFields[0][1]).toHaveLength(66);
  expect(nonceFields).toHaveLength(2);
  expect(
    nonceFields.every(([key, value]) => key.key.length === signerKeyLength && value.length === 66),
  ).toBe(true);
  expect(partialSigFields).toHaveLength(2);
  expect(
    partialSigFields.every(
      ([key, value]) => key.key.length === signerKeyLength && value.length === 32,
    ),
  ).toBe(true);
  if (keyPath) {
    const outputKey = input.witnessUtxo?.script.subarray(2);
    expect(outputKey).toHaveLength(32);
    expect(nonceFields.every(([key]) => Buffer.from(key.key.subarray(34)).equals(outputKey!))).toBe(
      true,
    );
    expect(
      partialSigFields.every(([key]) => Buffer.from(key.key.subarray(34)).equals(outputKey!)),
    ).toBe(true);
  }
}

function expectTaprootMusigSigningFlow(
  descriptor: string,
  signers: ReturnType<typeof makeTaprootSigner>[],
): void {
  let tx = createTaprootSigningPsbt(descriptor);

  expect(
    signWalletPsbtWithKey(
      tx,
      signers[0].accountKey,
      signers[0].fingerprint,
      descriptor,
      musigContext(0),
    ),
  ).toBe(1);
  tx = roundtripPsbt(tx);
  expect(
    signWalletPsbtWithKey(
      tx,
      signers[1].accountKey,
      signers[1].fingerprint,
      descriptor,
      musigContext(1),
    ),
  ).toBe(1);
  tx = roundtripPsbt(tx);
  expect(
    signWalletPsbtWithKey(
      tx,
      signers[0].accountKey,
      signers[0].fingerprint,
      descriptor,
      musigContext(0),
    ),
  ).toBe(1);
  tx = roundtripPsbt(tx);
  expect(
    signWalletPsbtWithKey(
      tx,
      signers[1].accountKey,
      signers[1].fingerprint,
      descriptor,
      musigContext(1),
    ),
  ).toBe(1);

  expectCoreMusig2Fields(tx, false);
  expect((tx.getInput(0).tapScriptSig ?? []).length).toBe(1);
  tx.finalize();
  expect(tx.isFinal).toBe(true);
}

function expectTaprootKeypathMusigSigningFlow(
  descriptor: string,
  signers: ReturnType<typeof makeTaprootSigner>[],
): void {
  let tx = createTaprootSigningPsbt(descriptor, { taprootKeyPath: true });

  expect(
    signWalletPsbtWithKey(
      tx,
      signers[0].accountKey,
      signers[0].fingerprint,
      descriptor,
      musigContext(0),
    ),
  ).toBe(1);
  tx = roundtripPsbt(tx);
  expect(
    signWalletPsbtWithKey(
      tx,
      signers[1].accountKey,
      signers[1].fingerprint,
      descriptor,
      musigContext(1),
    ),
  ).toBe(1);
  tx = roundtripPsbt(tx);
  expect(
    signWalletPsbtWithKey(
      tx,
      signers[0].accountKey,
      signers[0].fingerprint,
      descriptor,
      musigContext(0),
    ),
  ).toBe(1);
  tx = roundtripPsbt(tx);
  expect(
    signWalletPsbtWithKey(
      tx,
      signers[1].accountKey,
      signers[1].fingerprint,
      descriptor,
      musigContext(1),
    ),
  ).toBe(1);

  expectCoreMusig2Fields(tx, true);
  expect(tx.getInput(0).tapKeySig).toHaveLength(64);
  tx.finalize();
  expect(tx.isFinal).toBe(true);
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

  it("signs taproot sortedmulti_a script-path inputs", () => {
    const signers = Array.from({ length: 6 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
    );
    const tx = createTaprootSigningPsbt(descriptor);

    const signed0 = signWalletPsbtWithKey(
      tx,
      signers[0].accountKey,
      signers[0].fingerprint,
      descriptor,
    );
    const signed1 = signWalletPsbtWithKey(
      tx,
      signers[1].accountKey,
      signers[1].fingerprint,
      descriptor,
    );

    expect(signed0).toBe(1);
    expect(signed1).toBe(1);
    expect((tx.getInput(0).tapScriptSig ?? []).length).toBe(2);
    tx.finalize();
    expect(tx.isFinal).toBe(true);
  });

  it("rejects taproot musig-leaf signing without nonce storage context", () => {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
    );
    const tx = createTaprootSigningPsbt(descriptor);

    expect(() =>
      signWalletPsbtWithKey(tx, signers[0].accountKey, signers[0].fingerprint, descriptor),
    ).toThrow("Taproot MuSig signing requires local MuSig2 nonce storage context");
  });

  it("signs taproot multisig MuSig2 script-path inputs after nonce exchange", () => {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
    );

    expectTaprootMusigSigningFlow(descriptor, signers);
  });

  it("signs taproot multisig MuSig2 key-path inputs after nonce exchange", () => {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
      "DEFAULT",
    );

    expectTaprootKeypathMusigSigningFlow(descriptor, signers);
  });

  it("destroys a MuSig2 secret nonce as soon as it signs, preventing reuse", () => {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
      "DEFAULT",
    );
    let tx = createTaprootSigningPsbt(descriptor, { taprootKeyPath: true });

    // Round 1: both signers publish MuSig2 public nonces (secret nonces saved locally).
    expect(
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toBe(1);
    tx = roundtripPsbt(tx);
    expect(
      signWalletPsbtWithKey(
        tx,
        signers[1].accountKey,
        signers[1].fingerprint,
        descriptor,
        musigContext(1),
      ),
    ).toBe(1);
    tx = roundtripPsbt(tx);

    // This is exactly the state a malicious coordinator would replay after a failed
    // upload: signer 0's public nonce is present, but no partial signature yet.
    const replayed = roundtripPsbt(tx);
    const signed = roundtripPsbt(tx);

    // Signer 0 produces its partial signature — the secret nonce is destroyed in the
    // same step, before the signed PSBT can leave the process.
    expect(
      signWalletPsbtWithKey(
        signed,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toBe(1);

    // Replaying the pre-signature PSBT must NOT re-sign with the same secret nonce:
    // the record is gone, so signing fails loudly instead of reusing the nonce.
    expect(() =>
      signWalletPsbtWithKey(
        replayed,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toThrow(/Missing local MuSig2 secret nonce/);
  });

  it("starts MuSig2 signing for all DEFAULT taproot paths present in the PSBT", () => {
    const signers = Array.from({ length: 3 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
      "DEFAULT",
    );

    const tx = createTaprootSigningPsbt(descriptor);
    expect(
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toBe(2);

    const input = tx.getInput(0);
    const unknown = (input.unknown as Array<[{ type: number; key: Uint8Array }, Uint8Array]>) ?? [];
    const participantFields = unknown.filter(
      ([key]) => key.type === PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    );
    const nonceFields = unknown.filter(([key]) => key.type === PSBT_IN_MUSIG2_PUB_NONCE);
    const partialSigFields = unknown.filter(([key]) => key.type === PSBT_IN_MUSIG2_PARTIAL_SIG);
    const nonceKeyLengths = nonceFields.map(([key]) => key.key.length).sort((a, b) => a - b);

    expect(input.tapKeySig).toBeUndefined();
    expect(participantFields).toHaveLength(2);
    expect(nonceFields).toHaveLength(2);
    expect(nonceKeyLengths).toEqual([66, 98]);
    expect(partialSigFields).toHaveLength(0);
  });

  it("does not treat a MuSig2 signer as complete until every path involving that key is signed", () => {
    const signers = Array.from({ length: 3 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
      "DEFAULT",
    );

    let tx = createTaprootSigningPsbt(descriptor);
    expect(
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toBe(2);
    tx = roundtripPsbt(tx);
    expect(
      signWalletPsbtWithKey(
        tx,
        signers[1].accountKey,
        signers[1].fingerprint,
        descriptor,
        musigContext(1),
      ),
    ).toBe(2);
    tx = roundtripPsbt(tx);
    expect(
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toBe(1);

    expect(hasWalletSignerSignedPsbt(tx, signers[0].fingerprint, descriptor, "testnet")).toBe(
      false,
    );

    tx = roundtripPsbt(tx);
    expect(
      signWalletPsbtWithKey(
        tx,
        signers[2].accountKey,
        signers[2].fingerprint,
        descriptor,
        musigContext(2),
      ),
    ).toBe(2);
    tx = roundtripPsbt(tx);
    expect(
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toBe(1);

    expect(hasWalletSignerSignedPsbt(tx, signers[0].fingerprint, descriptor, "testnet")).toBe(true);
  });

  it("ignores polluted taproot input derivation paths when starting MuSig2 signing", () => {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
    );
    const tx = createTaprootSigningPsbt(descriptor);
    const input = tx.getInput(0);
    const tapBip32 = input.tapBip32Derivation;
    if (!tapBip32?.[0]) {
      throw new Error("Missing taproot derivation fixture");
    }

    input.tapBip32Derivation = [
      [
        tapBip32[0][0],
        {
          hashes: tapBip32[0][1].hashes,
          der: {
            fingerprint: tapBip32[0][1].der.fingerprint,
            path: [...tapBip32[0][1].der.path.slice(0, -2), 0, 83],
          },
        },
      ],
      ...tapBip32,
    ];

    expect(
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toBe(1);
  });

  it("signs taproot miniscript MuSig2 leaves after nonce exchange", () => {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptors = signers.map((signer) => signer.descriptor);
    const unspendableXpub = getUnspendableXpub(descriptors);
    const body = `tr(${unspendableXpub}/<0;1>/*,pk(musig(${descriptors[0]}/<0;1>/*,${descriptors[1]}/<0;1>/*)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;

    expectTaprootMusigSigningFlow(descriptor, signers);
  });

  it("signs taproot miniscript MuSig2 key-path inputs after nonce exchange", () => {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptors = signers.map((signer) => signer.descriptor);
    const body = `tr(musig(${descriptors[0]},${descriptors[1]})/<0;1>/*,pk(${descriptors[0]}/<0;1>/*))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;

    expectTaprootKeypathMusigSigningFlow(descriptor, signers);
  });

  it("signs taproot miniscript script-path inputs", () => {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptors = signers.map((signer) => signer.descriptor);
    const unspendableXpub = getUnspendableXpub(descriptors);
    const body = `tr(${unspendableXpub}/<0;1>/*,and_v(v:pk(${descriptors[0]}/<0;1>/*),pk(${descriptors[1]}/<0;1>/*)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const tx = createTaprootSigningPsbt(descriptor);

    const signed0 = signWalletPsbtWithKey(
      tx,
      signers[0].accountKey,
      signers[0].fingerprint,
      descriptor,
    );
    const signed1 = signWalletPsbtWithKey(
      tx,
      signers[1].accountKey,
      signers[1].fingerprint,
      descriptor,
    );

    expect(signed0).toBe(1);
    expect(signed1).toBe(1);
    expect((tx.getInput(0).tapScriptSig ?? []).length).toBe(2);
    tx.finalize();
    expect(tx.isFinal).toBe(true);
  });
});

function setInputSighash(tx: Transaction, index: number, value: number): void {
  (tx as unknown as { inputs: Array<{ sighashType?: number }> }).inputs[index].sighashType = value;
}

const SIGHASH_SINGLE = 0x03;
const SIGHASH_ALL_ANYONECANPAY = 0x81;
const SIGHASH_NONE_ANYONECANPAY = 0x82;

describe("signWalletPsbtWithKey sighash policy", () => {
  const miniscriptDescriptor = buildDescriptor(`pk(${signerDescriptor})`);
  const miniscriptXfp = parseInt(masterFingerprint, 16);

  function taprootMusigWallet() {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
      "DEFAULT",
    );
    return { signers, descriptor };
  }

  it("refuses a taproot MuSig2 input with SIGHASH_NONE without producing a nonce", () => {
    const { signers, descriptor } = taprootMusigWallet();
    const tx = createTaprootSigningPsbt(descriptor, { taprootKeyPath: true });
    setInputSighash(tx, 0, SignatureHash.NONE);

    expect(() =>
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toThrow(/is not the canonical sighash for a Taproot input/);

    // Nothing was signed and no MuSig2 nonce was published before the rejection.
    const input = tx.getInput(0);
    expect(input.tapKeySig).toBeUndefined();
    expect(input.tapScriptSig).toBeUndefined();
    const unknown = (input.unknown as Array<[{ type: number }, Uint8Array]>) ?? [];
    expect(unknown.some(([key]) => key.type === PSBT_IN_MUSIG2_PUB_NONCE)).toBe(false);
  });

  it("refuses an explicit SIGHASH_ALL on a taproot input (canonical is SIGHASH_DEFAULT)", () => {
    const { signers, descriptor } = taprootMusigWallet();
    const tx = createTaprootSigningPsbt(descriptor, { taprootKeyPath: true });
    setInputSighash(tx, 0, SignatureHash.ALL);

    expect(() =>
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toThrow(/is not the canonical sighash for a Taproot input \(expected SIGHASH_DEFAULT\)/);
  });

  it("signs a taproot input whose sighash flag is explicit SIGHASH_DEFAULT", () => {
    const { signers, descriptor } = taprootMusigWallet();
    const tx = createTaprootSigningPsbt(descriptor, { taprootKeyPath: true });
    setInputSighash(tx, 0, SignatureHash.DEFAULT);

    expect(
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toBe(1);
  });

  it("refuses a miniscript ECDSA input with SIGHASH_NONE without producing a signature", () => {
    const tx = createSigningPsbt(miniscriptDescriptor, 0, 0);
    setInputSighash(tx, 0, SignatureHash.NONE);

    expect(() => signWalletPsbtWithKey(tx, signerKey, miniscriptXfp, miniscriptDescriptor)).toThrow(
      /is not the canonical sighash for a non-Taproot input/,
    );
    expect(tx.getInput(0).partialSig).toBeUndefined();
  });

  it("refuses an explicit SIGHASH_DEFAULT on a segwit v0 input", () => {
    const tx = createSigningPsbt(miniscriptDescriptor, 0, 0);
    setInputSighash(tx, 0, SignatureHash.DEFAULT);

    expect(() => signWalletPsbtWithKey(tx, signerKey, miniscriptXfp, miniscriptDescriptor)).toThrow(
      /is not the canonical sighash for a non-Taproot input \(expected SIGHASH_ALL\)/,
    );
  });

  it("signs a segwit v0 input whose sighash flag is explicit SIGHASH_ALL", () => {
    const tx = createSigningPsbt(miniscriptDescriptor, 0, 0);
    setInputSighash(tx, 0, SignatureHash.ALL);

    expect(signWalletPsbtWithKey(tx, signerKey, miniscriptXfp, miniscriptDescriptor)).toBe(1);
    expect((tx.getInput(0).partialSig ?? []).length).toBe(1);
  });

  it.each([SIGHASH_SINGLE, SIGHASH_ALL_ANYONECANPAY, SIGHASH_NONE_ANYONECANPAY])(
    "refuses a miniscript input with sighash flag 0x%s",
    (flag) => {
      const tx = createSigningPsbt(miniscriptDescriptor, 0, 0);
      setInputSighash(tx, 0, flag);

      expect(() =>
        signWalletPsbtWithKey(tx, signerKey, miniscriptXfp, miniscriptDescriptor),
      ).toThrow(/is not the canonical sighash/);
    },
  );

  it("refuses the whole transaction when any input carries a bad sighash flag", () => {
    const tx = createSigningPsbt(miniscriptDescriptor, 0, 0);
    const second = deriveDescriptorPayment(miniscriptDescriptor, "testnet", 0, 1);
    tx.addInput({
      txid: "01".repeat(32),
      index: 0,
      sequence: 0xfffffffd,
      witnessUtxo: { amount: 20_000n, script: second.script },
      bip32Derivation: second.bip32Derivation,
      witnessScript: second.witnessScript,
    });
    // First input is fine; the second requests SIGHASH_NONE.
    setInputSighash(tx, 1, SignatureHash.NONE);

    expect(() => signWalletPsbtWithKey(tx, signerKey, miniscriptXfp, miniscriptDescriptor)).toThrow(
      /input 1/,
    );
    // The valid first input must not have been signed before the tx was refused.
    expect(tx.getInput(0).partialSig).toBeUndefined();
  });

  it("classifies a real P2TR input from its output script even if taproot metadata is stripped", () => {
    const { signers, descriptor } = taprootMusigWallet();
    const tx = createTaprootSigningPsbt(descriptor, { taprootKeyPath: true });
    // Attacker strips the optional taproot hints but leaves the real P2TR prevout script,
    // then requests explicit SIGHASH_ALL (valid on taproot, but non-canonical).
    const prevScript = tx.getInput(0).witnessUtxo?.script;
    // Sanity: the prevout really is a P2TR output (OP_1 <32-byte key>).
    expect(prevScript?.[0]).toBe(0x51);
    expect(prevScript?.length).toBe(34);
    const stripped = tx as unknown as {
      inputs: Array<{
        tapInternalKey?: Uint8Array;
        tapMerkleRoot?: Uint8Array;
        tapLeafScript?: unknown;
        tapBip32Derivation?: unknown;
        sighashType?: number;
      }>;
    };
    stripped.inputs[0].tapInternalKey = undefined;
    stripped.inputs[0].tapMerkleRoot = undefined;
    stripped.inputs[0].tapLeafScript = undefined;
    stripped.inputs[0].tapBip32Derivation = undefined;
    stripped.inputs[0].sighashType = SignatureHash.ALL;

    expect(() =>
      signWalletPsbtWithKey(
        tx,
        signers[0].accountKey,
        signers[0].fingerprint,
        descriptor,
        musigContext(0),
      ),
    ).toThrow(/is not the canonical sighash for a Taproot input/);
  });

  it("classifies a segwit v0 input from its output script even if taproot metadata is injected", () => {
    const tx = createSigningPsbt(miniscriptDescriptor, 0, 0);
    // Attacker injects a fake taproot hint onto a real segwit v0 input, then requests
    // explicit SIGHASH_DEFAULT (which is canonical for taproot but not for segwit v0).
    const injected = tx as unknown as {
      inputs: Array<{ tapInternalKey?: Uint8Array; sighashType?: number }>;
    };
    injected.inputs[0].tapInternalKey = new Uint8Array(32).fill(0xab);
    injected.inputs[0].sighashType = SignatureHash.DEFAULT;

    expect(() => signWalletPsbtWithKey(tx, signerKey, miniscriptXfp, miniscriptDescriptor)).toThrow(
      /is not the canonical sighash for a non-Taproot input/,
    );
    expect(tx.getInput(0).partialSig).toBeUndefined();
  });

  it("fails closed when an input has a non-default sighash but no previous output info", () => {
    const tx = createSigningPsbt(miniscriptDescriptor, 0, 0);
    // Remove the prevout data so the input type cannot be established from the UTXO script.
    const bare = tx as unknown as {
      inputs: Array<{ witnessUtxo?: unknown; nonWitnessUtxo?: unknown; sighashType?: number }>;
    };
    bare.inputs[0].witnessUtxo = undefined;
    bare.inputs[0].nonWitnessUtxo = undefined;
    bare.inputs[0].sighashType = SignatureHash.NONE;

    expect(() => signWalletPsbtWithKey(tx, signerKey, miniscriptXfp, miniscriptDescriptor)).toThrow(
      /previous output/i,
    );
    expect(tx.getInput(0).partialSig).toBeUndefined();
  });
});
