import { afterAll, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { HDKey } from "@scure/bip32";
import { Transaction, TEST_NETWORK } from "@scure/btc-signer";
import { TESTNET_VERSIONS, deriveDescriptorPayment } from "../address.js";
import { buildWalletDescriptor, descriptorChecksum, getUnspendableXpub } from "../descriptor.js";
import { hasWalletSignerSignedPsbt, signWalletPsbtWithKey } from "../psbt-sign.js";
import { _clearMasterKeyCache, _closeDatabase, loadMusigNonce } from "../storage.js";

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

  it("can defer consumed MuSig2 nonce deletion until the caller persists the signed PSBT", () => {
    const signers = Array.from({ length: 2 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(
      signers.map((signer) => signer.descriptor),
      2,
      "TAPROOT",
      "DEFAULT",
    );
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

    const consumedNonceIds: string[] = [];
    const context = { ...musigContext(0), consumedNonceIds };
    expect(
      signWalletPsbtWithKey(tx, signers[0].accountKey, signers[0].fingerprint, descriptor, context),
    ).toBe(1);

    expect(consumedNonceIds).toHaveLength(1);
    expect(loadMusigNonce(context.email, context.network, consumedNonceIds[0])).not.toBeNull();
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
