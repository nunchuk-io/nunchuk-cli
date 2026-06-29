import { describe, expect, it, vi } from "vitest";
import { HDKey } from "@scure/bip32";
import { hex } from "@scure/base";
import { Transaction, TEST_NETWORK } from "@scure/btc-signer";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  deriveDescriptorAddresses,
  deriveDescriptorPayment,
  TESTNET_VERSIONS,
} from "../address.js";
import { addressToScripthash } from "../electrum.js";
import { buildMiniscriptDescriptor } from "../miniscript.js";
import { finalizeMiniscriptPsbt } from "../miniscript-finalize.js";
import { signWalletPsbtWithKey } from "../psbt-sign.js";
import { encryptWalletPayload } from "../wallet-keys.js";
import {
  availableCandidates,
  classifyWalletOutput,
  combinePendingPsbt,
  createWalletOutputClassifier,
  createTransaction,
  decodePsbtDetail,
  fetchPendingTransaction,
  fetchPendingTransactions,
  fetchPendingTxInputTimelockMetadataBatch,
  fetchPsbtInputTimelockMetadata,
} from "../transaction.js";
import { CFeeRate, makeCOutput, type COutput } from "../coin-selection.js";
import { SeededRng } from "../coin-selection-params.js";
import { createDummyPsbt } from "../platform-key.js";
import {
  buildWalletDescriptor,
  descriptorChecksum,
  getUnspendableXpub,
  parseSignerDescriptor,
} from "../descriptor.js";
import { PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, PSBT_IN_MUSIG2_PUB_NONCE } from "../musig.js";
import { aggregateMusigCompressedPubkey, toXOnlyPubkey } from "../taproot.js";
import type { WalletData } from "../storage.js";
import type { ElectrumClient } from "../electrum.js";
import type { ApiClient } from "../api-client.js";

const TEST_WALLET: WalletData = {
  walletId: "207u9ts4",
  groupId: "883409fe-511d-4ae7-92bf-250b5bd6ce45",
  gid: "mrQ3kuD4AUt1S2H5HFhGk6LbpRGLDQkzLg",
  name: "Wallet 1",
  m: 2,
  n: 3,
  addressType: "NATIVE_SEGWIT",
  descriptor: "",
  signers: [
    "[b9a14f1a/48'/1'/0'/2']tpubDDuXvjq5jan2EVqnJpQjUcUAhYWVf4rrfuAgPp2oLqeGE6eZXvci5dbzuwpHdHrmGVzeBVZSCLavn4Fr5sYAd5PtzcufWwNH78KpUm37RRs",
    "[8317a853/48'/1'/0'/2']tpubDFUfs6uQ1PdCjjEasu5jAVjN32hhiSfFzS4cmgtkAK83WwWVSm26aoGeRBqKry51WmZkUgewhRaJzGGb3YLdxCFyKL8f7zC9tsF7KhQ9RxZ",
    "[ecfed4c1/48'/1'/45'/2']tpubDEeLpUMN5J595ocbHwWGyX39k7X8Jae5DqyQe5csXgJAnUZsAKrP6dhy2WDtxXvMmYCGTXo5eUuMAKV9dQryVyx3kW1EZnLXtcTTxsBvrnD",
  ],
  secretboxKey: "jnQRPI4//QSN8ti/4KUkcE0dt99/hDXIxwxCcDtKCiU=",
  createdAt: "2026-03-31T02:02:07.273Z",
};

TEST_WALLET.descriptor = buildWalletDescriptor(
  TEST_WALLET.signers,
  TEST_WALLET.m,
  TEST_WALLET.addressType,
);
const TEST_RECIPIENT = deriveDescriptorAddresses(TEST_WALLET.descriptor, "testnet", 0, 10, 1)[0];

const REPORTED_TAPROOT_DESCRIPTOR =
  "tr(musig([249fdf68/87'/0'/1']xpub6CtyrbfeG1bS5TgK5k67RpFscZLd7Kkn2wj2kb3kgy39ydU87sUutSCGU4YHHnz4FA79Fz4Jo7H7Jqfqz3AoqDGXNCzo4TnZ1KeXcuyMsfh/<0;1>/*,[86d82f57/87'/0'/0']xpub6CCsMJnVGqX6hU2Eyztx4rvdcCvY9kp9z44ANBGGVcc6zbCtEC24JZLzaem9SHYosC6n6Mympsv2BzcW3FBxHmu5R1yPtwMr74TQK46oSkt/<0;1>/*),{pk(musig([249fdf68/87'/0'/1']xpub6CtyrbfeG1bS5TgK5k67RpFscZLd7Kkn2wj2kb3kgy39ydU87sUutSCGU4YHHnz4FA79Fz4Jo7H7Jqfqz3AoqDGXNCzo4TnZ1KeXcuyMsfh/<0;1>/*,[480101ce/87'/0'/2']xpub6CFYMcJmguCwDe1g4SFgfpZjoNXaeU7LTtfx4MMKPiSnfxmsuXVKCRKDukYjq7jN6Y121GiuR6iaH2hPbYTNY8Dzp9AEzwMCJgLqFVNYH1L/<0;1>/*)),pk(musig([86d82f57/87'/0'/0']xpub6CCsMJnVGqX6hU2Eyztx4rvdcCvY9kp9z44ANBGGVcc6zbCtEC24JZLzaem9SHYosC6n6Mympsv2BzcW3FBxHmu5R1yPtwMr74TQK46oSkt/<0;1>/*,[480101ce/87'/0'/2']xpub6CFYMcJmguCwDe1g4SFgfpZjoNXaeU7LTtfx4MMKPiSnfxmsuXVKCRKDukYjq7jN6Y121GiuR6iaH2hPbYTNY8Dzp9AEzwMCJgLqFVNYH1L/<0;1>/*))})#xrde05jr";

const TEST_XPRV =
  "tprv8indigs9s1wXrGCnzFR8m65FU1BmZ7UMR8TqVArSk3KegTFipNCWQJenF45BjmrcPXXfNjyx5NrsU1gEd5BKYog9dEHuu7YqWB7HUt7AuzM";

const TEST_XFP = 0x8317a853;
const TEST_PREIMAGE_7 = new Uint8Array(32).fill(7);
const TEST_PREIMAGE_11 = new Uint8Array(32).fill(0x11);
const TEST_PREIMAGE_22 = new Uint8Array(32).fill(0x22);

const VALID_MINISCRIPT_SIGNERS = [
  {
    descriptor:
      "[96eca294/48'/1'/0'/2']tpubDFPj9hqgQDd6XmwP6rFLyfan3WwEXgAvWWwCAyTVfqegGX6FBofdCagNzn6FveEnaqa9k3sHdAX9Styj4LXVdT9FGiZcRhKE8pMEvZoSn7Y",
    fingerprint: 0x96eca294,
    xprv: "tprv8ihh1HoSFqwReJubDCakaFvfUVRJNLz1wDLQtTRCFZrHS2qUZQr3264Wpcbv8CxAYKYV2ZuucLntw96V9X1ZFeuoRQqdPcz3PACnJeHX5Eq",
  },
  {
    descriptor:
      "[e442ae1d/48'/1'/0'/2']tpubDFUQmRE5eeoBnPfjy3RkqCfGdzsbnTzJHqM7ioNrFspMUrgvBMJkUurg9dCmeb9zd9rTaVoNkMzPku6VsopVnhAPMyQs95KoK8Q1zUCtX2B",
    fingerprint: 0xe442ae1d,
    xprv: "tprv8inNd1BqWH7Wtvdx5PmARo1A4yMfd8oPiXkLSHLYqc1xeNS9YxVAJREoyUJpUAqJbY9EMeALmYe3dXPBtAMqpwuZeXv4WAgEMfDs48TyMk9",
  },
  {
    descriptor:
      "[dd38da6b/48'/1'/0'/2']tpubDFJiyLvovM1LQjFEiPb4Mbwc1RwksKEhaik61g4ayMUF2TjwqFBpKYh53cNCnxNiuzmpxjJ9UiTGJMKQ8RVCTv2bV4xv9FcaMmPhLjYPx7b",
    fingerprint: 0xdd38da6b,
    xprv: "tprv8icgpvtZmyKfXGDSpjvTxCHVSQRphz3o1R9JjA2HZ5frByVBCrNE945CsV8Z1xgqsBC7BQHMKcrWH4zSreE4RLsjRxNHg4d6ULj75y6xskC",
  },
] as const;

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

function templateSigner(index: number): string {
  return `${TEST_WALLET.signers[index]}/<0;1>/*`;
}

function materializeTemplate(template: string): string {
  return template
    .replaceAll("key_0_0", templateSigner(0))
    .replaceAll("key_1_0", templateSigner(1))
    .replaceAll("key_2_0", templateSigner(2));
}

function walletSigners(indexes: number[]): string[] {
  return indexes.map((index) => TEST_WALLET.signers[index]);
}

function signWithKnownTestSigner(tx: Transaction, signerIndex: 1, descriptor: string): number {
  return signWalletPsbtWithKey(
    tx,
    HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS),
    TEST_XFP,
    descriptor,
  );
}

function materializeValidMiniscriptTemplate(template: string): string {
  let result = template;
  for (const [index, signer] of VALID_MINISCRIPT_SIGNERS.entries()) {
    result = result.replaceAll(`key_${index}_0`, `${signer.descriptor}/<0;1>/*`);
  }
  return result;
}

function signWithValidMiniscriptSigner(
  tx: Transaction,
  signerIndex: 0 | 1 | 2,
  descriptor: string,
): number {
  const signer = VALID_MINISCRIPT_SIGNERS[signerIndex];
  return signWalletPsbtWithKey(
    tx,
    HDKey.fromExtendedKey(signer.xprv, TESTNET_VERSIONS),
    signer.fingerprint,
    descriptor,
  );
}

function createPsbtB64(requestBody = "testing"): string {
  return Buffer.from(createDummyPsbt(TEST_WALLET, requestBody, "testnet").toPSBT()).toString(
    "base64",
  );
}

function createSignedPsbtB64(requestBody = "testing"): string {
  const psbt = createDummyPsbt(TEST_WALLET, requestBody, "testnet");
  const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
  const input = psbt.getInput(0);
  const bip32 = input.bip32Derivation as Array<
    [Uint8Array, { fingerprint: number; path: number[] }]
  >;

  for (const [, { fingerprint, path }] of bip32) {
    if (fingerprint !== TEST_XFP) continue;

    const chain = path[path.length - 2];
    const index = path[path.length - 1];
    const childKey = signerKey.deriveChild(chain).deriveChild(index);
    if (childKey.privateKey) {
      psbt.signIdx(childKey.privateKey, 0);
    }
    break;
  }

  return Buffer.from(psbt.toPSBT()).toString("base64");
}

async function createServerTxEvent(txId: string, psbt: string) {
  return {
    id: txId,
    data: await encryptWalletPayload(TEST_WALLET, { psbt, txId }),
  };
}

describe("combinePendingPsbt", () => {
  it("marks changed when the provided PSBT adds a new signature", () => {
    const currentPsbtB64 = createPsbtB64();
    const nextPsbtB64 = createSignedPsbtB64();

    const result = combinePendingPsbt(currentPsbtB64, nextPsbtB64);
    const detail = decodePsbtDetail(
      result.psbtB64,
      "testnet",
      TEST_WALLET.m,
      TEST_WALLET.signers,
      TEST_WALLET.descriptor,
    );

    expect(result.changed).toBe(true);
    expect(detail?.signedCount).toBe(1);
    expect(detail?.signers["8317a853"]).toBe(true);
  });

  it("marks unchanged when the provided PSBT adds no new data", () => {
    const currentPsbtB64 = createSignedPsbtB64();

    const result = combinePendingPsbt(currentPsbtB64, currentPsbtB64);
    const detail = decodePsbtDetail(
      result.psbtB64,
      "testnet",
      TEST_WALLET.m,
      TEST_WALLET.signers,
      TEST_WALLET.descriptor,
    );

    expect(result.changed).toBe(false);
    expect(detail?.signedCount).toBe(1);
    expect(detail?.signers["8317a853"]).toBe(true);
  });

  it("rejects a provided PSBT for a different unsigned transaction", () => {
    const currentPsbtB64 = createPsbtB64();
    const nextPsbtB64 = createSignedPsbtB64("different testing body");

    expect(() => combinePendingPsbt(currentPsbtB64, nextPsbtB64)).toThrow(
      "Provided PSBT does not match the current pending transaction",
    );
  });
});

describe("fetchPendingTransactions", () => {
  it("skips deleted empty-PSBT transaction events", async () => {
    const deletedTxId = "deleted-tx";
    const activeTxId = "active-tx";
    const deletedEvent = await createServerTxEvent(deletedTxId, "");
    const olderDeletedEvent = await createServerTxEvent(deletedTxId, createPsbtB64("deleted"));
    const activeEvent = await createServerTxEvent(activeTxId, createPsbtB64("active"));
    const client = {
      get: vi.fn(async () => ({
        transactions: [deletedEvent, olderDeletedEvent, activeEvent],
      })),
    } as unknown as ApiClient;

    await expect(fetchPendingTransactions(client, TEST_WALLET)).resolves.toEqual([
      { txId: activeTxId, psbt: createPsbtB64("active") },
    ]);
  });

  it("treats a single empty-PSBT transaction event as not found", async () => {
    const client = {
      get: vi.fn(async () => ({
        transaction: await createServerTxEvent("deleted-tx", ""),
      })),
    } as unknown as ApiClient;

    await expect(fetchPendingTransaction(client, TEST_WALLET, "deleted-tx")).rejects.toThrow(
      "Transaction not found on server",
    );
  });
});

describe("classifyWalletOutput", () => {
  it("uses discovered wallet addresses beyond the first fallback gap batch", () => {
    const highIndexChangeAddress = deriveDescriptorAddresses(
      TEST_WALLET.descriptor,
      "testnet",
      1,
      25,
      1,
    )[0];
    const classifier = createWalletOutputClassifier("testnet", TEST_WALLET.descriptor, 3);

    expect(classifier.classify(highIndexChangeAddress, null)).toEqual({
      isWalletOutput: false,
      isChange: false,
    });

    classifier.addKnownAddress(highIndexChangeAddress, 1);

    expect(classifier.classify(highIndexChangeAddress, null)).toEqual({
      isWalletOutput: true,
      isChange: true,
    });
  });

  it("classifies the reported libnunchuk taproot change output by descriptor address", () => {
    expect(
      classifyWalletOutput(
        "bc1p5xh697m2tyqvnaxz2kf6c64dp4jexemslvdx8cmedfasf00dq0dqavlpft",
        null,
        "mainnet",
        REPORTED_TAPROOT_DESCRIPTOR,
        3,
      ),
    ).toEqual({ isWalletOutput: true, isChange: true });

    expect(
      classifyWalletOutput(
        "bc1pv4kkj7nqdqu3t0mnawfcq4ufwn88ka7p9flvhddt5uea5wf25g6swjufvs",
        null,
        "mainnet",
        REPORTED_TAPROOT_DESCRIPTOR,
        3,
      ),
    ).toEqual({ isWalletOutput: false, isChange: false });
  });
});

function createFundingHex(address: string, amount: bigint): { rawHex: string; txid: string } {
  const tx = new Transaction();
  tx.addInput({ txid: "00".repeat(32), index: 0, sequence: 0xfffffffd });
  tx.addOutputAddress(address, amount, TEST_NETWORK);
  return {
    rawHex: Buffer.from(tx.unsignedTx).toString("hex"),
    txid: tx.id,
  };
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function deriveSignerChildPubkey(desc: string): Uint8Array {
  const parsed = parseSignerDescriptor(desc);
  const child = HDKey.fromExtendedKey(parsed.xpub, TESTNET_VERSIONS).deriveChild(0).deriveChild(0);
  if (!child.publicKey) {
    throw new Error("Failed to derive signer child pubkey");
  }
  return child.publicKey;
}

function addMusigNonceForSigner(
  tx: Transaction,
  signerDescriptors: string[],
  signerIndex: number,
  participantIndexes = signerDescriptors.map((_, index) => index),
): string {
  if (!participantIndexes.includes(signerIndex)) {
    throw new Error("Nonce signer is not in the requested MuSig2 keyset");
  }

  const participants = participantIndexes.map((index) =>
    deriveSignerChildPubkey(signerDescriptors[index]),
  );
  const signerPubkey = deriveSignerChildPubkey(signerDescriptors[signerIndex]);
  const aggregatePubkey = aggregateMusigCompressedPubkey(participants);
  const inputs = (
    tx as unknown as {
      inputs?: Array<
        ReturnType<Transaction["getInput"]> & {
          unknown?: Array<[{ type: number; key: Uint8Array }, Uint8Array]>;
        }
      >;
    }
  ).inputs;
  const input = inputs?.[0];
  if (!input) {
    throw new Error("Missing PSBT input");
  }
  const mutableInput = input as ReturnType<Transaction["getInput"]> & {
    unknown?: Array<[{ type: number; key: Uint8Array }, Uint8Array]>;
  };
  const tapBip32 = mutableInput.tapBip32Derivation as
    | Array<[Uint8Array, { der: { fingerprint: number } }]>
    | undefined;
  const signerXOnlyPubkey = hex.encode(toXOnlyPubkey(signerPubkey));
  const nonceFingerprint = tapBip32?.find(
    ([pubkey]) => hex.encode(pubkey) === signerXOnlyPubkey,
  )?.[1].der.fingerprint;

  mutableInput.unknown = [
    ...(mutableInput.unknown ?? []),
    [{ type: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, key: aggregatePubkey }, concatBytes(participants)],
    [
      {
        type: PSBT_IN_MUSIG2_PUB_NONCE,
        key: concatBytes([signerPubkey, aggregatePubkey]),
      },
      new Uint8Array(66).fill(1),
    ],
  ];

  if (nonceFingerprint === undefined) {
    throw new Error("Failed to map nonce signer fingerprint");
  }
  return nonceFingerprint.toString(16).padStart(8, "0");
}

function createBlockHeaderHex(blocktime: number): string {
  const header = Buffer.alloc(80);
  header.writeUInt32LE(blocktime, 68);
  return header.toString("hex");
}

function removeInputWitnessUtxo(psbtB64: string): string {
  const tx = Transaction.fromPSBT(Buffer.from(psbtB64, "base64"));
  const inputs = (tx as unknown as { inputs?: Array<Record<string, unknown>> }).inputs;
  if (!inputs?.[0]) {
    throw new Error("Missing PSBT input");
  }
  delete inputs[0].witnessUtxo;
  return Buffer.from(tx.toPSBT()).toString("base64");
}

// Locate the wallet's change output regardless of its (randomized) position:
// only the change output carries wallet derivation metadata — recipient outputs
// are added via addOutputAddress with no bip32/taproot metadata.
function findChangeOutputIndex(tx: Transaction): number {
  for (let i = 0; i < tx.outputsLength; i++) {
    const out = tx.getOutput(i);
    if (
      out.tapInternalKey ||
      (out.bip32Derivation?.length ?? 0) > 0 ||
      (out.tapBip32Derivation?.length ?? 0) > 0
    ) {
      return i;
    }
  }
  throw new Error("No wallet change output found");
}

function findChangeOutput(tx: Transaction) {
  return tx.getOutput(findChangeOutputIndex(tx));
}

function createMiniscriptElectrumMock(
  descriptor: string,
  fundingAmount: bigint,
  height = 200,
  blocktime = 1_700_000_000,
): { electrum: ElectrumClient; txid: string } {
  const receiveAddress = deriveDescriptorAddresses(descriptor, "testnet", 0, 0, 1)[0];
  const { rawHex, txid } = createFundingHex(receiveAddress, fundingAmount);
  const scripthash = addressToScripthash(receiveAddress, "testnet");
  const getTransaction = vi.fn(async (hash: string) => {
    if (hash !== txid) {
      throw new Error("unknown tx");
    }
    return rawHex;
  });
  const listUnspent = vi.fn(async (hash: string) =>
    hash === scripthash ? [{ tx_hash: txid, tx_pos: 0, height, value: Number(fundingAmount) }] : [],
  );
  const getHistory = vi.fn(async (hash: string) =>
    hash === scripthash ? [{ tx_hash: txid, height }] : [],
  );
  const getBlockHeader = vi.fn(async (requestedHeight: number) => {
    if (requestedHeight !== height) {
      throw new Error("unknown block");
    }
    return createBlockHeaderHex(blocktime);
  });

  return {
    txid,
    electrum: {
      estimateFee: vi.fn(async () => 0.00001),
      getTransaction,
      getTransactionBatch: vi.fn(async (hashes: string[]) =>
        Promise.all(hashes.map(getTransaction)),
      ),
      listUnspent,
      listUnspentBatch: vi.fn(async (hashes: string[]) => Promise.all(hashes.map(listUnspent))),
      getHistory,
      getHistoryBatch: vi.fn(async (hashes: string[]) => Promise.all(hashes.map(getHistory))),
      getBlockHeader,
      getBlockHeaderBatch: vi.fn(async (heights: number[]) =>
        Promise.all(heights.map(getBlockHeader)),
      ),
    } as unknown as ElectrumClient,
  };
}

// Funds the wallet's first receive address with several independent UTXOs so
// coin selection actually has a set to choose from. Amounts must be distinct
// (createFundingHex derives the txid from the output, so equal amounts collide).
function createMultiUtxoElectrumMock(
  descriptor: string,
  amounts: bigint[],
  height = 200,
  blocktime = 1_700_000_000,
): { electrum: ElectrumClient; txids: string[] } {
  const receiveAddress = deriveDescriptorAddresses(descriptor, "testnet", 0, 0, 1)[0];
  const scripthash = addressToScripthash(receiveAddress, "testnet");
  const funding = amounts.map((amount) => createFundingHex(receiveAddress, amount));
  const hexByTxid = new Map(funding.map((f) => [f.txid, f.rawHex]));
  const utxos = funding.map((f, i) => ({
    tx_hash: f.txid,
    tx_pos: 0,
    height,
    value: Number(amounts[i]),
  }));
  const getTransaction = vi.fn(async (hash: string) => {
    const rawHex = hexByTxid.get(hash);
    if (!rawHex) throw new Error("unknown tx");
    return rawHex;
  });
  const listUnspent = vi.fn(async (hash: string) => (hash === scripthash ? utxos : []));
  const getHistory = vi.fn(async (hash: string) =>
    hash === scripthash ? utxos.map((u) => ({ tx_hash: u.tx_hash, height })) : [],
  );
  const getBlockHeader = vi.fn(async (requestedHeight: number) => {
    if (requestedHeight !== height) throw new Error("unknown block");
    return createBlockHeaderHex(blocktime);
  });

  return {
    txids: funding.map((f) => f.txid),
    electrum: {
      estimateFee: vi.fn(async () => 0.00001),
      getTransaction,
      getTransactionBatch: vi.fn(async (hashes: string[]) =>
        Promise.all(hashes.map(getTransaction)),
      ),
      listUnspent,
      listUnspentBatch: vi.fn(async (hashes: string[]) => Promise.all(hashes.map(listUnspent))),
      getHistory,
      getHistoryBatch: vi.fn(async (hashes: string[]) => Promise.all(hashes.map(getHistory))),
      getBlockHeader,
      getBlockHeaderBatch: vi.fn(async (heights: number[]) =>
        Promise.all(heights.map(getBlockHeader)),
      ),
    } as unknown as ElectrumClient,
  };
}

describe("availableCandidates (remain_target oldest-first cap)", () => {
  const MAX_BIP125_RBF_SEQUENCE = 0xfffffffd;

  // feerate 0 → fee 0 → effectiveValue == value, so cap math is exact and obvious.
  function coinAt(height: number, value: bigint): COutput {
    return makeCOutput(
      {
        txid: "00".repeat(32),
        vout: 0,
        value,
        inputVBytes: 68,
        height,
        blocktime: 0,
        isChange: false,
      },
      {
        effectiveFeerate: new CFeeRate(0n),
        longTermFeerate: new CFeeRate(0n),
        currentHeight: 1_000_000,
      },
    );
  }

  const coins = [
    coinAt(300, 30_000n),
    coinAt(100, 25_000n),
    coinAt(-1, 99_000n), // unconfirmed
    coinAt(200, 20_000n),
  ];

  it("returns every coin, oldest-confirmed-first, for a normal RBF spend", () => {
    const result = availableCandidates(coins, MAX_BIP125_RBF_SEQUENCE, 10_000n, false);
    expect(result.map((c) => c.coin.height)).toEqual([100, 200, 300, -1]);
  });

  it("does not cap when sequence is 0 (no relative timelock)", () => {
    const result = availableCandidates(coins, 0, 10_000n, false);
    expect(result).toHaveLength(coins.length);
  });

  it("caps a CSV spend to the oldest coins covering the target", () => {
    // target 40k: oldest-first 25k (h100) + 20k (h200) = 45k >= 40k → stop.
    const result = availableCandidates(coins, 6, 40_000n, false);
    expect(result.map((c) => c.coin.height)).toEqual([100, 200]);
  });

  it("keeps adding oldest coins until the target is met, unconfirmed last", () => {
    // target 80k: 25k + 20k + 30k = 75k (< 80k) then unconfirmed 99k crosses it.
    const result = availableCandidates(coins, 6, 80_000n, false);
    expect(result.map((c) => c.coin.height)).toEqual([100, 200, 300, -1]);
  });
});

describe("createTransaction coin selection (multi-UTXO end-to-end)", () => {
  // Sum of every input's value and every output's value, read off the PSBT.
  function sumInOut(tx: Transaction): { totalIn: bigint; totalOut: bigint } {
    let totalIn = 0n;
    for (let i = 0; i < tx.inputsLength; i++) {
      totalIn += tx.getInput(i).witnessUtxo!.amount;
    }
    let totalOut = 0n;
    for (let i = 0; i < tx.outputsLength; i++) {
      totalOut += tx.getOutput(i).amount!;
    }
    return { totalIn, totalOut };
  }

  it("selects a subset and balances inputs = outputs + fee (segwit multisig)", async () => {
    const amounts = [40_000n, 35_000n, 30_000n, 25_000n, 22_000n, 18_000n];
    const { electrum } = createMultiUtxoElectrumMock(TEST_WALLET.descriptor, amounts);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet: TEST_WALLET,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      // Selection chose a proper subset of the available UTXOs (not all of them).
      expect(tx.inputsLength).toBeGreaterThanOrEqual(1);
      expect(tx.inputsLength).toBeLessThan(amounts.length);

      // Every selected input is one of our funded UTXOs (amounts are distinct).
      const fundedAmounts = new Set(amounts);
      for (let i = 0; i < tx.inputsLength; i++) {
        expect(fundedAmounts.has(tx.getInput(i).witnessUtxo!.amount)).toBe(true);
      }

      // The recipient is paid exactly, and inputs cover amount + fee.
      const { totalIn, totalOut } = sumInOut(tx);
      expect([...Array(tx.outputsLength).keys()].map((i) => tx.getOutput(i).amount)).toContain(
        10_000n,
      );
      expect(result.fee).toBeGreaterThan(0n);
      expect(totalIn - totalOut).toBe(result.fee); // value conservation
      expect(totalIn).toBeGreaterThanOrEqual(10_000n + result.fee);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("selects a subset for a taproot key-path multisig wallet", async () => {
    const signers = TEST_WALLET.signers.slice(0, 2);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT", "DEFAULT");
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 2,
      n: 2,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const amounts = [40_000n, 33_000n, 27_000n, 21_000n, 16_000n];
    const { electrum } = createMultiUtxoElectrumMock(descriptor, amounts);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });

      expect(tx.inputsLength).toBeGreaterThanOrEqual(1);
      expect(tx.inputsLength).toBeLessThan(amounts.length);

      // Key-path spend: every input carries a taproot internal key, no leaf script.
      for (let i = 0; i < tx.inputsLength; i++) {
        const input = tx.getInput(i);
        expect(input.tapInternalKey).toHaveLength(32);
        expect(input.tapLeafScript ?? []).toEqual([]);
      }

      const { totalIn, totalOut } = sumInOut(tx);
      expect(result.fee).toBeGreaterThan(0n);
      expect(totalIn - totalOut).toBe(result.fee);
      expect(totalIn).toBeGreaterThanOrEqual(10_000n + result.fee);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("rejects a recipient amount below the dust threshold", async () => {
    // TEST_RECIPIENT is a P2WSH output → ~330 sat dust at the 3000 sat/kvB discard rate.
    const { electrum } = createMultiUtxoElectrumMock(TEST_WALLET.descriptor, [40_000n]);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      await expect(
        createTransaction({
          wallet: TEST_WALLET,
          network: "testnet",
          electrum,
          toAddress: TEST_RECIPIENT,
          amount: 100n,
        }),
      ).rejects.toThrow(/too small/i);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("createTransaction privacy (input shuffle + change position)", () => {
  it("places the change output at both positions across RNG seeds", async () => {
    const { electrum } = createMiniscriptElectrumMock(TEST_WALLET.descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const positions = new Set<number>();
      for (let seed = 0; seed < 16; seed++) {
        const result = await createTransaction({
          wallet: TEST_WALLET,
          network: "testnet",
          electrum,
          toAddress: TEST_RECIPIENT,
          amount: 10_000n,
          rng: new SeededRng(seed),
        });
        const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));
        expect(tx.outputsLength).toBe(2);
        positions.add(findChangeOutputIndex(tx));
      }
      // Change must appear at both index 0 and index 1 — not a fixed position.
      expect([...positions].sort()).toEqual([0, 1]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("shuffles the input order across RNG seeds", async () => {
    // Amounts chosen so all three coins are always required (no two cover 60k),
    // fixing the selected set — only the input order can vary, via the shuffle.
    const amounts = [30_000n, 28_000n, 26_000n];
    const { electrum } = createMultiUtxoElectrumMock(TEST_WALLET.descriptor, amounts);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const orderings = new Set<string>();
      for (let seed = 0; seed < 16; seed++) {
        const result = await createTransaction({
          wallet: TEST_WALLET,
          network: "testnet",
          electrum,
          toAddress: TEST_RECIPIENT,
          amount: 60_000n,
          rng: new SeededRng(seed),
        });
        const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));
        expect(tx.inputsLength).toBe(amounts.length);
        const order = Array.from({ length: tx.inputsLength }, (_, i) =>
          tx.getInput(i).witnessUtxo!.amount.toString(),
        ).join(",");
        orderings.add(order);
      }
      // At least two distinct input orderings → inputs are shuffled, not fixed.
      expect(orderings.size).toBeGreaterThan(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("createTransaction manual fee rate", () => {
  const offlineBase = (electrum: ElectrumClient) => ({
    wallet: TEST_WALLET,
    network: "testnet" as const,
    electrum,
    toAddress: TEST_RECIPIENT,
    amount: 10_000n,
  });

  it("uses the manual rate verbatim and scales the fee by it (overriding the estimate)", async () => {
    const { electrum } = createMiniscriptElectrumMock(TEST_WALLET.descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const base = offlineBase(electrum);
      const high = await createTransaction({ ...base, feeRateSatPerKvB: 25_000n }); // 25 sat/vB
      const low = await createTransaction({ ...base, feeRateSatPerKvB: 5_000n }); // 5 sat/vB
      const auto = await createTransaction(base); // estimate (~1 sat/vB)

      // Manual rate is used verbatim, not the estimate.
      expect(high.feeRateSatPerKvB).toBe(25_000n);
      expect(low.feeRateSatPerKvB).toBe(5_000n);
      expect(high.feeRateSatPerKvB).not.toBe(auto.feeRateSatPerKvB);

      // fee == getFee(vsize) = rate × vsize / 1000; an integer sat/vB rate divides it.
      expect(high.fee % 25n).toBe(0n);
      expect(low.fee % 5n).toBe(0n);
      expect(high.fee).toBeGreaterThan(low.fee);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("supports a fractional rate (1.5 sat/vB = 1500 sat/kvB)", async () => {
    const { electrum } = createMiniscriptElectrumMock(TEST_WALLET.descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const base = offlineBase(electrum);
      const r1 = await createTransaction({ ...base, feeRateSatPerKvB: 1_000n }); // 1 sat/vB → fee == vsize
      const r15 = await createTransaction({ ...base, feeRateSatPerKvB: 1_500n }); // 1.5 sat/vB
      const r2 = await createTransaction({ ...base, feeRateSatPerKvB: 2_000n }); // 2 sat/vB

      expect(r15.feeRateSatPerKvB).toBe(1_500n);
      // Same single-UTXO tx shape → fee scales with the rate, strictly between 1× and 2×.
      expect(r15.fee).toBeGreaterThan(r1.fee);
      expect(r15.fee).toBeLessThan(r2.fee);
      // fee(1.5) == floor(1.5 × vsize), and vsize == fee at 1 sat/vB.
      expect(r15.fee).toBe((3n * r1.fee) / 2n);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("createTransaction fee level", () => {
  const offlineFetch = () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;
    return () => {
      globalThis.fetch = originalFetch;
    };
  };

  it("estimates with the requested level's conf_target and reports it", async () => {
    const { electrum } = createMiniscriptElectrumMock(TEST_WALLET.descriptor, 50_000n);
    const restore = offlineFetch();
    try {
      const result = await createTransaction({
        wallet: TEST_WALLET,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        feeLevel: "priority",
      });
      // priority → Electrum conf_target 2 on the API-offline fallback path.
      expect(electrum.estimateFee).toHaveBeenCalledWith(2);
      expect(result.feeLevel).toBe("priority");
    } finally {
      restore();
    }
  });

  it("defaults to economy (conf_target 6) when no level is given", async () => {
    const { electrum } = createMiniscriptElectrumMock(TEST_WALLET.descriptor, 50_000n);
    const restore = offlineFetch();
    try {
      const result = await createTransaction({
        wallet: TEST_WALLET,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      expect(electrum.estimateFee).toHaveBeenCalledWith(6);
      expect(result.feeLevel).toBe("economy");
    } finally {
      restore();
    }
  });

  it("ignores the level and reports no level when a manual rate is supplied", async () => {
    const { electrum } = createMiniscriptElectrumMock(TEST_WALLET.descriptor, 50_000n);
    const restore = offlineFetch();
    try {
      const result = await createTransaction({
        wallet: TEST_WALLET,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        feeRateSatPerKvB: 5_000n,
        feeLevel: "priority",
      });
      // Manual rate wins: no estimate, and no level reported back.
      expect(electrum.estimateFee).not.toHaveBeenCalled();
      expect(result.feeRateSatPerKvB).toBe(5_000n);
      expect(result.feeLevel).toBeUndefined();
    } finally {
      restore();
    }
  });
});

describe("createTransaction anti-fee sniping", () => {
  const offline = () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;
    return () => {
      globalThis.fetch = originalFetch;
    };
  };

  it("pins nLockTime to the chain tip when no path locktime exists", async () => {
    const { electrum } = createMiniscriptElectrumMock(TEST_WALLET.descriptor, 50_000n);
    const headersSubscribe = vi.fn(async () => ({ height: 850_000, hex: "tip" }));
    (electrum as unknown as { headersSubscribe: unknown }).headersSubscribe = headersSubscribe;
    const restore = offline();
    try {
      const result = await createTransaction({
        wallet: TEST_WALLET,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        antiFeeSniping: true,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(headersSubscribe).toHaveBeenCalled();
      expect(result.lockTime).toBe(850_000);
      expect(tx.lockTime).toBe(850_000);
      // Default Replace-By-Fee sequence (< 0xFFFFFFFF) keeps the locktime enforced.
      expect(tx.getInput(0).sequence).toBe(0xfffffffd);
    } finally {
      restore();
    }
  });

  it("leaves nLockTime at 0 when anti-fee sniping is off", async () => {
    const { electrum } = createMiniscriptElectrumMock(TEST_WALLET.descriptor, 50_000n);
    const headersSubscribe = vi.fn(async () => ({ height: 850_000, hex: "tip" }));
    (electrum as unknown as { headersSubscribe: unknown }).headersSubscribe = headersSubscribe;
    const restore = offline();
    try {
      const result = await createTransaction({
        wallet: TEST_WALLET,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      expect(headersSubscribe).not.toHaveBeenCalled();
      expect(result.lockTime).toBe(0);
    } finally {
      restore();
    }
  });

  it("keeps a path's absolute locktime instead of the chain tip", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),after(144))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[0]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const headersSubscribe = vi.fn(async () => ({ height: 850_000, hex: "tip" }));
    (electrum as unknown as { headersSubscribe: unknown }).headersSubscribe = headersSubscribe;
    const restore = offline();
    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        antiFeeSniping: true,
      });
      // The path's absolute locktime wins; the chain tip is never consulted.
      expect(headersSubscribe).not.toHaveBeenCalled();
      expect(result.lockTime).toBe(144);
    } finally {
      restore();
    }
  });

  it("still fills the chain-tip locktime for a relative-timelock-only path", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),older(10))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[0]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const headersSubscribe = vi.fn(async () => ({ height: 850_000, hex: "tip" }));
    (electrum as unknown as { headersSubscribe: unknown }).headersSubscribe = headersSubscribe;
    const restore = offline();
    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        antiFeeSniping: true,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));
      // A relative timelock sets the input sequence, not the locktime, so
      // anti-fee sniping still fills the locktime.
      expect(result.lockTime).toBe(850_000);
      expect(tx.lockTime).toBe(850_000);
      expect(tx.getInput(0).sequence).toBe(10);
    } finally {
      restore();
    }
  });
});

describe("createTransaction multisig", () => {
  it("uses the default dust threshold for standard multisig coin selection", async () => {
    const { electrum } = createMiniscriptElectrumMock(TEST_WALLET.descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet: TEST_WALLET,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(tx.inputsLength).toBe(1);
      expect(result.fee).toBeGreaterThan(0n);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("creates taproot multisig disable-key-path PSBT metadata", async () => {
    const signers = TEST_WALLET.signers.slice(0, 2);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT");
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 2,
      n: 2,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });
      const input = tx.getInput(0);
      const changeOutput = findChangeOutput(tx);

      expect(tx.inputsLength).toBe(1);
      expect(tx.outputsLength).toBe(2);
      expect(input.bip32Derivation ?? []).toEqual([]);
      expect(input.tapInternalKey).toHaveLength(32);
      expect(input.tapMerkleRoot).toHaveLength(32);
      expect(input.tapLeafScript).toHaveLength(1);
      expect(input.tapBip32Derivation).toHaveLength(signers.length);
      expect(changeOutput.bip32Derivation ?? []).toEqual([]);
      expect(changeOutput.tapInternalKey).toHaveLength(32);
      expect(changeOutput.tapBip32Derivation).toHaveLength(signers.length);
      expect(result.changeAddress).toMatch(/^tb1p/);
      expect(result.fee).toBeGreaterThan(0n);

      const signerXfps = signers.map((signer) => parseSignerDescriptor(signer).masterFingerprint);
      const detail = decodePsbtDetail(
        result.psbtB64,
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
      );
      expect(detail?.keysets).toEqual([
        {
          index: 0,
          type: "script-path",
          status: "PENDING_NONCE",
          signers: [signerXfps[0], signerXfps[1]].sort(),
          nonces: {
            [signerXfps[0]]: false,
            [signerXfps[1]]: false,
          },
          signatures: {
            [signerXfps[0]]: false,
            [signerXfps[1]]: false,
          },
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("creates taproot multisig key-path MuSig2 PSBT metadata", async () => {
    const signers = TEST_WALLET.signers.slice(0, 2);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT", "DEFAULT");
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 2,
      n: 2,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });
      const input = tx.getInput(0);

      expect(input.bip32Derivation ?? []).toEqual([]);
      expect(input.tapInternalKey).toHaveLength(32);
      expect(input.tapMerkleRoot).toBeUndefined();
      expect(input.tapLeafScript).toBeUndefined();
      expect(input.tapBip32Derivation).toHaveLength(signers.length);
      expect(input.tapBip32Derivation?.every(([, { hashes }]) => hashes.length === 0)).toBe(true);
      expect(result.changeAddress).toMatch(/^tb1p/);
      expect(result.fee).toBeGreaterThan(0n);

      const outputClassifier = createWalletOutputClassifier("testnet", wallet.descriptor);
      const detail = decodePsbtDetail(
        result.psbtB64,
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { outputClassifier },
      );
      expect(detail?.status).toBe("PENDING_NONCE");
      expect(detail?.nonces).toEqual({
        [parseSignerDescriptor(signers[0]).masterFingerprint]: false,
        [parseSignerDescriptor(signers[1]).masterFingerprint]: false,
      });
      expect(detail?.keysets).toHaveLength(1);
      expect(detail?.keysets?.[0]).toMatchObject({
        index: 0,
        type: "key-path",
        status: "PENDING_NONCE",
        signers: signers.map((signer) => parseSignerDescriptor(signer).masterFingerprint).sort(),
        nonces: {
          [parseSignerDescriptor(signers[0]).masterFingerprint]: false,
          [parseSignerDescriptor(signers[1]).masterFingerprint]: false,
        },
        signatures: {
          [parseSignerDescriptor(signers[0]).masterFingerprint]: false,
          [parseSignerDescriptor(signers[1]).masterFingerprint]: false,
        },
      });

      const nonceFingerprint = addMusigNonceForSigner(tx, signers, 0);
      const detailWithNonce = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { outputClassifier },
      );
      expect(detailWithNonce?.status).toBe("PENDING_NONCE");
      expect(detailWithNonce?.nonces).toEqual({
        [parseSignerDescriptor(signers[0]).masterFingerprint]:
          nonceFingerprint === parseSignerDescriptor(signers[0]).masterFingerprint,
        [parseSignerDescriptor(signers[1]).masterFingerprint]:
          nonceFingerprint === parseSignerDescriptor(signers[1]).masterFingerprint,
      });
      expect(detailWithNonce?.keysets?.[0]).toMatchObject({
        status: "PENDING_NONCE",
        nonces: {
          [parseSignerDescriptor(signers[0]).masterFingerprint]:
            nonceFingerprint === parseSignerDescriptor(signers[0]).masterFingerprint,
          [parseSignerDescriptor(signers[1]).masterFingerprint]:
            nonceFingerprint === parseSignerDescriptor(signers[1]).masterFingerprint,
        },
      });

      addMusigNonceForSigner(tx, signers, 1);
      const detailWithCompleteNonce = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { outputClassifier },
      );
      expect(detailWithCompleteNonce?.status).toBe("PENDING_SIGNATURES");
      expect(detailWithCompleteNonce?.keysets?.[0]).toMatchObject({
        status: "PENDING_SIGNATURES",
        nonces: {
          [parseSignerDescriptor(signers[0]).masterFingerprint]: true,
          [parseSignerDescriptor(signers[1]).masterFingerprint]: true,
        },
        signatures: {
          [parseSignerDescriptor(signers[0]).masterFingerprint]: false,
          [parseSignerDescriptor(signers[1]).masterFingerprint]: false,
        },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("creates taproot multisig key-path PSBT metadata for DEFAULT wallets with script leaves", async () => {
    const signers = TEST_WALLET.signers.slice(0, 3);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT", "DEFAULT");
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 2,
      n: 3,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });
      const input = tx.getInput(0);
      const changeOutput = findChangeOutput(tx);

      expect(input.tapInternalKey).toHaveLength(32);
      expect(input.tapMerkleRoot).toHaveLength(32);
      expect(input.tapLeafScript).toBeUndefined();
      expect(input.tapBip32Derivation).toHaveLength(2);
      expect(input.tapBip32Derivation?.every(([, { hashes }]) => hashes.length === 0)).toBe(true);
      expect(changeOutput.tapInternalKey).toHaveLength(32);
      expect(changeOutput.tapBip32Derivation).toHaveLength(2);
      expect(changeOutput.tapBip32Derivation?.every(([, { hashes }]) => hashes.length === 0)).toBe(
        true,
      );
      expect(result.changeAddress).toMatch(/^tb1p/);
      expect(result.fee).toBeGreaterThan(0n);
    } finally {
      globalThis.fetch = originalFetch;
    }
  }, 10_000);

  it("creates taproot multisig script-path PSBT metadata when requested", async () => {
    const signers = TEST_WALLET.signers.slice(0, 3);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT", "DEFAULT");
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 2,
      n: 3,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        taprootScriptPath: true,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });
      const input = tx.getInput(0);
      const changeOutput = findChangeOutput(tx);

      expect(input.tapInternalKey).toHaveLength(32);
      expect(input.tapMerkleRoot).toHaveLength(32);
      expect(input.tapLeafScript).toHaveLength(2);
      expect(input.tapBip32Derivation?.length).toBeGreaterThan(2);
      expect(input.tapBip32Derivation?.some(([, { hashes }]) => hashes.length > 0)).toBe(true);
      expect(changeOutput.tapInternalKey).toHaveLength(32);
      expect(changeOutput.tapBip32Derivation?.length).toBeGreaterThan(2);
      expect(result.changeAddress).toMatch(/^tb1p/);
      expect(result.fee).toBeGreaterThan(0n);
    } finally {
      globalThis.fetch = originalFetch;
    }
  }, 10_000);

  it("rejects taproot script-path spending for key-path-only multisig wallets", async () => {
    const signers = TEST_WALLET.signers.slice(0, 2);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT", "DEFAULT");
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 2,
      n: 2,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);

    await expect(
      createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        taprootScriptPath: true,
      }),
    ).rejects.toThrow("script-path spending enabled");
  });

  it("reports taproot multisig keysets for DEFAULT wallets with script leaves", () => {
    const signers = TEST_WALLET.signers.slice(0, 3);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT", "DEFAULT");
    const signerXfps = signers.map((signer) => parseSignerDescriptor(signer).masterFingerprint);
    const detail = decodePsbtDetail(createPsbtB64(), "testnet", 2, signers, descriptor, {
      outputClassifier: {
        addKnownAddress: vi.fn(),
        classify: () => ({ isWalletOutput: false, isChange: false }),
      },
    });

    expect(detail?.keysets).toEqual([
      {
        index: 0,
        type: "key-path",
        status: "PENDING_NONCE",
        signers: [signerXfps[0], signerXfps[1]].sort(),
        nonces: {
          [signerXfps[0]]: false,
          [signerXfps[1]]: false,
        },
        signatures: {
          [signerXfps[0]]: false,
          [signerXfps[1]]: false,
        },
      },
      {
        index: 1,
        type: "script-path",
        status: "PENDING_NONCE",
        signers: [signerXfps[0], signerXfps[2]].sort(),
        nonces: {
          [signerXfps[0]]: false,
          [signerXfps[2]]: false,
        },
        signatures: {
          [signerXfps[0]]: false,
          [signerXfps[2]]: false,
        },
      },
      {
        index: 2,
        type: "script-path",
        status: "PENDING_NONCE",
        signers: [signerXfps[1], signerXfps[2]].sort(),
        nonces: {
          [signerXfps[1]]: false,
          [signerXfps[2]]: false,
        },
        signatures: {
          [signerXfps[1]]: false,
          [signerXfps[2]]: false,
        },
      },
    ]);
  });

  it("recognizes libnunchuk-style output-keyed MuSig2 key-path nonces", () => {
    const signers = TEST_WALLET.signers.slice(0, 3);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT", "DEFAULT");
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
      tapLeafScript: payment.tapLeafScript,
      tapBip32Derivation: payment.tapBip32Derivation,
    });
    tx.addOutputAddress(payment.address, 49_000n, TEST_NETWORK);

    const participants = [deriveSignerChildPubkey(signers[0]), deriveSignerChildPubkey(signers[1])];
    const signerXfps = signers.map((signer) => parseSignerDescriptor(signer).masterFingerprint);
    const aggregatePubkey = aggregateMusigCompressedPubkey(participants);
    const outputKey = payment.script.subarray(2);
    const outputCompressedPubkey = concatBytes([new Uint8Array([0x02]), outputKey]);
    const inputs = tx as unknown as {
      inputs: Array<
        ReturnType<Transaction["getInput"]> & {
          unknown?: Array<[{ type: number; key: Uint8Array }, Uint8Array]>;
        }
      >;
    };
    inputs.inputs[0].unknown = [
      [
        { type: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, key: aggregatePubkey },
        concatBytes(participants),
      ],
      [
        {
          type: PSBT_IN_MUSIG2_PUB_NONCE,
          key: concatBytes([participants[0], outputCompressedPubkey]),
        },
        new Uint8Array(66).fill(1),
      ],
      [
        {
          type: PSBT_IN_MUSIG2_PUB_NONCE,
          key: concatBytes([participants[1], outputCompressedPubkey]),
        },
        new Uint8Array(66).fill(2),
      ],
    ];

    const detail = decodePsbtDetail(
      Buffer.from(tx.toPSBT()).toString("base64"),
      "testnet",
      2,
      signers,
      descriptor,
    );

    expect(detail?.status).toBe("PENDING_SIGNATURES");
    expect(detail?.keysets?.[0]).toMatchObject({
      type: "key-path",
      status: "PENDING_SIGNATURES",
      nonces: {
        [signerXfps[0]]: true,
        [signerXfps[1]]: true,
      },
    });
  });

  it("counts external taproot outputs even when PSBT output metadata is polluted", async () => {
    const signers = TEST_WALLET.signers.slice(0, 3);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT", "DEFAULT");
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 2,
      n: 3,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });
      // Pollute the recipient output's metadata with the change output's keys,
      // to prove classification is by address ownership, not PSBT metadata.
      const changeIndex = findChangeOutputIndex(tx);
      const recipientIndex = changeIndex === 0 ? 1 : 0;
      const changeOutput = tx.getOutput(changeIndex);
      tx.updateOutput(recipientIndex, {
        tapInternalKey: changeOutput.tapInternalKey,
        tapBip32Derivation: changeOutput.tapBip32Derivation,
      });

      const detail = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
      );

      expect(detail?.subAmount).toBe("10000 sat");
      expect(detail?.subAmountBtc).toBe("0.00010000 BTC");
      expect(detail?.outputs[recipientIndex].isChange).toBe(false);
      expect(detail?.outputs[changeIndex].isChange).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  }, 10_000);

  it("rejects taproot key-path spending for disable-key-path multisig wallets", async () => {
    const signers = TEST_WALLET.signers.slice(0, 3);
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT");
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 2,
      n: 3,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);

    await expect(
      createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        taprootKeyPath: true,
      }),
    ).rejects.toThrow("key-path spending enabled");
  });
});

describe("createTransaction miniscript", () => {
  it("creates taproot miniscript PSBT metadata", async () => {
    const signers = TEST_WALLET.signers.slice(0, 2);
    const unspendableXpub = getUnspendableXpub(signers);
    const body = `tr(${unspendableXpub}/<0;1>/*,and_v(v:pk(${signers[0]}/<0;1>/*),pk(${signers[1]}/<0;1>/*)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      n: 2,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });
      const input = tx.getInput(0);
      const changeOutput = findChangeOutput(tx);

      expect(tx.inputsLength).toBe(1);
      expect(tx.outputsLength).toBe(2);
      expect(input.witnessScript).toBeUndefined();
      expect(input.bip32Derivation ?? []).toEqual([]);
      expect(input.tapInternalKey).toHaveLength(32);
      expect(input.tapMerkleRoot).toHaveLength(32);
      expect(input.tapLeafScript).toHaveLength(1);
      expect(input.tapBip32Derivation).toHaveLength(signers.length);
      expect(changeOutput.bip32Derivation ?? []).toEqual([]);
      expect(changeOutput.tapInternalKey).toHaveLength(32);
      expect(changeOutput.tapBip32Derivation).toHaveLength(signers.length);
      expect(result.miniscriptPath).toMatchObject({
        requiredSignatures: 2,
      });
      expect(result.changeAddress).toMatch(/^tb1p/);

      const detail = decodePsbtDetail(
        result.psbtB64,
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
      );
      expect(detail?.status).toBe("PENDING_SIGNATURES");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("creates taproot miniscript key-path MuSig2 PSBT metadata", async () => {
    const signers = TEST_WALLET.signers.slice(0, 3);
    const body = `tr(musig(${signers[0]},${signers[1]})/<0;1>/*,pk(${signers[2]}/<0;1>/*))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 2,
      n: 3,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });
      const input = tx.getInput(0);
      const changeOutput = findChangeOutput(tx);

      expect(input.tapInternalKey).toHaveLength(32);
      expect(input.tapMerkleRoot).toHaveLength(32);
      expect(input.tapLeafScript).toBeUndefined();
      expect(input.tapBip32Derivation).toHaveLength(2);
      expect(input.tapBip32Derivation?.every(([, { hashes }]) => hashes.length === 0)).toBe(true);
      expect(changeOutput.tapInternalKey).toHaveLength(32);
      expect(changeOutput.tapBip32Derivation).toHaveLength(2);
      expect(result.miniscriptPath).toBeUndefined();
      const detail = decodePsbtDetail(
        result.psbtB64,
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
      );
      expect(detail?.miniscriptPath).toBeUndefined();
      expect(detail?.signers).toEqual({
        [parseSignerDescriptor(signers[0]).masterFingerprint]: false,
        [parseSignerDescriptor(signers[1]).masterFingerprint]: false,
      });
      expect(detail?.nonces).toEqual({
        [parseSignerDescriptor(signers[0]).masterFingerprint]: false,
        [parseSignerDescriptor(signers[1]).masterFingerprint]: false,
      });
      expect(detail?.signers).not.toHaveProperty(
        parseSignerDescriptor(signers[2]).masterFingerprint,
      );
      expect(result.changeAddress).toMatch(/^tb1p/);
      expect(result.fee).toBeGreaterThan(0n);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("does not report a script path for default single-key taproot miniscript key-path PSBTs", async () => {
    const signers = TEST_WALLET.signers.slice(0, 3);
    const body = `tr(${signers[0]}/<0;1>/*,thresh(2,pk(${signers[1]}/<0;1>/*),s:pk(${signers[2]}/<0;1>/*),sln:older(1)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 1,
      n: 3,
      addressType: "TAPROOT",
      descriptor,
      signers,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });
      const input = tx.getInput(0);
      const detail = decodePsbtDetail(
        result.psbtB64,
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
      );

      expect(input.tapInternalKey).toHaveLength(32);
      expect(input.tapMerkleRoot).toHaveLength(32);
      expect(input.tapLeafScript).toBeUndefined();
      expect(input.tapBip32Derivation).toHaveLength(1);
      expect(input.tapBip32Derivation?.every(([, { hashes }]) => hashes.length === 0)).toBe(true);
      expect(result.miniscriptPath).toBeUndefined();
      expect(detail?.miniscriptPath).toBeUndefined();
      expect(detail?.signers).toEqual({
        [parseSignerDescriptor(signers[0]).masterFingerprint]: false,
      });
      expect(detail?.signers).not.toHaveProperty(
        parseSignerDescriptor(signers[1]).masterFingerprint,
      );
      expect(detail?.signers).not.toHaveProperty(
        parseSignerDescriptor(signers[2]).masterFingerprint,
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("finalizes taproot miniscript script-path leaves unknown to the default taproot finalizer", async () => {
    const descriptors = VALID_MINISCRIPT_SIGNERS.map((signer) => signer.descriptor);
    const body = `tr(${descriptors[0]}/<0;1>/*,thresh(3,pk(${descriptors[0]}/<0;1>/*),s:pk(${descriptors[1]}/<0;1>/*),s:pk(${descriptors[2]}/<0;1>/*),sln:older(1)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 1,
      n: 3,
      addressType: "TAPROOT",
      descriptor,
      signers: descriptors,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        taprootScriptPath: true,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });

      expect(result.miniscriptPath).toMatchObject({
        index: 0,
        requiredSignatures: 3,
      });
      expect(tx.getInput(0).tapLeafScript).toHaveLength(1);
      expect(signWithValidMiniscriptSigner(tx, 0, wallet.descriptor)).toBe(1);
      expect(signWithValidMiniscriptSigner(tx, 1, wallet.descriptor)).toBe(1);
      expect(signWithValidMiniscriptSigner(tx, 2, wallet.descriptor)).toBe(1);

      expect(finalizeMiniscriptPsbt(tx, wallet.descriptor, "testnet")).toMatchObject({
        requiredPreimages: 0,
      });
      expect(tx.isFinal).toBe(true);
      expect(() => tx.extract()).not.toThrow();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("finalizes taproot miniscript multi_a script-path inputs", async () => {
    const descriptors = VALID_MINISCRIPT_SIGNERS.map((signer) => signer.descriptor);
    const unspendableXpub = getUnspendableXpub(descriptors);
    const body = `tr(${unspendableXpub}/<0;1>/*,and_v(v:multi_a(2,${descriptors[0]}/<0;1>/*,${descriptors[1]}/<0;1>/*,${descriptors[2]}/<0;1>/*),after(1)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      n: 3,
      addressType: "TAPROOT",
      descriptor,
      signers: descriptors,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        taprootScriptPath: true,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });

      expect(tx.getInput(0).tapLeafScript).toHaveLength(1);
      expect(signWithValidMiniscriptSigner(tx, 0, wallet.descriptor)).toBe(1);
      expect(signWithValidMiniscriptSigner(tx, 2, wallet.descriptor)).toBe(1);

      expect(finalizeMiniscriptPsbt(tx, wallet.descriptor, "testnet")).toMatchObject({
        requiredPreimages: 0,
        requiredSignatures: 2,
      });
      const witness = tx.getInput(0).finalScriptWitness;
      expect(witness).toHaveLength(5);
      expect(witness?.[1]).toHaveLength(0);
      expect(tx.isFinal).toBe(true);
      expect(() => tx.extract()).not.toThrow();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("reports all compatible taproot miniscript satisfaction paths and narrows by signatures", async () => {
    const descriptors = VALID_MINISCRIPT_SIGNERS.map((signer) => signer.descriptor);
    const unspendableXpub = getUnspendableXpub(descriptors);
    const body = `tr(${unspendableXpub}/<0;1>/*,thresh(2,pk(${descriptors[0]}/<0;1>/*),s:pk(${descriptors[1]}/<0;1>/*),s:pk(${descriptors[2]}/<0;1>/*)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      n: 3,
      addressType: "TAPROOT",
      descriptor,
      signers: descriptors,
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        taprootScriptPath: true,
        miniscriptPath: 1,
      });
      expect(result.miniscriptPath).toMatchObject({
        index: 1,
        requiredSignatures: 2,
      });

      const unsignedDetail = decodePsbtDetail(
        result.psbtB64,
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
      );
      expect(unsignedDetail?.miniscriptPaths?.map((path) => path.index)).toEqual([0, 1, 2]);
      expect(unsignedDetail?.miniscriptPaths?.find((path) => path.index === 1)).toMatchObject({
        requiredSignatures: 2,
        signedCount: 0,
        status: "compatible",
      });

      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"), {
        allowUnknown: true,
      });
      expect(signWithValidMiniscriptSigner(tx, 0, wallet.descriptor)).toBe(1);
      expect(signWithValidMiniscriptSigner(tx, 2, wallet.descriptor)).toBe(1);

      const signedDetail = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
      );
      expect(signedDetail?.status).toBe("READY_TO_BROADCAST");
      expect(signedDetail?.miniscriptPath).toMatchObject({ index: 1 });
      expect(signedDetail?.miniscriptPaths?.find((path) => path.index === 1)).toMatchObject({
        signedCount: 2,
        status: "satisfied",
      });
      expect(signedDetail?.miniscriptPaths?.find((path) => path.index === 0)).toMatchObject({
        status: "compatible",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("uses absolute timelocks as transaction locktime", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),after(144))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[0]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(tx.lockTime).toBe(144);
      expect(tx.getInput(0).sequence).toBe(0xfffffffd);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("uses relative timelocks as input sequence", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),older(10))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[0]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(tx.lockTime).toBe(0);
      expect(tx.getInput(0).sequence).toBe(10);
      expect(tx.getInput(0).witnessScript).toBeDefined();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("uses an explicit miniscript path selection when provided", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `or_d(pk(${TEST_WALLET.signers[0]}/<0;1>/*),and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(10)))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[0], TEST_WALLET.signers[1]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        miniscriptPath: 1,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(result.miniscriptPath).toMatchObject({
        index: 1,
        requiredSignatures: 1,
        sequence: 10,
        signerNames: [`${TEST_WALLET.signers[1]}/<0;1>/*`],
      });
      expect(tx.lockTime).toBe(0);
      expect(tx.getInput(0).sequence).toBe(10);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("reports future absolute locktime separately from ready status", async () => {
    const futureLocktime = 2_100_000_000;
    const descriptor = buildMiniscriptDescriptor(
      `or_d(pk(${TEST_WALLET.signers[0]}/<0;1>/*),and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),after(${futureLocktime})))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[0], TEST_WALLET.signers[1]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        miniscriptPath: 1,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);

      const detail = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { currentUnixTime: futureLocktime - 1 },
      );

      expect(detail?.status).toBe("READY_TO_BROADCAST");
      expect(detail?.signedCount).toBe(1);
      expect(detail?.requiredCount).toBe(1);
      expect(detail?.miniscriptPath).toMatchObject({
        index: 1,
        lockTime: futureLocktime,
        requiredSignatures: 1,
        signerNames: [`${TEST_WALLET.signers[1]}/<0;1>/*`],
      });
      expect(detail?.timelockedUntil).toEqual({
        based: "TIME_LOCK",
        mature: false,
        value: futureLocktime,
      });
      expect(detail?.signers["b9a14f1a"]).toBe(false);
      expect(detail?.signers["8317a853"]).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("reports immature relative timelocks separately from ready status", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(10))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[1]],
    };
    const { electrum, txid } = createMiniscriptElectrumMock(descriptor, 50_000n, 100);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));
      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);

      const detail = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { currentHeight: 105, inputUtxos: [{ txHash: txid, txPos: 0, height: 100 }] },
      );

      expect(detail?.status).toBe("READY_TO_BROADCAST");
      expect(detail?.timelockedUntil).toEqual({
        based: "HEIGHT_LOCK",
        mature: false,
        value: 110,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("reports mature relative timelocks separately from ready status", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(10))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[1]],
    };
    const { electrum, txid } = createMiniscriptElectrumMock(descriptor, 50_000n, 100);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));
      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);

      const detail = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { currentHeight: 110, inputUtxos: [{ txHash: txid, txPos: 0, height: 100 }] },
      );

      expect(detail?.status).toBe("READY_TO_BROADCAST");
      expect(detail?.timelockedUntil).toEqual({
        based: "HEIGHT_LOCK",
        mature: true,
        value: 110,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("reports unconfirmed relative timelocks as undetermined", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(10))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[1]],
    };
    const { electrum, txid } = createMiniscriptElectrumMock(descriptor, 50_000n, 0);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));
      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);

      const detail = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { currentHeight: 110, inputUtxos: [{ txHash: txid, txPos: 0, height: 0 }] },
      );

      expect(detail?.status).toBe("READY_TO_BROADCAST");
      expect(detail?.timelockedUntil).toEqual({
        based: "HEIGHT_LOCK",
        mature: null,
        value: null,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("resolves relative time lock targets from PSBT input history", async () => {
    const sequence = 0x400000 | 7;
    const relativeSeconds = 7 * 512;
    const blocktime = 1_700_000_000;
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(${sequence}))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[1]],
    };
    const { electrum, txid } = createMiniscriptElectrumMock(descriptor, 50_000n, 100, blocktime);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));
      expect(tx.getInput(0).sequence).toBe(sequence);
      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);

      const psbtB64 = Buffer.from(tx.toPSBT()).toString("base64");
      const inputUtxos = await fetchPsbtInputTimelockMetadata(psbtB64, electrum, "testnet");

      expect(inputUtxos).toEqual([{ txHash: txid, txPos: 0, height: 100, blocktime }]);

      const detail = decodePsbtDetail(
        psbtB64,
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { currentUnixTime: blocktime + relativeSeconds - 1, inputUtxos },
      );

      expect(detail?.status).toBe("READY_TO_BROADCAST");
      expect(detail?.timelockedUntil).toEqual({
        based: "TIME_LOCK",
        mature: false,
        value: blocktime + relativeSeconds,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("dedupes timelock metadata lookups across pending PSBTs", async () => {
    const blocktime = 1_700_000_000;
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(10))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[1]],
    };
    const { electrum, txid } = createMiniscriptElectrumMock(descriptor, 50_000n, 100, blocktime);
    const mockedElectrum = electrum as unknown as {
      getTransactionBatch: ReturnType<typeof vi.fn>;
      getHistoryBatch: ReturnType<typeof vi.fn>;
      getBlockHeaderBatch: ReturnType<typeof vi.fn>;
    };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const psbtWithoutWitnessUtxo = removeInputWitnessUtxo(result.psbtB64);
      mockedElectrum.getTransactionBatch.mockClear();
      mockedElectrum.getHistoryBatch.mockClear();
      mockedElectrum.getBlockHeaderBatch.mockClear();

      const metadataByTxId = await fetchPendingTxInputTimelockMetadataBatch(
        [
          { txId: "pending-a", psbt: psbtWithoutWitnessUtxo },
          { txId: "pending-b", psbt: psbtWithoutWitnessUtxo },
        ],
        electrum,
        "testnet",
      );

      const expected = [{ txHash: txid, txPos: 0, height: 100, blocktime }];
      expect(metadataByTxId.get("pending-a")).toEqual(expected);
      expect(metadataByTxId.get("pending-b")).toEqual(expected);
      expect(mockedElectrum.getTransactionBatch).toHaveBeenCalledTimes(1);
      expect(mockedElectrum.getTransactionBatch.mock.calls[0][0]).toEqual([txid]);
      expect(mockedElectrum.getHistoryBatch).toHaveBeenCalledTimes(1);
      expect(mockedElectrum.getHistoryBatch.mock.calls[0][0]).toHaveLength(1);
      expect(mockedElectrum.getBlockHeaderBatch).toHaveBeenCalledTimes(1);
      expect(mockedElectrum.getBlockHeaderBatch.mock.calls[0][0]).toEqual([100]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("skips malformed PSBTs when resolving pending timelock metadata in batch", async () => {
    const blocktime = 1_700_000_000;
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(10))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[1]],
    };
    const { electrum, txid } = createMiniscriptElectrumMock(descriptor, 50_000n, 100, blocktime);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });

      const metadataByTxId = await fetchPendingTxInputTimelockMetadataBatch(
        [
          { txId: "bad", psbt: "not-a-psbt" },
          { txId: "good", psbt: result.psbtB64 },
        ],
        electrum,
        "testnet",
      );

      expect(metadataByTxId.has("bad")).toBe(false);
      expect(metadataByTxId.get("good")).toEqual([
        { txHash: txid, txPos: 0, height: 100, blocktime },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("signs miniscript PSBT inputs with the local fallback signer", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),pk(${TEST_WALLET.signers[1]}/<0;1>/*))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[0], TEST_WALLET.signers[1]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      const signed = signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor);

      expect(signed).toBe(1);
      expect((tx.getInput(0).partialSig ?? []).length).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("reports partial progress for miniscript multi branches", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:multi(2,${TEST_WALLET.signers[0]}/<0;1>/*,${TEST_WALLET.signers[1]}/<0;1>/*,${TEST_WALLET.signers[2]}/<0;1>/*),after(1))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[0], TEST_WALLET.signers[1], TEST_WALLET.signers[2]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);

      const detail = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { currentHeight: 1 },
      );

      expect(detail?.status).toBe("PENDING_SIGNATURES");
      expect(detail?.signedCount).toBe(1);
      expect(detail?.requiredCount).toBe(2);
      expect(detail?.signers).toEqual({
        "8317a853": true,
        b9a14f1a: false,
        ecfed4c1: false,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("finalizes a signed miniscript PSBT locally", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(10))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[1]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);
      expect(finalizeMiniscriptPsbt(tx, wallet.descriptor, "testnet").requiredSignatures).toBe(1);
      expect(tx.isFinal).toBe(true);
      expect(() => tx.extract()).not.toThrow();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("finalizes hashed-key miniscript PSBTs locally", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `pkh(${TEST_WALLET.signers[1]}/<0;1>/*)`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[1]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);
      expect(finalizeMiniscriptPsbt(tx, wallet.descriptor, "testnet").requiredSignatures).toBe(1);
      expect(tx.isFinal).toBe(true);
      expect(() => tx.extract()).not.toThrow();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("marks a satisfiable miniscript PSBT as ready to broadcast", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `or_i(pk(${TEST_WALLET.signers[1]}/<0;1>/*),after(144))`,
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: [TEST_WALLET.signers[1]],
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);

      const detail = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { currentHeight: 1 },
      );

      expect(detail?.status).toBe("READY_TO_BROADCAST");
      expect(detail?.requiredCount).toBe(1);
      expect(detail?.signedCount).toBe(1);
      expect(detail?.signers).toEqual({ "8317a853": true });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("does not over-attribute signer fingerprints for server-style finalized miniscript PSBTs", async () => {
    const descriptor = buildMiniscriptDescriptor(
      materializeValidMiniscriptTemplate("and_v(v:multi(2,key_0_0,key_1_0,key_2_0),after(1))"),
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: VALID_MINISCRIPT_SIGNERS.map((signer) => signer.descriptor),
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const result = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

      expect(signWithValidMiniscriptSigner(tx, 0, wallet.descriptor)).toBe(1);
      expect(signWithValidMiniscriptSigner(tx, 1, wallet.descriptor)).toBe(1);
      finalizeMiniscriptPsbt(tx, wallet.descriptor, "testnet");

      const inputs = (tx as unknown as { inputs?: Array<Record<string, unknown>> }).inputs;
      if (!inputs?.[0]) {
        throw new Error("Missing finalized input");
      }
      delete inputs[0].partialSig;
      delete inputs[0].bip32Derivation;

      const detail = decodePsbtDetail(
        Buffer.from(tx.toPSBT()).toString("base64"),
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        { currentHeight: 1 },
      );

      expect(detail?.status).toBe("READY_TO_BROADCAST");
      expect(detail?.signedCount).toBe(2);
      expect(detail?.requiredCount).toBe(2);
      expect(detail?.signers).toEqual({});
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  const preimageHashCases = [
    {
      field: "sha256",
      hash: hex.encode(sha256(TEST_PREIMAGE_7)),
      name: "sha256 signer+preimage template",
      preimage: TEST_PREIMAGE_7,
      template: "and_v(v:pk(key_1_0),sha256(HASH))",
      type: "SHA256" as const,
    },
    {
      field: "hash256",
      hash: hex.encode(hash256(TEST_PREIMAGE_11)),
      name: "hash256 signer+preimage template",
      preimage: TEST_PREIMAGE_11,
      template: "and_v(v:pk(key_1_0),hash256(HASH))",
      type: "HASH256" as const,
    },
    {
      field: "ripemd160",
      hash: hex.encode(ripemd160(TEST_PREIMAGE_22)),
      name: "ripemd160 signer+preimage template",
      preimage: TEST_PREIMAGE_22,
      template: "and_v(v:pk(key_1_0),ripemd160(HASH))",
      type: "RIPEMD160" as const,
    },
    {
      field: "hash160",
      hash: hex.encode(hash160(TEST_PREIMAGE_7)),
      name: "hash160 signer+preimage template",
      preimage: TEST_PREIMAGE_7,
      template: "and_v(v:pk(key_1_0),hash160(HASH))",
      type: "HASH160" as const,
    },
  ];

  it.each(preimageHashCases)(
    "finalizes miniscript PSBTs for $name",
    async ({ field, hash, preimage, template, type }) => {
      const descriptor = buildMiniscriptDescriptor(
        materializeTemplate(template.replace("HASH", hash)),
        "NATIVE_SEGWIT",
      );
      const wallet: WalletData = {
        ...TEST_WALLET,
        m: 0,
        descriptor,
        signers: walletSigners([1]),
      };
      const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn(async () => {
        throw new Error("offline");
      }) as typeof fetch;

      try {
        const withoutPreimage = await createTransaction({
          wallet,
          network: "testnet",
          electrum,
          toAddress: TEST_RECIPIENT,
          amount: 10_000n,
        });
        const unsignedTx = Transaction.fromPSBT(Buffer.from(withoutPreimage.psbtB64, "base64"));
        expect(signWithKnownTestSigner(unsignedTx, 1, wallet.descriptor)).toBe(1);
        expect(() => finalizeMiniscriptPsbt(unsignedTx, wallet.descriptor, "testnet")).toThrow(
          "Not enough signatures or hash preimages to finalize miniscript PSBT",
        );

        const withPreimage = await createTransaction({
          wallet,
          network: "testnet",
          electrum,
          toAddress: TEST_RECIPIENT,
          amount: 10_000n,
          preimages: [hex.encode(preimage)],
        });
        const tx = Transaction.fromPSBT(Buffer.from(withPreimage.psbtB64, "base64"));

        expect(withPreimage.miniscriptPath).toMatchObject({
          preimageRequirements: [{ hash, type }],
          requiredSignatures: 1,
        });
        const hashEntries = (
          ((tx.getInput(0) as unknown as Record<string, unknown>)[field] as unknown[]) ?? []
        ).length;
        expect(hashEntries).toBe(1);
        expect(signWithKnownTestSigner(tx, 1, wallet.descriptor)).toBe(1);
        expect(finalizeMiniscriptPsbt(tx, wallet.descriptor, "testnet")).toMatchObject({
          requiredPreimages: 1,
          requiredSignatures: 1,
        });
        expect(tx.isFinal).toBe(true);

        const detail = decodePsbtDetail(
          Buffer.from(tx.toPSBT()).toString("base64"),
          "testnet",
          wallet.m,
          wallet.signers,
          wallet.descriptor,
        );
        expect(detail?.status).toBe("READY_TO_BROADCAST");
        expect(detail?.miniscriptPath?.preimageRequirements).toEqual([{ hash, type }]);
      } finally {
        globalThis.fetch = originalFetch;
      }
    },
    10_000,
  );

  it("finalizes the preimage fallback branch of an or_d template", async () => {
    const digest = hex.encode(sha256(TEST_PREIMAGE_11));
    const descriptor = buildMiniscriptDescriptor(
      materializeTemplate(`or_d(pk(key_0_0),and_v(v:pk(key_1_0),sha256(${digest})))`),
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: walletSigners([0, 1]),
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const withoutPreimage = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        miniscriptPath: 1,
      });
      const unsignedTx = Transaction.fromPSBT(Buffer.from(withoutPreimage.psbtB64, "base64"));
      expect(signWithKnownTestSigner(unsignedTx, 1, wallet.descriptor)).toBe(1);
      expect(() => finalizeMiniscriptPsbt(unsignedTx, wallet.descriptor, "testnet")).toThrow(
        "Not enough signatures or hash preimages to finalize miniscript PSBT",
      );

      const withPreimage = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        miniscriptPath: 1,
        preimages: [hex.encode(TEST_PREIMAGE_11)],
      });
      const tx = Transaction.fromPSBT(Buffer.from(withPreimage.psbtB64, "base64"));

      expect(withPreimage.miniscriptPath).toMatchObject({
        index: 1,
        preimageRequirements: [{ hash: digest, type: "SHA256" }],
        requiredSignatures: 1,
        signerNames: [templateSigner(1)],
      });
      expect(signWithKnownTestSigner(tx, 1, wallet.descriptor)).toBe(1);
      expect(finalizeMiniscriptPsbt(tx, wallet.descriptor, "testnet")).toMatchObject({
        requiredPreimages: 1,
        requiredSignatures: 1,
      });
      expect(tx.isFinal).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("finalizes a 2-of-3 multi template that also requires a preimage", async () => {
    const digest = hex.encode(sha256(TEST_PREIMAGE_22));
    const descriptor = buildMiniscriptDescriptor(
      materializeValidMiniscriptTemplate(
        `and_v(v:multi(2,key_0_0,key_1_0,key_2_0),sha256(${digest}))`,
      ),
      "NATIVE_SEGWIT",
    );
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor,
      signers: VALID_MINISCRIPT_SIGNERS.map((signer) => signer.descriptor),
    };
    const { electrum } = createMiniscriptElectrumMock(descriptor, 50_000n);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("offline");
    }) as typeof fetch;

    try {
      const withoutPreimage = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const unsignedTx = Transaction.fromPSBT(Buffer.from(withoutPreimage.psbtB64, "base64"));
      expect(signWithValidMiniscriptSigner(unsignedTx, 0, wallet.descriptor)).toBe(1);
      expect(signWithValidMiniscriptSigner(unsignedTx, 1, wallet.descriptor)).toBe(1);
      expect(() => finalizeMiniscriptPsbt(unsignedTx, wallet.descriptor, "testnet")).toThrow(
        "Not enough signatures or hash preimages to finalize miniscript PSBT",
      );

      const withPreimage = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        preimages: [hex.encode(TEST_PREIMAGE_22)],
      });
      const tx = Transaction.fromPSBT(Buffer.from(withPreimage.psbtB64, "base64"));

      expect(withPreimage.miniscriptPath).toMatchObject({
        preimageRequirements: [{ hash: digest, type: "SHA256" }],
        requiredSignatures: 2,
      });
      expect(signWithValidMiniscriptSigner(tx, 0, wallet.descriptor)).toBe(1);
      expect(signWithValidMiniscriptSigner(tx, 1, wallet.descriptor)).toBe(1);
      expect(finalizeMiniscriptPsbt(tx, wallet.descriptor, "testnet")).toMatchObject({
        requiredPreimages: 1,
        requiredSignatures: 2,
      });
      expect(tx.isFinal).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
