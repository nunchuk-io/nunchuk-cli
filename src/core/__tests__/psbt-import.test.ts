import { beforeEach, describe, expect, it, vi } from "vitest";
import { HDKey } from "@scure/bip32";
import { Transaction, TEST_NETWORK, p2pkh, p2wpkh } from "@scure/btc-signer";
import { SignatureHash } from "@scure/btc-signer/transaction.js";
import { TESTNET_VERSIONS, deriveDescriptorPayment } from "../address.js";
import { descriptorChecksum, parseDescriptor } from "../descriptor.js";
import type { ApiClient } from "../api-client.js";
import type { ElectrumClient } from "../electrum.js";
import type { WalletData } from "../storage.js";

const { mockFetchPendingTransactionIfExists, mockUploadTransaction } = vi.hoisted(() => ({
  mockFetchPendingTransactionIfExists: vi.fn(),
  mockUploadTransaction: vi.fn(),
}));

vi.mock("../transaction.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../transaction.js")>()),
  fetchPendingTransactionIfExists: mockFetchPendingTransactionIfExists,
  uploadTransaction: mockUploadTransaction,
}));

import {
  checkPsbtInputSighashes,
  checkPsbtInputsBelongToWallet,
  checkPsbtInputsOnChain,
  getPsbtTxId,
  importPsbt,
  normalizePsbtInput,
  parsePsbt,
  resolvePsbtInputScripts,
} from "../psbt-import.js";

// -- Fixtures: a single-key wsh(pk(...)) testnet wallet ----------------------------

const ROOT_TPRV =
  "tprv8ZgxMBicQKsPcsrtKiH9QjEKETBYXnT7hc5Rqcr4jmRDSxguKdSXKSdkBkPRk43YtBML3U2xJEj4dMo1832UwM46AnyVRNwnVNJHxBknYRs";
const rootKey = HDKey.fromExtendedKey(ROOT_TPRV, TESTNET_VERSIONS);
const signerKey = rootKey.derive("m/48'/1'/0'/2'");
const masterFingerprint = rootKey.fingerprint.toString(16).padStart(8, "0");
const signerDescriptor = `[${masterFingerprint}/48'/1'/0'/2']${signerKey.publicExtendedKey}`;
const body = `wsh(pk(${signerDescriptor}/<0;1>/*))`;
const DESCRIPTOR = `${body}#${descriptorChecksum(body)}`;
const parsed = parseDescriptor(DESCRIPTOR);

const WALLET: WalletData = {
  walletId: "w1import",
  groupId: "group-1",
  gid: "mrQ3kuD4AUt1S2H5HFhGk6LbpRGLDQkzLg",
  name: "Import wallet",
  m: parsed.m,
  n: parsed.n,
  addressType: parsed.addressType,
  descriptor: DESCRIPTOR,
  signers: parsed.signers,
  secretboxKey: "jnQRPI4//QSN8ti/4KUkcE0dt99/hDXIxwxCcDtKCiU=",
  createdAt: "2026-09-23T00:00:00.000Z",
};

const FUNDING_TXID = "11".repeat(32);

function walletPayment(chain: 0 | 1, index: number) {
  return deriveDescriptorPayment(DESCRIPTOR, "testnet", chain, index);
}

// Unsigned PSBT spending one wallet coin, filled like Nunchuk's FillPsbt (witnessUtxo +
// bip32Derivation + witnessScript).
function createWalletPsbt(opts: { chain?: 0 | 1; index?: number; withUtxo?: boolean } = {}) {
  const { chain = 0, index = 0, withUtxo = true } = opts;
  const payment = walletPayment(chain, index);
  const tx = new Transaction();
  tx.addInput({
    txid: FUNDING_TXID,
    index: 0,
    sequence: 0xfffffffd,
    ...(withUtxo ? { witnessUtxo: { amount: 50_000n, script: payment.script } } : {}),
    bip32Derivation: payment.bip32Derivation,
    witnessScript: payment.witnessScript,
  });
  tx.addOutputAddress(walletPayment(0, 9).address, 49_000n, TEST_NETWORK);
  return tx;
}

function signPsbt(tx: Transaction, chain: 0 | 1, index: number): Transaction {
  const child = signerKey.deriveChild(chain).deriveChild(index);
  tx.signIdx(child.privateKey!, 0);
  return tx;
}

function toB64(tx: Transaction): string {
  return Buffer.from(tx.toPSBT()).toString("base64");
}

function makeElectrum(overrides: Partial<Record<keyof ElectrumClient, unknown>> = {}) {
  return {
    listUnspentBatch: vi.fn(async () => [
      [{ tx_hash: FUNDING_TXID, tx_pos: 0, height: 1, value: 50_000 }],
    ]),
    getTransactionBatch: vi.fn(async () => []),
    ...overrides,
  } as unknown as ElectrumClient;
}

const client = {} as ApiClient;

// -- normalizePsbtInput --------------------------------------------------------

describe("normalizePsbtInput", () => {
  const psbtB64 = toB64(createWalletPsbt());
  const psbtBytes = Buffer.from(psbtB64, "base64");

  it("accepts a binary PSBT file", () => {
    expect(normalizePsbtInput(psbtBytes)).toBe(psbtB64);
  });

  it("accepts base64 text with surrounding whitespace and line wrapping", () => {
    const wrapped = psbtB64.match(/.{1,40}/g)!.join("\n");
    expect(normalizePsbtInput(Buffer.from(`  ${wrapped}\n`))).toBe(psbtB64);
  });

  it("accepts hex text", () => {
    expect(normalizePsbtInput(Buffer.from(psbtBytes.toString("hex").toUpperCase()))).toBe(psbtB64);
  });

  it("rejects a raw transaction hex with a dedicated error", () => {
    const raw = Buffer.from(createWalletPsbt().unsignedTx).toString("hex");
    expect(raw.startsWith("02000000")).toBe(true);
    expect(() => normalizePsbtInput(Buffer.from(raw))).toThrow(
      expect.objectContaining({ error: "RAW_TX_NOT_SUPPORTED" }),
    );
  });

  it("rejects an empty file and non-PSBT content", () => {
    expect(() => normalizePsbtInput(Buffer.from(""))).toThrow(
      expect.objectContaining({ error: "INVALID_PSBT" }),
    );
    expect(() => normalizePsbtInput(Buffer.from("hello world"))).toThrow(
      expect.objectContaining({ error: "INVALID_PSBT" }),
    );
    expect(() => normalizePsbtInput(Buffer.from("deadbeef"))).toThrow(
      expect.objectContaining({ error: "INVALID_PSBT" }),
    );
  });
});

// -- parsePsbt --------------------------------------------------------------------

describe("parsePsbt", () => {
  it("rejects PSBT v2 (unreadable by Nunchuk apps)", () => {
    const v2 = Buffer.from(createWalletPsbt().toPSBT(2)).toString("base64");
    expect(() => parsePsbt(v2)).toThrow(
      expect.objectContaining({
        error: "INVALID_PSBT",
        message: expect.stringContaining("version 2"),
      }),
    );
  });

  it("rejects undecodable input", () => {
    expect(() => parsePsbt(Buffer.from("cHNidP8BAA==", "base64").toString("base64"))).toThrow(
      expect.objectContaining({ error: "INVALID_PSBT" }),
    );
  });
});

// -- getPsbtTxId -------------------------------------------------------------------

describe("getPsbtTxId", () => {
  it("equals tx.id for an unsigned or native-segwit PSBT", () => {
    const tx = createWalletPsbt();
    expect(getPsbtTxId(tx)).toBe(tx.id);
    signPsbt(tx, 0, 0);
    tx.finalize();
    const reparsed = Transaction.fromPSBT(tx.toPSBT(), { allowUnknown: true });
    expect(getPsbtTxId(reparsed)).toBe(tx.id);
    expect(reparsed.id).toBe(tx.id);
  });

  it("equals the unsigned txid — not tx.id — for a finalized legacy PSBT", () => {
    // Legacy inputs carry the signature in scriptSig, so the final txid differs from
    // the unsigned one that libnunchuk (and the group server key) use.
    const key = HDKey.fromMasterSeed(new Uint8Array(32).fill(7)).derive("m/44'/1'/0'/0/0");
    const legacy = p2pkh(key.publicKey!, TEST_NETWORK);
    const funding = new Transaction({ allowUnknownOutputs: true });
    funding.addOutput({ script: legacy.script, amount: 100_000n });
    funding.addInput({ txid: "22".repeat(32), index: 0, finalScriptSig: new Uint8Array([0x51]) });
    const tx = new Transaction({ allowUnknownOutputs: true });
    tx.addInput({
      txid: funding.id,
      index: 0,
      ...legacy,
      nonWitnessUtxo: funding.toBytes(true, false),
    });
    tx.addOutput({ script: legacy.script, amount: 90_000n });
    const unsignedId = tx.id;

    tx.signIdx(key.privateKey!, 0);
    tx.finalize();
    const reparsed = Transaction.fromPSBT(tx.toPSBT(), { allowUnknown: true });

    expect(reparsed.id).not.toBe(unsignedId);
    expect(getPsbtTxId(reparsed)).toBe(unsignedId);
  });
});

// -- Input resolution & ownership ----------------------------------------------------

describe("resolvePsbtInputScripts / checkPsbtInputsBelongToWallet", () => {
  it("accepts a PSBT whose inputs carry witnessUtxo for wallet addresses", async () => {
    const tx = createWalletPsbt({ chain: 1, index: 3 });
    const inputs = await resolvePsbtInputScripts(tx, null);
    expect(checkPsbtInputsBelongToWallet(tx, inputs, WALLET, "testnet")).toEqual([]);
  });

  it("resolves the script from nonWitnessUtxo when witnessUtxo is absent", async () => {
    const payment = walletPayment(0, 2);
    const funding = new Transaction({ allowUnknownOutputs: true });
    funding.addOutput({ script: payment.script, amount: 50_000n });
    funding.addInput({ txid: "33".repeat(32), index: 0, finalScriptSig: new Uint8Array([0x51]) });
    const tx = new Transaction();
    tx.addInput({
      txid: funding.id,
      index: 0,
      nonWitnessUtxo: funding.toBytes(true, false),
      bip32Derivation: payment.bip32Derivation,
      witnessScript: payment.witnessScript,
    });
    tx.addOutputAddress(walletPayment(0, 9).address, 49_000n, TEST_NETWORK);

    const inputs = await resolvePsbtInputScripts(tx, null);
    expect(inputs[0].script).toEqual(payment.script);
    expect(checkPsbtInputsBelongToWallet(tx, inputs, WALLET, "testnet")).toEqual([]);
  });

  it("fetches the previous transaction from Electrum when the PSBT has no UTXO data", async () => {
    const payment = walletPayment(0, 0);
    const funding = new Transaction({ allowUnknownOutputs: true });
    funding.addOutput({ script: payment.script, amount: 50_000n });
    funding.addInput({ txid: "44".repeat(32), index: 0, finalScriptSig: new Uint8Array([0x51]) });
    const tx = new Transaction();
    tx.addInput({ txid: funding.id, index: 0, bip32Derivation: payment.bip32Derivation });
    tx.addOutputAddress(walletPayment(0, 9).address, 49_000n, TEST_NETWORK);

    const electrum = makeElectrum({
      getTransactionBatch: vi.fn(async () => [funding.hex]),
    });
    const inputs = await resolvePsbtInputScripts(tx, electrum);
    expect(electrum.getTransactionBatch).toHaveBeenCalledWith([funding.id]);
    expect(inputs[0].script).toEqual(payment.script);
    expect(inputs[0].amount).toBe(50_000n);
    expect(checkPsbtInputsBelongToWallet(tx, inputs, WALLET, "testnet")).toEqual([]);
  });

  it("ignores a previous transaction from Electrum that does not hash to the outpoint", async () => {
    const payment = walletPayment(0, 0);
    const real = new Transaction({ allowUnknownOutputs: true });
    real.addOutput({ script: payment.script, amount: 50_000n });
    real.addInput({ txid: "44".repeat(32), index: 0, finalScriptSig: new Uint8Array([0x51]) });
    // A different tx that also pays the wallet — a lying server could return it.
    const decoy = new Transaction({ allowUnknownOutputs: true });
    decoy.addOutput({ script: payment.script, amount: 50_000n });
    decoy.addInput({ txid: "55".repeat(32), index: 0, finalScriptSig: new Uint8Array([0x51]) });
    const tx = new Transaction();
    tx.addInput({ txid: real.id, index: 0 });
    tx.addOutputAddress(walletPayment(0, 9).address, 49_000n, TEST_NETWORK);

    const electrum = makeElectrum({ getTransactionBatch: vi.fn(async () => [decoy.hex]) });
    const inputs = await resolvePsbtInputScripts(tx, electrum);
    expect(inputs[0].script).toBeNull();
    expect(checkPsbtInputsBelongToWallet(tx, inputs, WALLET, "testnet")).toHaveLength(1);
  });

  it("reports an unresolvable input when there is no UTXO data and no chain", async () => {
    const tx = createWalletPsbt({ withUtxo: false });
    const inputs = await resolvePsbtInputScripts(tx, null);
    const problems = checkPsbtInputsBelongToWallet(tx, inputs, WALLET, "testnet");
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatchObject({
      inputIndex: 0,
      outpoint: `${FUNDING_TXID}:0`,
      reason: expect.stringContaining("could not be resolved"),
    });
  });

  it("reports inputs that belong to another wallet", async () => {
    const foreign = p2wpkh(
      HDKey.fromMasterSeed(new Uint8Array(32).fill(9)).derive("m/84'/1'/0'/0/0").publicKey!,
      TEST_NETWORK,
    );
    const tx = new Transaction();
    tx.addInput({
      txid: FUNDING_TXID,
      index: 5,
      witnessUtxo: { amount: 50_000n, script: foreign.script },
    });
    tx.addOutputAddress(walletPayment(0, 9).address, 49_000n, TEST_NETWORK);

    const inputs = await resolvePsbtInputScripts(tx, null);
    const problems = checkPsbtInputsBelongToWallet(tx, inputs, WALLET, "testnet");
    expect(problems).toEqual([
      {
        inputIndex: 0,
        outpoint: `${FUNDING_TXID}:5`,
        reason: `not an address of wallet ${WALLET.walletId}`,
      },
    ]);
  });
});

// -- Sighash ---------------------------------------------------------------------

describe("checkPsbtInputSighashes", () => {
  it("accepts unset and SIGHASH_ALL on a segwit input", async () => {
    const tx = createWalletPsbt();
    expect(checkPsbtInputSighashes(tx, await resolvePsbtInputScripts(tx, null))).toEqual([]);
    tx.updateInput(0, { sighashType: SignatureHash.ALL });
    expect(checkPsbtInputSighashes(tx, await resolvePsbtInputScripts(tx, null))).toEqual([]);
  });

  it("rejects SIGHASH_NONE and ANYONECANPAY flags", async () => {
    for (const flag of [SignatureHash.NONE, SignatureHash.ALL | SignatureHash.ANYONECANPAY]) {
      const tx = createWalletPsbt();
      tx.updateInput(0, { sighashType: flag });
      const problems = checkPsbtInputSighashes(tx, await resolvePsbtInputScripts(tx, null));
      expect(problems).toHaveLength(1);
      expect(problems[0]).toContain("not the canonical sighash");
    }
  });
});

// -- Chain check --------------------------------------------------------------------

describe("checkPsbtInputsOnChain", () => {
  it("reports outpoints missing from listunspent as spent", async () => {
    const tx = createWalletPsbt();
    const inputs = await resolvePsbtInputScripts(tx, null);
    const electrum = makeElectrum({ listUnspentBatch: vi.fn(async () => [[]]) });
    await expect(checkPsbtInputsOnChain(inputs, electrum)).resolves.toEqual({
      spent: [`${FUNDING_TXID}:0`],
      amountMismatch: [],
    });
  });

  it("passes when every input is unspent with the claimed amount", async () => {
    const tx = createWalletPsbt();
    const inputs = await resolvePsbtInputScripts(tx, null);
    await expect(checkPsbtInputsOnChain(inputs, makeElectrum())).resolves.toEqual({
      spent: [],
      amountMismatch: [],
    });
  });

  it("treats an outpoint that is unspent for a different script as spent (forged witnessUtxo)", async () => {
    // Two inputs claim different wallet scripts; the chain says the outpoint pays only
    // the second one. The first input's witnessUtxo is therefore a lie.
    const a = walletPayment(0, 0);
    const b = walletPayment(0, 1);
    const tx = new Transaction();
    tx.addInput({
      txid: FUNDING_TXID,
      index: 0,
      witnessUtxo: { amount: 50_000n, script: a.script },
    });
    tx.addInput({
      txid: FUNDING_TXID,
      index: 1,
      witnessUtxo: { amount: 50_000n, script: b.script },
    });
    tx.addOutputAddress(walletPayment(0, 9).address, 90_000n, TEST_NETWORK);
    const inputs = await resolvePsbtInputScripts(tx, null);
    const electrum = makeElectrum({
      listUnspentBatch: vi.fn(async () => [
        [], // script a owns nothing
        [
          { tx_hash: FUNDING_TXID, tx_pos: 0, height: 1, value: 50_000 }, // really pays b
          { tx_hash: FUNDING_TXID, tx_pos: 1, height: 1, value: 50_000 },
        ],
      ]),
    });
    await expect(checkPsbtInputsOnChain(inputs, electrum)).resolves.toEqual({
      spent: [`${FUNDING_TXID}:0`],
      amountMismatch: [],
    });
  });

  it("reports a claimed amount that differs from the chain", async () => {
    const tx = createWalletPsbt();
    const inputs = await resolvePsbtInputScripts(tx, null);
    const electrum = makeElectrum({
      listUnspentBatch: vi.fn(async () => [
        [{ tx_hash: FUNDING_TXID, tx_pos: 0, height: 1, value: 1_000_000 }],
      ]),
    });
    await expect(checkPsbtInputsOnChain(inputs, electrum)).resolves.toEqual({
      spent: [],
      amountMismatch: [`${FUNDING_TXID}:0 (PSBT says 50000 sat, chain says 1000000 sat)`],
    });
  });

  it("returns null when the chain query fails", async () => {
    const tx = createWalletPsbt();
    const inputs = await resolvePsbtInputScripts(tx, null);
    const electrum = makeElectrum({
      listUnspentBatch: vi.fn(async () => {
        throw new Error("timeout");
      }),
    });
    await expect(checkPsbtInputsOnChain(inputs, electrum)).resolves.toBeNull();
  });
});

// -- importPsbt orchestrator ------------------------------------------------------

describe("importPsbt", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUploadTransaction.mockResolvedValue(undefined);
  });

  it("creates the transaction on the server when it does not exist yet", async () => {
    mockFetchPendingTransactionIfExists.mockResolvedValue(null);
    const tx = createWalletPsbt();
    const psbtB64 = toB64(tx);

    const result = await importPsbt({
      client,
      wallet: WALLET,
      network: "testnet",
      psbtB64,
      electrum: makeElectrum(),
    });

    expect(result).toEqual({
      txId: tx.id,
      action: "created",
      psbtB64,
      updated: true,
      warnings: [],
    });
    expect(mockFetchPendingTransactionIfExists).toHaveBeenCalledWith(client, WALLET, tx.id);
    expect(mockUploadTransaction).toHaveBeenCalledWith(client, WALLET, psbtB64, tx.id);
  });

  it("merges into the existing pending transaction when the file adds a signature", async () => {
    const unsigned = createWalletPsbt();
    mockFetchPendingTransactionIfExists.mockResolvedValue({
      txId: unsigned.id,
      psbt: toB64(unsigned),
    });
    const signed = signPsbt(createWalletPsbt(), 0, 0);

    const result = await importPsbt({
      client,
      wallet: WALLET,
      network: "testnet",
      psbtB64: toB64(signed),
      electrum: makeElectrum(),
    });

    expect(result.action).toBe("merged");
    expect(result.updated).toBe(true);
    expect(mockUploadTransaction).toHaveBeenCalledTimes(1);
    const uploaded = Transaction.fromPSBT(
      Buffer.from(mockUploadTransaction.mock.calls[0][2] as string, "base64"),
      { allowUnknown: true },
    );
    expect((uploaded.getInput(0).partialSig ?? []).length).toBe(1);
  });

  it("reports unchanged and skips the upload when the server already has everything", async () => {
    const signed = signPsbt(createWalletPsbt(), 0, 0);
    mockFetchPendingTransactionIfExists.mockResolvedValue({ txId: signed.id, psbt: toB64(signed) });

    const result = await importPsbt({
      client,
      wallet: WALLET,
      network: "testnet",
      psbtB64: toB64(createWalletPsbt()),
      electrum: makeElectrum(),
    });

    expect(result.action).toBe("unchanged");
    expect(result.updated).toBe(false);
    expect(mockUploadTransaction).not.toHaveBeenCalled();
  });

  it("rejects a PSBT that does not belong to the wallet before touching the server", async () => {
    const foreign = p2wpkh(
      HDKey.fromMasterSeed(new Uint8Array(32).fill(9)).derive("m/84'/1'/0'/0/0").publicKey!,
      TEST_NETWORK,
    );
    const tx = new Transaction();
    tx.addInput({
      txid: FUNDING_TXID,
      index: 0,
      witnessUtxo: { amount: 50_000n, script: foreign.script },
    });
    tx.addOutputAddress(walletPayment(0, 9).address, 49_000n, TEST_NETWORK);

    await expect(
      importPsbt({
        client,
        wallet: WALLET,
        network: "testnet",
        psbtB64: toB64(tx),
        electrum: makeElectrum(),
      }),
    ).rejects.toMatchObject({
      error: "PSBT_WALLET_MISMATCH",
      message: expect.stringContaining(
        `input 0: ${FUNDING_TXID}:0 not an address of wallet ${WALLET.walletId}`,
      ),
    });
    expect(mockFetchPendingTransactionIfExists).not.toHaveBeenCalled();
    expect(mockUploadTransaction).not.toHaveBeenCalled();
  });

  it("rejects a PSBT whose inputs are already spent", async () => {
    const electrum = makeElectrum({ listUnspentBatch: vi.fn(async () => [[]]) });
    await expect(
      importPsbt({
        client,
        wallet: WALLET,
        network: "testnet",
        psbtB64: toB64(createWalletPsbt()),
        electrum,
      }),
    ).rejects.toMatchObject({
      error: "PSBT_INPUTS_SPENT",
      message: expect.stringContaining(`${FUNDING_TXID}:0`),
    });
    expect(mockUploadTransaction).not.toHaveBeenCalled();
  });

  it("rejects a PSBT with a non-canonical sighash flag before touching the server", async () => {
    const tx = createWalletPsbt();
    tx.updateInput(0, { sighashType: SignatureHash.NONE });
    await expect(
      importPsbt({
        client,
        wallet: WALLET,
        network: "testnet",
        psbtB64: toB64(tx),
        electrum: makeElectrum(),
      }),
    ).rejects.toMatchObject({ error: "PSBT_INVALID_SIGHASH" });
    expect(mockFetchPendingTransactionIfExists).not.toHaveBeenCalled();
    expect(mockUploadTransaction).not.toHaveBeenCalled();
  });

  it("rejects a PSBT whose input amount disagrees with the chain", async () => {
    const electrum = makeElectrum({
      listUnspentBatch: vi.fn(async () => [
        [{ tx_hash: FUNDING_TXID, tx_pos: 0, height: 1, value: 1_000_000 }],
      ]),
    });
    await expect(
      importPsbt({
        client,
        wallet: WALLET,
        network: "testnet",
        psbtB64: toB64(createWalletPsbt()),
        electrum,
      }),
    ).rejects.toMatchObject({ error: "PSBT_INPUT_AMOUNT_MISMATCH" });
    expect(mockUploadTransaction).not.toHaveBeenCalled();
  });

  it("skips the spent check with a warning when the chain is unavailable", async () => {
    mockFetchPendingTransactionIfExists.mockResolvedValue(null);
    const result = await importPsbt({
      client,
      wallet: WALLET,
      network: "testnet",
      psbtB64: toB64(createWalletPsbt()),
      electrum: null,
    });
    expect(result.action).toBe("created");
    expect(result.warnings).toEqual([expect.stringContaining("skipped the spent-input check")]);
  });

  it("propagates server errors other than not-found", async () => {
    mockFetchPendingTransactionIfExists.mockRejectedValue({
      error: "NETWORK_ERROR",
      message: "offline",
    });
    await expect(
      importPsbt({
        client,
        wallet: WALLET,
        network: "testnet",
        psbtB64: toB64(createWalletPsbt()),
        electrum: makeElectrum(),
      }),
    ).rejects.toEqual({ error: "NETWORK_ERROR", message: "offline" });
    expect(mockUploadTransaction).not.toHaveBeenCalled();
  });

  it("fails with PSBT_COMBINE_FAILED if the server holds a different transaction under that id", async () => {
    const other = createWalletPsbt();
    other.updateOutput(0, { amount: 48_000n }); // different outputs → different transaction
    expect(other.id).not.toBe(createWalletPsbt().id);
    mockFetchPendingTransactionIfExists.mockResolvedValue({ txId: "whatever", psbt: toB64(other) });
    await expect(
      importPsbt({
        client,
        wallet: WALLET,
        network: "testnet",
        psbtB64: toB64(createWalletPsbt()),
        electrum: makeElectrum(),
      }),
    ).rejects.toMatchObject({ error: "PSBT_COMBINE_FAILED" });
    expect(mockUploadTransaction).not.toHaveBeenCalled();
  });
});
