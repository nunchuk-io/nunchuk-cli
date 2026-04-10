import { describe, expect, it, vi } from "vitest";
import { HDKey } from "@scure/bip32";
import { hex } from "@scure/base";
import { Transaction, TEST_NETWORK } from "@scure/btc-signer";
import { sha256 } from "@noble/hashes/sha2.js";
import { deriveDescriptorAddresses, TESTNET_VERSIONS } from "../address.js";
import { addressToScripthash } from "../electrum.js";
import { buildMiniscriptDescriptor, MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT } from "../miniscript.js";
import { finalizeMiniscriptPsbt } from "../miniscript-finalize.js";
import { signWalletPsbtWithKey } from "../psbt-sign.js";
import { combinePendingPsbt, createTransaction, decodePsbtDetail } from "../transaction.js";
import { createDummyPsbt } from "../platform-key.js";
import { buildWalletDescriptor } from "../descriptor.js";
import type { WalletData } from "../storage.js";
import type { ElectrumClient } from "../electrum.js";

const TEST_WALLET: WalletData = {
  walletId: "207u9ts4",
  groupId: "883409fe-511d-4ae7-92bf-250b5bd6ce45",
  gid: "mrQ3kuD4AUt1S2H5HFhGk6LbpRGLDQkzLg",
  name: "Wallet 1",
  m: 2,
  n: 3,
  addressType: 3,
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

const TEST_XPRV =
  "tprv8indigs9s1wXrGCnzFR8m65FU1BmZ7UMR8TqVArSk3KegTFipNCWQJenF45BjmrcPXXfNjyx5NrsU1gEd5BKYog9dEHuu7YqWB7HUt7AuzM";

const TEST_XFP = 0x8317a853;

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

function createFundingHex(address: string, amount: bigint): { rawHex: string; txid: string } {
  const tx = new Transaction();
  tx.addInput({ txid: "00".repeat(32), index: 0, sequence: 0xfffffffd });
  tx.addOutputAddress(address, amount, TEST_NETWORK);
  return {
    rawHex: Buffer.from(tx.unsignedTx).toString("hex"),
    txid: tx.id,
  };
}

function createMiniscriptElectrumMock(
  descriptor: string,
  fundingAmount: bigint,
  height = 200,
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
    } as unknown as ElectrumClient,
  };
}

describe("createTransaction miniscript", () => {
  it("uses absolute timelocks as transaction locktime", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),after(144))`,
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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

  it("keeps a future-locktime miniscript branch pending until the locktime matures", async () => {
    const futureLocktime = 2_100_000_000;
    const descriptor = buildMiniscriptDescriptor(
      `or_d(pk(${TEST_WALLET.signers[0]}/<0;1>/*),and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),after(${futureLocktime})))`,
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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

      expect(detail?.status).toBe("PENDING_LOCKTIME");
      expect(detail?.signedCount).toBe(1);
      expect(detail?.requiredCount).toBe(1);
      expect(detail?.miniscriptPath).toMatchObject({
        index: 1,
        lockTime: futureLocktime,
        requiredSignatures: 1,
        signerNames: [`${TEST_WALLET.signers[1]}/<0;1>/*`],
      });
      expect(detail?.signers["b9a14f1a"]).toBe(false);
      expect(detail?.signers["8317a853"]).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("signs miniscript PSBT inputs with the local fallback signer", async () => {
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),pk(${TEST_WALLET.signers[1]}/<0;1>/*))`,
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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
      `and_v(v:multi(2,${TEST_WALLET.signers[0]}/<0;1>/*,${TEST_WALLET.signers[1]}/<0;1>/*,${TEST_WALLET.signers[2]}/<0;1>/*),after(1))`,
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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
      const secondSigner = HDKey.fromExtendedKey(
        "tprv8ZgxMBicQKsPcsrtKiH9QjEKETBYXnT7hc5Rqcr4jmRDSxguKdSXKSdkBkPRk43YtBML3U2xJEj4dMo1832UwM46AnyVRNwnVNJHxBknYRs",
        TESTNET_VERSIONS,
      );
      expect(signWalletPsbtWithKey(tx, secondSigner, 0xb9a14f1a, wallet.descriptor)).toBe(1);
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

  it("finalizes miniscript PSBTs that require a hash preimage", async () => {
    const preimage = new Uint8Array(32).fill(7);
    const preimageHex = hex.encode(preimage);
    const digest = hex.encode(sha256(preimage));
    const descriptor = buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),sha256(${digest}))`,
      MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
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
      const withoutPreimage = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
      });
      const unsignedTx = Transaction.fromPSBT(Buffer.from(withoutPreimage.psbtB64, "base64"));
      expect(signWalletPsbtWithKey(unsignedTx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);
      expect(() => finalizeMiniscriptPsbt(unsignedTx, wallet.descriptor, "testnet")).toThrow(
        "Not enough signatures or hash preimages to finalize miniscript PSBT",
      );

      const withPreimage = await createTransaction({
        wallet,
        network: "testnet",
        electrum,
        toAddress: TEST_RECIPIENT,
        amount: 10_000n,
        preimages: [preimageHex],
      });
      const tx = Transaction.fromPSBT(Buffer.from(withPreimage.psbtB64, "base64"));

      expect(withPreimage.miniscriptPath).toMatchObject({
        preimageRequirements: [{ hash: digest, type: "SHA256" }],
        requiredSignatures: 1,
      });
      expect((tx.getInput(0).sha256 ?? []).length).toBe(1);
      expect(signWalletPsbtWithKey(tx, signerKey, TEST_XFP, wallet.descriptor)).toBe(1);
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
      expect(detail?.miniscriptPath?.preimageRequirements).toEqual([
        { hash: digest, type: "SHA256" },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
