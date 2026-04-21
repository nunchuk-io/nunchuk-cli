import { describe, expect, it, vi } from "vitest";
import { HDKey } from "@scure/bip32";
import { hex } from "@scure/base";
import { Transaction, TEST_NETWORK } from "@scure/btc-signer";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { deriveDescriptorAddresses, TESTNET_VERSIONS } from "../address.js";
import { addressToScripthash } from "../electrum.js";
import { buildMiniscriptDescriptor } from "../miniscript.js";
import { finalizeMiniscriptPsbt } from "../miniscript-finalize.js";
import { signWalletPsbtWithKey } from "../psbt-sign.js";
import {
  combinePendingPsbt,
  createTransaction,
  decodePsbtDetail,
  fetchPendingTxInputTimelockMetadataBatch,
  fetchPsbtInputTimelockMetadata,
} from "../transaction.js";
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
});

describe("createTransaction miniscript", () => {
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
