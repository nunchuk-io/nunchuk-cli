import { describe, expect, it, vi } from "vitest";
import { HDKey } from "@scure/bip32";
import { Transaction, TEST_NETWORK } from "@scure/btc-signer";
import { deriveDescriptorAddresses, TESTNET_VERSIONS } from "../address.js";
import { addressToScripthash } from "../electrum.js";
import { buildMiniscriptDescriptor } from "../miniscript.js";
import { finalizeMiniscriptPsbt } from "../miniscript-finalize.js";
import { signWalletPsbtWithKey } from "../psbt-sign.js";
import { createTransaction, decodePsbtDetail } from "../transaction.js";
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
const TEST_SIGNER_0_XPRV =
  "tprv8ZgxMBicQKsPcsrtKiH9QjEKETBYXnT7hc5Rqcr4jmRDSxguKdSXKSdkBkPRk43YtBML3U2xJEj4dMo1832UwM46AnyVRNwnVNJHxBknYRs";

const TEST_XFP = 0x8317a853;
const TEST_XFP_0 = 0xb9a14f1a;

type TimelockEndToEndCase = {
  currentHeight?: number;
  currentUnixTime?: number;
  descriptor: string;
  expectedLockTime: number;
  expectedSequence: number;
  expectedTimelockedUntil: {
    based: "HEIGHT_LOCK" | "TIME_LOCK";
    mature: boolean;
    value: number;
  };
  fundingBlocktime?: number;
  fundingHeight?: number;
  name: string;
  signerIndex: 0 | 1;
  walletSigners: string[];
};

const RELATIVE_TIME_SEQUENCE = 0x400000 | 7;
const RELATIVE_TIME_BLOCKTIME = 1_700_000_000;
const RELATIVE_TIME_SECONDS = 7 * 512;

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

function signWithKnownTestSigner(tx: Transaction, signerIndex: 0 | 1, descriptor: string): number {
  if (signerIndex === 0) {
    return signWalletPsbtWithKey(
      tx,
      HDKey.fromExtendedKey(TEST_SIGNER_0_XPRV, TESTNET_VERSIONS),
      TEST_XFP_0,
      descriptor,
    );
  }
  return signWalletPsbtWithKey(
    tx,
    HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS),
    TEST_XFP,
    descriptor,
  );
}

const TIMELOCK_END_TO_END_CASES: TimelockEndToEndCase[] = [
  {
    currentHeight: 143,
    descriptor: buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),after(144))`,
      "NATIVE_SEGWIT",
    ),
    expectedLockTime: 144,
    expectedSequence: 0xfffffffd,
    expectedTimelockedUntil: {
      based: "HEIGHT_LOCK",
      mature: false,
      value: 144,
    },
    name: "absolute height locks",
    signerIndex: 0,
    walletSigners: [TEST_WALLET.signers[0]],
  },
  {
    currentUnixTime: 2_100_000_000 - 1,
    descriptor: buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),after(2100000000))`,
      "NATIVE_SEGWIT",
    ),
    expectedLockTime: 2_100_000_000,
    expectedSequence: 0xfffffffd,
    expectedTimelockedUntil: {
      based: "TIME_LOCK",
      mature: false,
      value: 2_100_000_000,
    },
    name: "absolute time locks",
    signerIndex: 1,
    walletSigners: [TEST_WALLET.signers[1]],
  },
  {
    currentHeight: 105,
    descriptor: buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(10))`,
      "NATIVE_SEGWIT",
    ),
    expectedLockTime: 0,
    expectedSequence: 10,
    expectedTimelockedUntil: {
      based: "HEIGHT_LOCK",
      mature: false,
      value: 110,
    },
    fundingHeight: 100,
    name: "relative height locks",
    signerIndex: 1,
    walletSigners: [TEST_WALLET.signers[1]],
  },
  {
    currentUnixTime: RELATIVE_TIME_BLOCKTIME + RELATIVE_TIME_SECONDS - 1,
    descriptor: buildMiniscriptDescriptor(
      `and_v(v:pk(${TEST_WALLET.signers[1]}/<0;1>/*),older(${RELATIVE_TIME_SEQUENCE}))`,
      "NATIVE_SEGWIT",
    ),
    expectedLockTime: 0,
    expectedSequence: RELATIVE_TIME_SEQUENCE,
    expectedTimelockedUntil: {
      based: "TIME_LOCK",
      mature: false,
      value: RELATIVE_TIME_BLOCKTIME + RELATIVE_TIME_SECONDS,
    },
    fundingBlocktime: RELATIVE_TIME_BLOCKTIME,
    fundingHeight: 100,
    name: "relative time locks",
    signerIndex: 1,
    walletSigners: [TEST_WALLET.signers[1]],
  },
];

describe("miniscript timelock end-to-end", () => {
  it.each(TIMELOCK_END_TO_END_CASES)("supports $name", async (tc) => {
    const wallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor: tc.descriptor,
      signers: tc.walletSigners,
    };
    const { electrum, txid } = createMiniscriptElectrumMock(
      tc.descriptor,
      50_000n,
      tc.fundingHeight,
      tc.fundingBlocktime,
    );
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

      expect(tx.lockTime).toBe(tc.expectedLockTime);
      expect(tx.getInput(0).sequence).toBe(tc.expectedSequence);
      expect(signWithKnownTestSigner(tx, tc.signerIndex, wallet.descriptor)).toBe(1);

      const psbtB64 = Buffer.from(tx.toPSBT()).toString("base64");
      const inputUtxos =
        tc.fundingHeight === undefined
          ? undefined
          : [
              {
                txHash: txid,
                txPos: 0,
                height: tc.fundingHeight,
                blocktime: tc.fundingBlocktime,
              },
            ];
      const detail = decodePsbtDetail(
        psbtB64,
        "testnet",
        wallet.m,
        wallet.signers,
        wallet.descriptor,
        {
          currentHeight: tc.currentHeight,
          currentUnixTime: tc.currentUnixTime,
          inputUtxos,
        },
      );

      expect(detail?.status).toBe("READY_TO_BROADCAST");
      expect(detail?.signedCount).toBe(1);
      expect(detail?.requiredCount).toBe(1);
      expect(detail?.timelockedUntil).toEqual(tc.expectedTimelockedUntil);

      expect(finalizeMiniscriptPsbt(tx, wallet.descriptor, "testnet")).toMatchObject({
        requiredSignatures: 1,
      });
      expect(tx.isFinal).toBe(true);
      expect(() => tx.extract()).not.toThrow();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
