import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Transaction, TEST_NETWORK } from "@scure/btc-signer";
import { addressToScripthash } from "../electrum.js";
import { deriveDescriptorAddresses } from "../address.js";
import { buildWalletDescriptor } from "../descriptor.js";
import {
  _clearMasterKeyCache,
  _closeDatabase,
  _deleteAccountData,
  saveProfile,
} from "../storage.js";
import type { ElectrumClient } from "../electrum.js";
import type { Profile, WalletData } from "../storage.js";
import { listCoins, raiseStatus, type CoinStatus } from "../coins.js";

const TEST_RUN_ID = crypto.randomBytes(4).toString("hex");
const TEST_HOME = path.join(os.tmpdir(), "nunchuk-cli-coins", TEST_RUN_ID);
process.env.NUNCHUK_CLI_HOME = TEST_HOME;

const createdEmails: string[] = [];
let counter = 0;
function uniqueEmail(): string {
  const email = `coins-${TEST_RUN_ID}-${++counter}@test.local`;
  createdEmails.push(email);
  return email;
}

const FAKE_PROFILE: Profile = {
  apiKey: "k",
  email: "x",
  userId: "u",
  name: "n",
  ephemeralPub: "p",
  ephemeralPriv: "v",
};

const SIGNERS = [
  "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
];

const WALLET: WalletData = {
  walletId: "test-wallet",
  groupId: "g",
  gid: "gid",
  name: "Test",
  m: 2,
  n: 2,
  addressType: "NATIVE_SEGWIT",
  descriptor: buildWalletDescriptor(SIGNERS, 2, "NATIVE_SEGWIT"),
  signers: SIGNERS,
  secretboxKey: "",
  createdAt: "2025-01-01T00:00:00.000Z",
};

beforeEach(() => {
  _closeDatabase();
  _clearMasterKeyCache();
});

afterAll(() => {
  _closeDatabase();
  for (const email of createdEmails) _deleteAccountData(email);
  _closeDatabase();
  fs.rmSync(TEST_HOME, { recursive: true, force: true });
  delete process.env.NUNCHUK_CLI_HOME;
});

function createFundingHex(address: string, amount: bigint): { rawHex: string; txid: string } {
  const tx = new Transaction();
  tx.addInput({ txid: "00".repeat(32), index: 0, sequence: 0xfffffffd });
  tx.addOutputAddress(address, amount, TEST_NETWORK);
  return { rawHex: Buffer.from(tx.unsignedTx).toString("hex"), txid: tx.id };
}

interface MockUtxo {
  value: bigint;
  height: number;
  chain: 0 | 1;
  index: number;
}

function mockElectrum(utxos: MockUtxo[]): {
  electrum: ElectrumClient;
  outpoints: Array<{ txid: string; vout: number; address: string }>;
} {
  const utxoByAddress = new Map<
    string,
    { txid: string; rawHex: string; value: bigint; height: number }
  >();
  const outpoints: Array<{ txid: string; vout: number; address: string }> = [];

  for (const utxo of utxos) {
    const addr = deriveDescriptorAddresses(
      WALLET.descriptor,
      "testnet",
      utxo.chain,
      utxo.index,
      1,
    )[0];
    const { rawHex, txid } = createFundingHex(addr, utxo.value);
    utxoByAddress.set(addr, { txid, rawHex, value: utxo.value, height: utxo.height });
    outpoints.push({ txid, vout: 0, address: addr });
  }
  const scripthashToAddress = new Map<string, string>();
  for (const addr of utxoByAddress.keys()) {
    scripthashToAddress.set(addressToScripthash(addr, "testnet"), addr);
  }

  const listUnspent = vi.fn(async (hash: string) => {
    const addr = scripthashToAddress.get(hash);
    if (!addr) return [];
    const u = utxoByAddress.get(addr);
    if (!u) return [];
    return [{ tx_hash: u.txid, tx_pos: 0, height: u.height, value: Number(u.value) }];
  });
  const getHistory = vi.fn(async (hash: string) => {
    const addr = scripthashToAddress.get(hash);
    if (!addr) return [];
    const u = utxoByAddress.get(addr);
    return u ? [{ tx_hash: u.txid, height: u.height }] : [];
  });

  // 80-byte header whose timestamp field (bytes 68–71, little-endian) encodes
  // a deterministic per-height time: 1_700_000_000 + height.
  const headerForHeight = (height: number): string => {
    const timestamp = Buffer.alloc(4);
    timestamp.writeUInt32LE(1_700_000_000 + height, 0);
    return "00".repeat(68) + timestamp.toString("hex") + "00".repeat(8);
  };

  return {
    electrum: {
      headersSubscribe: vi.fn(async () => ({ height: 850_000, hex: "00".repeat(80) })),
      listUnspent,
      listUnspentBatch: vi.fn(async (hashes: string[]) => Promise.all(hashes.map(listUnspent))),
      getHistory,
      getHistoryBatch: vi.fn(async (hashes: string[]) => Promise.all(hashes.map(getHistory))),
      getBlockHeaderBatch: vi.fn(async (heights: number[]) => heights.map(headerForHeight)),
    } as unknown as ElectrumClient,
    outpoints,
  };
}

describe("raiseStatus", () => {
  it("only promotes upward in the libnunchuk status order", () => {
    const cases: Array<[CoinStatus, CoinStatus, CoinStatus]> = [
      ["CONFIRMED", "OUTGOING_PENDING_SIGNATURES", "OUTGOING_PENDING_SIGNATURES"],
      ["OUTGOING_PENDING_SIGNATURES", "CONFIRMED", "OUTGOING_PENDING_SIGNATURES"],
      ["OUTGOING_PENDING_BROADCAST", "OUTGOING_PENDING_SIGNATURES", "OUTGOING_PENDING_BROADCAST"],
      ["INCOMING_PENDING_CONFIRMATION", "CONFIRMED", "CONFIRMED"],
      ["CONFIRMED", "CONFIRMED", "CONFIRMED"],
    ];
    for (const [current, candidate, expected] of cases) {
      expect(raiseStatus(current, candidate)).toBe(expected);
    }
  });
});

describe("listCoins", () => {
  it("returns CONFIRMED for confirmed UTXOs and INCOMING_PENDING_CONFIRMATION for unconfirmed", async () => {
    const email = uniqueEmail();
    saveProfile(email, "testnet", { ...FAKE_PROFILE, email });
    const { electrum } = mockElectrum([
      { value: 100_000n, height: 100, chain: 0, index: 0 },
      { value: 50_000n, height: 0, chain: 0, index: 1 }, // unconfirmed
    ]);
    const coins = await listCoins({ wallet: WALLET, network: "testnet", electrum });
    expect(coins).toHaveLength(2);
    const byHeight = Object.fromEntries(coins.map((c) => [c.height, c.status]));
    expect(byHeight[100]).toBe("CONFIRMED");
    expect(byHeight[0]).toBe("INCOMING_PENDING_CONFIRMATION");
  });

  it("marks isChange when chain === 1", async () => {
    const email = uniqueEmail();
    saveProfile(email, "testnet", { ...FAKE_PROFILE, email });
    const { electrum } = mockElectrum([{ value: 100_000n, height: 100, chain: 1, index: 0 }]);
    const coins = await listCoins({ wallet: WALLET, network: "testnet", electrum });
    expect(coins).toHaveLength(1);
    expect(coins[0].isChange).toBe(true);
  });

  it("computes confirmations relative to the chain tip", async () => {
    const email = uniqueEmail();
    saveProfile(email, "testnet", { ...FAKE_PROFILE, email });
    const { electrum } = mockElectrum([{ value: 100_000n, height: 849_991, chain: 0, index: 0 }]);
    const coins = await listCoins({ wallet: WALLET, network: "testnet", electrum });
    // tip = 850_000 → confirmations = 850_000 - 849_991 + 1 = 10
    expect(coins[0].confirmations).toBe(10);
  });

  it("resolves the confirmation block time; unconfirmed coins get 0", async () => {
    const email = uniqueEmail();
    saveProfile(email, "testnet", { ...FAKE_PROFILE, email });
    const { electrum } = mockElectrum([
      { value: 100_000n, height: 100, chain: 0, index: 0 },
      { value: 50_000n, height: 0, chain: 0, index: 1 }, // unconfirmed
    ]);
    const coins = await listCoins({ wallet: WALLET, network: "testnet", electrum });
    const byHeight = Object.fromEntries(coins.map((c) => [c.height, c.blocktime]));
    expect(byHeight[100]).toBe(1_700_000_100);
    expect(byHeight[0]).toBe(0);
  });

  it("leaves blocktime 0 when headers cannot be fetched", async () => {
    const email = uniqueEmail();
    saveProfile(email, "testnet", { ...FAKE_PROFILE, email });
    const { electrum } = mockElectrum([{ value: 100_000n, height: 100, chain: 0, index: 0 }]);
    (electrum as unknown as { getBlockHeaderBatch: unknown }).getBlockHeaderBatch = vi.fn(
      async () => {
        throw new Error("unsupported");
      },
    );
    const coins = await listCoins({ wallet: WALLET, network: "testnet", electrum });
    expect(coins[0].blocktime).toBe(0);
  });
});
