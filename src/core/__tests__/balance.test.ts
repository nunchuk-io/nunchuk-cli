import { describe, it, expect, vi } from "vitest";
import { getNextReceiveAddress, getWalletBalance, scanUtxos } from "../transaction.js";
import { deriveAddresses, deriveDescriptorAddresses } from "../address.js";
import { buildWalletDescriptor } from "../descriptor.js";
import { buildMiniscriptDescriptor, MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT } from "../miniscript.js";
import { addressToScripthash } from "../electrum.js";
import type { WalletData } from "../storage.js";
import type { ElectrumClient, HistoryItem, ScripthashBalance, UnspentItem } from "../electrum.js";

// Test signers — same as descriptor.test.ts
const TEST_SIGNERS = [
  "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
];

const TEST_WALLET: WalletData = {
  walletId: "testid",
  groupId: "group1",
  gid: "gid1",
  name: "Test Wallet",
  m: 2,
  n: 2,
  addressType: 3, // NATIVE_SEGWIT
  descriptor: buildWalletDescriptor(TEST_SIGNERS, 2, 3),
  signers: TEST_SIGNERS,
  secretboxKey: "",
  createdAt: "2025-01-01T00:00:00.000Z",
};

const TEST_MINISCRIPT_DESCRIPTOR = buildMiniscriptDescriptor(
  `and_v(v:pk(${TEST_SIGNERS[0]}/<0;1>/*),pk(${TEST_SIGNERS[1]}/<0;1>/*))`,
  MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
);

const TEST_MINISCRIPT_WALLET: WalletData = {
  ...TEST_WALLET,
  walletId: "testid-miniscript",
  name: "Test Miniscript Wallet",
  m: 0,
  descriptor: TEST_MINISCRIPT_DESCRIPTOR,
};

// Pre-derive real scripthashes for known addresses so mock can match them
function getScripthash(chain: 0 | 1, index: number): string {
  const addrs = deriveAddresses(TEST_SIGNERS, 2, 3, "testnet", chain, index, 1);
  return addressToScripthash(addrs[0], "testnet");
}

function getMiniscriptScripthash(chain: 0 | 1, index: number): string {
  const addrs = deriveDescriptorAddresses(TEST_MINISCRIPT_DESCRIPTOR, "testnet", chain, index, 1);
  return addressToScripthash(addrs[0], "testnet");
}

function createMockElectrum(
  balanceMap: Record<string, ScripthashBalance>,
  historyMap: Record<string, HistoryItem[]> = {},
): ElectrumClient {
  const getHistory = vi.fn(async (scripthash: string) => {
    if (historyMap[scripthash]) {
      return historyMap[scripthash];
    }
    const balance = balanceMap[scripthash];
    if (balance && (balance.confirmed !== 0 || balance.unconfirmed !== 0)) {
      return [{ tx_hash: `tx-${scripthash}`, height: 1 }];
    }
    return [];
  });
  const getBalance = vi.fn(async (scripthash: string) => {
    return balanceMap[scripthash] ?? { confirmed: 0, unconfirmed: 0 };
  });

  return {
    getHistory,
    getHistoryBatch: vi.fn(async (scripthashes: string[]) =>
      Promise.all(scripthashes.map(getHistory)),
    ),
    getBalance,
    getBalanceBatch: vi.fn(async (scripthashes: string[]) =>
      Promise.all(scripthashes.map(getBalance)),
    ),
  } as unknown as ElectrumClient;
}

function createMockUtxoElectrum(
  unspentMap: Record<string, UnspentItem[]>,
  historyMap: Record<string, HistoryItem[]> = {},
): ElectrumClient {
  const getHistory = vi.fn(async (scripthash: string) => {
    if (historyMap[scripthash]) {
      return historyMap[scripthash];
    }
    if ((unspentMap[scripthash] ?? []).length > 0) {
      return [{ tx_hash: `tx-${scripthash}`, height: 1 }];
    }
    return [];
  });
  const listUnspent = vi.fn(async (scripthash: string) => unspentMap[scripthash] ?? []);

  return {
    getHistory,
    getHistoryBatch: vi.fn(async (scripthashes: string[]) =>
      Promise.all(scripthashes.map(getHistory)),
    ),
    listUnspent,
    listUnspentBatch: vi.fn(async (scripthashes: string[]) =>
      Promise.all(scripthashes.map(listUnspent)),
    ),
  } as unknown as ElectrumClient;
}

function createMockHistoryElectrum(
  historyMap: Record<string, Array<{ tx_hash: string; height: number }>>,
): ElectrumClient {
  const getHistory = vi.fn(async (scripthash: string) => {
    return historyMap[scripthash] ?? [];
  });

  return {
    getHistory,
    getHistoryBatch: vi.fn(async (scripthashes: string[]) =>
      Promise.all(scripthashes.map(getHistory)),
    ),
  } as unknown as ElectrumClient;
}

describe("getWalletBalance", () => {
  it("returns 0 for empty wallet", async () => {
    const electrum = createMockElectrum({});
    const balance = await getWalletBalance(TEST_WALLET, "testnet", electrum);
    expect(balance).toBe(0n);
  });

  it("sums confirmed balance from receive addresses", async () => {
    const sh0 = getScripthash(0, 0);
    const sh1 = getScripthash(0, 3);
    const electrum = createMockElectrum({
      [sh0]: { confirmed: 50000, unconfirmed: 0 },
      [sh1]: { confirmed: 30000, unconfirmed: 0 },
    });

    const balance = await getWalletBalance(TEST_WALLET, "testnet", electrum);
    expect(balance).toBe(80000n);
  });

  it("sums confirmed balance from change addresses", async () => {
    const sh = getScripthash(1, 2);
    const electrum = createMockElectrum({
      [sh]: { confirmed: 100000, unconfirmed: 0 },
    });

    const balance = await getWalletBalance(TEST_WALLET, "testnet", electrum);
    expect(balance).toBe(100000n);
  });

  it("includes unconfirmed balance in total", async () => {
    const sh = getScripthash(0, 0);
    const electrum = createMockElectrum({
      [sh]: { confirmed: 200000, unconfirmed: 50000 },
    });

    const balance = await getWalletBalance(TEST_WALLET, "testnet", electrum);
    expect(balance).toBe(250000n);
  });

  it("handles negative unconfirmed (spending from mempool)", async () => {
    const sh = getScripthash(0, 0);
    const electrum = createMockElectrum({
      [sh]: { confirmed: 200000, unconfirmed: -50000 },
    });

    const balance = await getWalletBalance(TEST_WALLET, "testnet", electrum);
    expect(balance).toBe(150000n);
  });

  it("sums across receive and change chains", async () => {
    const shReceive = getScripthash(0, 0);
    const shChange = getScripthash(1, 0);
    const electrum = createMockElectrum({
      [shReceive]: { confirmed: 100000, unconfirmed: 0 },
      [shChange]: { confirmed: 25000, unconfirmed: 10000 },
    });

    const balance = await getWalletBalance(TEST_WALLET, "testnet", electrum);
    expect(balance).toBe(135000n);
  });

  it("respects gap limit — stops after 20 consecutive empty addresses", async () => {
    // Put balance only at index 0, nothing else
    const sh = getScripthash(0, 0);
    const electrum = createMockElectrum({
      [sh]: { confirmed: 42000, unconfirmed: 0 },
    });

    const balance = await getWalletBalance(TEST_WALLET, "testnet", electrum);
    expect(balance).toBe(42000n);

    // Should have called getBalance for:
    // chain 0: index 0 (hit) + 20 empty = 21 calls
    // chain 1: 20 empty = 20 calls
    // Total = 41 calls
    expect(electrum.getHistory).toHaveBeenCalledTimes(41);
    expect(electrum.getBalance).toHaveBeenCalledTimes(1);
  });

  it("resets gap counter on non-empty address", async () => {
    // Balance at index 0 and index 19 (just before gap limit would stop)
    const sh0 = getScripthash(0, 0);
    const sh19 = getScripthash(0, 19);
    const electrum = createMockElectrum({
      [sh0]: { confirmed: 10000, unconfirmed: 0 },
      [sh19]: { confirmed: 5000, unconfirmed: 0 },
    });

    const balance = await getWalletBalance(TEST_WALLET, "testnet", electrum);
    expect(balance).toBe(15000n);

    // chain 0: index 0 (hit) + 18 empty + index 19 (hit) + 20 empty = 40 calls
    // chain 1: 20 empty = 20 calls
    // Total = 60 calls
    expect(electrum.getHistory).toHaveBeenCalledTimes(60);
    expect(electrum.getBalance).toHaveBeenCalledTimes(2);
  });

  it("supports miniscript wallets", async () => {
    const shReceive = getMiniscriptScripthash(0, 0);
    const shChange = getMiniscriptScripthash(1, 1);
    const electrum = createMockElectrum({
      [shReceive]: { confirmed: 42000, unconfirmed: 1000 },
      [shChange]: { confirmed: 5000, unconfirmed: 0 },
    });

    const balance = await getWalletBalance(TEST_MINISCRIPT_WALLET, "testnet", electrum);
    expect(balance).toBe(48000n);
  });

  it("does not stop at spent addresses before a funded later index", async () => {
    const historyMap: Record<string, HistoryItem[]> = {};
    for (let index = 0; index < 20; index++) {
      historyMap[getMiniscriptScripthash(0, index)] = [{ tx_hash: `spent-${index}`, height: 1 }];
    }

    const funded = getMiniscriptScripthash(0, 20);
    historyMap[funded] = [{ tx_hash: "funded", height: 1 }];
    const electrum = createMockElectrum(
      {
        [funded]: { confirmed: 12345, unconfirmed: 0 },
      },
      historyMap,
    );

    const balance = await getWalletBalance(TEST_MINISCRIPT_WALLET, "testnet", electrum);
    expect(balance).toBe(12345n);
  });
});

describe("scanUtxos", () => {
  it("does not stop at spent addresses before a later UTXO", async () => {
    const historyMap: Record<string, HistoryItem[]> = {};
    for (let index = 0; index < 20; index++) {
      historyMap[getMiniscriptScripthash(0, index)] = [{ tx_hash: `spent-${index}`, height: 1 }];
    }

    const funded = getMiniscriptScripthash(0, 20);
    historyMap[funded] = [{ tx_hash: "funded", height: 1 }];
    const electrum = createMockUtxoElectrum(
      {
        [funded]: [{ tx_hash: "funded", tx_pos: 0, height: 1, value: 6789 }],
      },
      historyMap,
    );

    const result = await scanUtxos(TEST_MINISCRIPT_WALLET, "testnet", electrum);
    expect(result.utxos).toHaveLength(1);
    expect(result.utxos[0]).toMatchObject({
      txHash: "funded",
      txPos: 0,
      value: 6789n,
      chain: 0,
      index: 20,
    });
  });

  it("records the address index for a UTXO at a non-zero batch offset", async () => {
    const funded = getMiniscriptScripthash(0, 5);
    const electrum = createMockUtxoElectrum({
      [funded]: [{ tx_hash: "funded-offset", tx_pos: 1, height: 1, value: 6789 }],
    });

    const result = await scanUtxos(TEST_MINISCRIPT_WALLET, "testnet", electrum);
    expect(result.utxos).toHaveLength(1);
    expect(result.utxos[0]).toMatchObject({
      txHash: "funded-offset",
      txPos: 1,
      value: 6789n,
      chain: 0,
      index: 5,
    });
  });

  it("advances change index past spent change addresses", async () => {
    const spentChange = getMiniscriptScripthash(1, 0);
    const electrum = createMockUtxoElectrum(
      {},
      {
        [spentChange]: [{ tx_hash: "spent-change", height: 1 }],
      },
    );

    const result = await scanUtxos(TEST_MINISCRIPT_WALLET, "testnet", electrum);
    expect(result.nextChangeIndex).toBe(1);
  });
});

describe("getNextReceiveAddress", () => {
  it("returns index 0 when no receive address has history", async () => {
    const electrum = createMockHistoryElectrum({});
    const result = await getNextReceiveAddress(TEST_WALLET, "testnet", electrum);
    expect(result.index).toBe(0);
    expect(result.address).toBe(deriveAddresses(TEST_SIGNERS, 2, 3, "testnet", 0, 0, 1)[0]);
  });

  it("returns the next index after the highest used receive address", async () => {
    const sh0 = getScripthash(0, 0);
    const sh2 = getScripthash(0, 2);
    const electrum = createMockHistoryElectrum({
      [sh0]: [{ tx_hash: "tx0", height: 1 }],
      [sh2]: [{ tx_hash: "tx2", height: 2 }],
    });

    const result = await getNextReceiveAddress(TEST_WALLET, "testnet", electrum);
    expect(result.index).toBe(3);
    expect(result.address).toBe(deriveAddresses(TEST_SIGNERS, 2, 3, "testnet", 0, 3, 1)[0]);
  });

  it("supports miniscript wallets", async () => {
    const sh0 = getMiniscriptScripthash(0, 0);
    const sh1 = getMiniscriptScripthash(0, 1);
    const electrum = createMockHistoryElectrum({
      [sh0]: [{ tx_hash: "tx0", height: 1 }],
      [sh1]: [{ tx_hash: "tx1", height: 2 }],
    });

    const result = await getNextReceiveAddress(TEST_MINISCRIPT_WALLET, "testnet", electrum);
    expect(result.index).toBe(2);
    expect(result.address).toBe(
      deriveDescriptorAddresses(TEST_MINISCRIPT_DESCRIPTOR, "testnet", 0, 2, 1)[0],
    );
  });
});
