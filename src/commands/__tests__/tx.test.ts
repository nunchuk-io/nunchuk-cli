import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WalletData } from "../../core/storage.js";

const {
  mockCombinePendingPsbt,
  mockCreateTransaction,
  mockDecodePsbtDetail,
  mockEstimateFeeRateLevels,
  mockFetchPsbtInputTimelockMetadata,
  mockFetchPendingTransaction,
  mockGetDefaultFeeLevel,
  mockGetLockedOutpoints,
  mockGetOutpointsByCollection,
  mockGetOutpointsByTag,
  mockPlanChangeTags,
  mockReconcileNewCoins,
  mockStoreChangeTagIntent,
  mockHeadersSubscribe,
  mockImportPsbt,
  mockLoadWallet,
  mockReadPsbtFile,
  mockRemoveMusigNonce,
  mockUploadTransaction,
} = vi.hoisted(() => ({
  mockCombinePendingPsbt: vi.fn(),
  mockCreateTransaction: vi.fn(),
  mockDecodePsbtDetail: vi.fn(),
  mockEstimateFeeRateLevels: vi.fn(),
  mockFetchPsbtInputTimelockMetadata: vi.fn(),
  mockFetchPendingTransaction: vi.fn(),
  mockGetDefaultFeeLevel: vi.fn(),
  mockGetLockedOutpoints: vi.fn(() => new Set<string>()),
  mockGetOutpointsByCollection: vi.fn(),
  mockGetOutpointsByTag: vi.fn(),
  mockPlanChangeTags: vi.fn(() => ({ tagIds: [], tagNames: [] })),
  mockReconcileNewCoins: vi.fn(),
  mockStoreChangeTagIntent: vi.fn(),
  mockHeadersSubscribe: vi.fn(),
  mockImportPsbt: vi.fn(),
  mockLoadWallet: vi.fn(),
  mockReadPsbtFile: vi.fn(),
  mockRemoveMusigNonce: vi.fn(),
  mockUploadTransaction: vi.fn(),
}));

vi.mock("../../core/config.js", () => ({
  getElectrumServer: vi.fn(() => ({ host: "electrum.example.com", port: 50002, protocol: "ssl" })),
  getNetwork: vi.fn(() => "mainnet"),
  requireApiKey: vi.fn(() => "api-key"),
  requireEmail: vi.fn(() => "user@example.com"),
  loadConfig: vi.fn(() => ({})),
  getDefaultFeeLevel: mockGetDefaultFeeLevel,
  isFeeLevel: (value: string) => ["economy", "standard", "priority"].includes(value),
  DEFAULT_FEE_LEVEL: "economy",
  FEE_LEVELS: ["economy", "standard", "priority"],
}));

vi.mock("../../core/fees.js", () => ({
  estimateFeeRateLevels: mockEstimateFeeRateLevels,
}));

vi.mock("../../core/api-client.js", () => ({
  ApiClient: vi.fn(class MockApiClient {}),
}));

vi.mock("../../core/storage.js", () => ({
  loadWallet: mockLoadWallet,
  removeMusigNonce: mockRemoveMusigNonce,
}));

vi.mock("../../core/coin-store.js", () => ({
  getLockedOutpoints: mockGetLockedOutpoints,
}));

vi.mock("../../core/tag-store.js", () => ({
  getOutpointsByTag: mockGetOutpointsByTag,
}));

vi.mock("../../core/collection-store.js", () => ({
  getOutpointsByCollection: mockGetOutpointsByCollection,
}));

vi.mock("../../core/coin-rules.js", () => ({
  reconcileNewCoins: mockReconcileNewCoins,
}));

vi.mock("../../core/change-intents.js", () => ({
  planChangeTags: mockPlanChangeTags,
  storeChangeTagIntent: mockStoreChangeTagIntent,
}));

vi.mock("../../core/psbt-import.js", () => ({
  importPsbt: mockImportPsbt,
  readPsbtFile: mockReadPsbtFile,
}));

vi.mock("../../core/electrum.js", () => ({
  ElectrumClient: vi.fn(
    class MockElectrumClient {
      close = vi.fn();
      connect = vi.fn();
      headersSubscribe = mockHeadersSubscribe;
      serverVersion = vi.fn();
    },
  ),
  addressToScripthash: vi.fn(),
  parseBlockTime: vi.fn(() => 1_893_508_000),
}));

vi.mock("../../core/transaction.js", () => ({
  ServerTxResponse: class {},
  combinePendingPsbt: mockCombinePendingPsbt,
  createTransaction: mockCreateTransaction,
  decodePsbtDetail: mockDecodePsbtDetail,
  deleteTransaction: vi.fn(),
  fetchConfirmedTransactions: vi.fn(),
  fetchPendingTransaction: mockFetchPendingTransaction,
  fetchPendingTransactions: vi.fn(),
  fetchPendingTxInputTimelockMetadataBatch: vi.fn(),
  fetchPsbtInputTimelockMetadata: mockFetchPsbtInputTimelockMetadata,
  uploadTransaction: mockUploadTransaction,
}));

const TEST_WALLET: WalletData = {
  walletId: "jk74e3up",
  groupId: "883409fe-511d-4ae7-92bf-250b5bd6ce45",
  gid: "mrQ3kuD4AUt1S2H5HFhGk6LbpRGLDQkzLg",
  name: "Wallet 1",
  m: 0,
  n: 1,
  addressType: "NATIVE_SEGWIT",
  descriptor:
    "wsh(and_v(v:pk([6cbbb5d0/48'/0'/0'/2']xpub6FDWyqCf1ia58hQUMw8VCJaApL1mCnCzw88LPHCXpsczxnDoVhKLFJHCM76vXPsBuAhmimbHwGY7EGQvyvek2t48QpzWjcmyK5dTWHt4i7q/<0;1>/*),older(4194311)))",
  signers: [
    "[6cbbb5d0/48'/0'/0'/2']xpub6FDWyqCf1ia58hQUMw8VCJaApL1mCnCzw88LPHCXpsczxnDoVhKLFJHCM76vXPsBuAhmimbHwGY7EGQvyvek2t48QpzWjcmyK5dTWHt4i7q",
  ],
  secretboxKey: "jnQRPI4//QSN8ti/4KUkcE0dt99/hDXIxwxCcDtKCiU=",
  createdAt: "2026-03-31T02:02:07.273Z",
};

const TEST_PSBT_B64 =
  "cHNidP8BAF4CAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9////AegDAAAAAAAAIgAgYBH2S0UDjqKevQ0Q0eaZR3Jw0e7K4PHyyc2Vla7TCoIAAAAAAAEBH6CGAQAAAAAAFgAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

describe("tx create", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Commander persists parsed option values on the (singleton) command
    // instance; reset modules so each test gets a fresh txCommand and stale
    // option values (e.g. --fee-level) don't leak between tests.
    vi.resetModules();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockHeadersSubscribe.mockResolvedValue({ height: 900_000, hex: "tip-header" });
    mockCreateTransaction.mockResolvedValue({
      changeAddress: "bc1qchangeaddress0000000000000000000000000000000000000000",
      fee: 308n,
      feeRateSatPerKvB: 1_000n,
      lockTime: 0,
      subtractFee: false,
      recipientAmount: 20_000_000n,
      recipients: [
        {
          address: "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
          amount: 20_000_000n,
          receives: 20_000_000n,
        },
      ],
      changeAmount: 5_000_000n,
      selectedInputs: [{ txid: "funding-txid", vout: 0, value: 25_000_308n }],
      miniscriptPath: {
        index: 0,
        lockTime: 0,
        preimageRequirements: [],
        requiredSignatures: 1,
        sequence: 4_194_311,
        signerNames: [
          "[6cbbb5d0/48'/0'/0'/2']xpub6FDWyqCf1ia58hQUMw8VCJaApL1mCnCzw88LPHCXpsczxnDoVhKLFJHCM76vXPsBuAhmimbHwGY7EGQvyvek2t48QpzWjcmyK5dTWHt4i7q/<0;1>/*",
        ],
      },
      psbtB64: TEST_PSBT_B64,
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
    });
    mockFetchPsbtInputTimelockMetadata.mockResolvedValue([
      {
        blocktime: 1_891_360_074,
        height: 880_000,
        txHash: "funding-txid",
        txPos: 0,
      },
    ]);
    mockDecodePsbtDetail.mockReturnValue({
      fee: "308 sat",
      feeBtc: "0.00000308 BTC",
      miniscriptPath: {
        index: 0,
        lockTime: 0,
        preimageRequirements: [],
        requiredSignatures: 1,
        sequence: 4_194_311,
        signerNames: [
          "[6cbbb5d0/48'/0'/0'/2']xpub6FDWyqCf1ia58hQUMw8VCJaApL1mCnCzw88LPHCXpsczxnDoVhKLFJHCM76vXPsBuAhmimbHwGY7EGQvyvek2t48QpzWjcmyK5dTWHt4i7q/<0;1>/*",
        ],
      },
      outputs: [],
      requiredCount: 1,
      signers: { "6cbbb5d0": false },
      signedCount: 0,
      status: "PENDING_SIGNATURES",
      subAmount: "20000000 sat",
      subAmountBtc: "0.20000000 BTC",
      timelockedUntil: {
        based: "TIME_LOCK",
        mature: false,
        value: 1_893_508_506,
      },
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("prints timelock metadata for created miniscript transactions", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
      ],
      { from: "user" },
    );

    expect(mockFetchPsbtInputTimelockMetadata).toHaveBeenCalledWith(
      TEST_PSBT_B64,
      expect.any(Object),
      "mainnet",
    );
    expect(mockDecodePsbtDetail).toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledWith(
      "  Timelock: pending TIME_LOCK until 1893508506 (2030-01-01 14:35:06 UTC)",
    );
  });

  it("passes taproot script-path override when requested", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--taproot-script-path",
      ],
      { from: "user" },
    );

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({
        taprootScriptPath: true,
      }),
    );
  });

  it("converts a fractional --fee-rate (sat/vB) to sat/kvB", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--fee-rate",
        "1.5",
      ],
      { from: "user" },
    );

    // 1.5 sat/vB → 1500 sat/kvB (round to nearest).
    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ feeRateSatPerKvB: 1_500n }),
    );
  });

  it("forwards repeated --coin outpoints as preset coins and labels manual selection", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const txidA = "a".repeat(64);
    const txidB = "B".repeat(64); // uppercase hex is accepted and lowercased
    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--coin",
        `${txidA}:0`,
        "--coin",
        `${txidB}:3`,
      ],
      { from: "user" },
    );

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({
        presetCoins: [
          { txid: txidA, vout: 0 },
          { txid: "b".repeat(64), vout: 3 },
        ],
      }),
    );
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("selected manually");
  });

  it("forwards --from-tag as the resolved tag outpoints", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});
    const resolved = { name: "kyc", outpoints: new Set(["a".repeat(64) + ":0"]) };
    mockGetOutpointsByTag.mockReturnValue(resolved);

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--from-tag",
        "kyc",
      ],
      { from: "user" },
    );

    expect(mockGetOutpointsByTag).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      "kyc",
    );
    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ fromTag: resolved }),
    );
  });

  it("forwards --from-collection as the resolved collection outpoints", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});
    const resolved = { name: "Exchange A", outpoints: new Set(["b".repeat(64) + ":1"]) };
    mockGetOutpointsByCollection.mockReturnValue(resolved);

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--from-collection",
        "Exchange A",
      ],
      { from: "user" },
    );

    expect(mockGetOutpointsByCollection).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      "Exchange A",
    );
    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ fromCollection: resolved }),
    );
  });

  it("the reconcileScan hook re-resolves the filter outpoints after reconciliation", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});
    mockGetOutpointsByTag.mockReturnValue({ name: "kyc", outpoints: new Set<string>() });
    mockGetOutpointsByCollection.mockReturnValue({
      name: "Exchange A",
      outpoints: new Set<string>(),
    });

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--from-tag",
        "kyc",
        "--from-collection",
        "Exchange A",
      ],
      { from: "user" },
    );

    const { reconcileScan } = mockCreateTransaction.mock.calls[0][0] as {
      reconcileScan: (scanned: Array<{ txid: string; vout: number }>) => {
        lockedOutpoints: Set<string>;
        fromTagOutpoints?: Set<string>;
        fromCollectionOutpoints?: Set<string>;
      };
    };

    // The scan reconciled a new coin into the tag and collection; the fresh
    // sets returned by the hook must reflect that.
    const freshTag = new Set(["c".repeat(64) + ":0"]);
    const freshCollection = new Set(["c".repeat(64) + ":0", "d".repeat(64) + ":1"]);
    mockGetOutpointsByTag.mockReturnValue({ name: "kyc", outpoints: freshTag });
    mockGetOutpointsByCollection.mockReturnValue({
      name: "Exchange A",
      outpoints: freshCollection,
    });

    const returned = reconcileScan([{ txid: "c".repeat(64), vout: 0 }]);
    expect(returned.fromTagOutpoints).toBe(freshTag);
    expect(returned.fromCollectionOutpoints).toBe(freshCollection);
    // Re-resolution happens AFTER reconciliation (by name, not raw input).
    expect(mockGetOutpointsByTag).toHaveBeenLastCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      "kyc",
    );
    expect(mockReconcileNewCoins.mock.invocationCallOrder[0]).toBeLessThan(
      mockGetOutpointsByTag.mock.invocationCallOrder[1],
    );
  });

  it("passes a reconcileScan hook that runs the rules and returns the fresh locked set", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
      ],
      { from: "user" },
    );

    const { reconcileScan } = mockCreateTransaction.mock.calls[0][0] as {
      reconcileScan: (scanned: Array<{ txid: string; vout: number }>) => {
        lockedOutpoints: Set<string>;
      };
    };
    const scanned = [{ txid: "a".repeat(64), vout: 0 }];
    const locked = new Set(["a".repeat(64) + ":0"]);
    mockGetLockedOutpoints.mockReturnValue(locked);

    expect(reconcileScan(scanned)).toEqual({ lockedOutpoints: locked });
    expect(mockReconcileNewCoins).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      scanned,
    );
    // The locked set is read AFTER reconciliation, so rule-applied locks count.
    expect(mockReconcileNewCoins.mock.invocationCallOrder[0]).toBeLessThan(
      mockGetLockedOutpoints.mock.invocationCallOrder[0],
    );
  });

  it("stores a change-tag intent from the inherited plan and prints it", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    mockPlanChangeTags.mockReturnValueOnce({ tagIds: [1, 2], tagNames: ["kyc", "cold"] });

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
      ],
      { from: "user" },
    );

    // Default (no --change-tags): the plan is computed with requested=undefined.
    expect(mockPlanChangeTags).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      [{ txid: "funding-txid", vout: 0, value: 25_000_308n }],
      undefined,
    );
    expect(mockStoreChangeTagIntent).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      {
        address: "bc1qchangeaddress0000000000000000000000000000000000000000",
        amountSats: 5_000_000n,
        tagIds: [1, 2],
      },
    );
    expect(logSpy).toHaveBeenCalledWith("  Change tags: #kyc #cold");
  });

  it("--change-tags none plans nothing and stores no intent", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    mockPlanChangeTags.mockReturnValueOnce({ tagIds: [], tagNames: [] });

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--change-tags",
        "none",
      ],
      { from: "user" },
    );

    expect(mockPlanChangeTags).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      expect.any(Array),
      "none",
    );
    expect(mockStoreChangeTagIntent).not.toHaveBeenCalled();
    // The flag was explicit, so the choice is echoed back.
    expect(logSpy).toHaveBeenCalledWith("  Change tags: none");
  });

  it("warns and skips the intent when the transaction has no change output", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const base = await mockCreateTransaction();
    mockCreateTransaction.mockResolvedValueOnce({ ...base, changeAddress: null, changeAmount: 0n });
    mockPlanChangeTags.mockClear();

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--change-tags",
        "kyc",
      ],
      { from: "user" },
    );

    expect(mockPlanChangeTags).not.toHaveBeenCalled();
    expect(mockStoreChangeTagIntent).not.toHaveBeenCalled();
    const err = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(err).toContain("--change-tags is ignored because the transaction has no change output");
  });

  it("rejects a malformed --coin outpoint", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);
    // Parse errors surface in the subcommand, which needs its own exit override.
    for (const sub of txCommand.commands) sub.exitOverride();

    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    await expect(
      root.parseAsync(
        [
          "tx",
          "create",
          "--wallet",
          "jk74e3up",
          "--to",
          "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
          "--amount",
          "0.2",
          "--coin",
          "nothex:0",
        ],
        { from: "user" },
      ),
    ).rejects.toThrow(/--coin must be/);
    expect(mockCreateTransaction).not.toHaveBeenCalled();
  });

  it("forwards --fee-level as the auto-estimate level", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--fee-level",
        "priority",
      ],
      { from: "user" },
    );

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ feeLevel: "priority" }),
    );
  });

  it("falls back to the saved default fee level when no flag is given", async () => {
    mockGetDefaultFeeLevel.mockReturnValueOnce("standard");

    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
      ],
      { from: "user" },
    );

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ feeLevel: "standard" }),
    );
  });

  it("rejects an invalid --fee-level", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    // Suppress commander's stderr output for the invalid option.
    txCommand.configureOutput({ writeErr: () => {} });

    // Invalid enum is rejected at parse time, before the action runs.
    await expect(
      root.parseAsync(["tx", "create", "--fee-level", "turbo"], { from: "user" }),
    ).rejects.toThrow();
    expect(mockCreateTransaction).not.toHaveBeenCalled();
  });

  it("forwards --anti-fee-sniping and prints the effective locktime", async () => {
    mockCreateTransaction.mockResolvedValueOnce({
      changeAddress: "bc1qchangeaddress0000000000000000000000000000000000000000",
      fee: 308n,
      feeRateSatPerKvB: 1_000n,
      lockTime: 900_000,
      subtractFee: false,
      recipientAmount: 20_000_000n,
      recipients: [
        {
          address: "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
          amount: 20_000_000n,
          receives: 20_000_000n,
        },
      ],
      psbtB64: TEST_PSBT_B64,
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
    });

    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--anti-fee-sniping",
      ],
      { from: "user" },
    );

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ antiFeeSniping: true }),
    );
    expect(logSpy).toHaveBeenCalledWith("  Anti-fee sniping: locktime 900000");
  });

  it("forwards --subtract-fee and prints the recipient amount", async () => {
    mockCreateTransaction.mockResolvedValueOnce({
      changeAddress: "bc1qchangeaddress0000000000000000000000000000000000000000",
      fee: 308n,
      feeRateSatPerKvB: 1_000n,
      lockTime: 0,
      subtractFee: true,
      recipientAmount: 19_999_692n,
      recipients: [
        {
          address: "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
          amount: 20_000_000n,
          receives: 19_999_692n,
        },
      ],
      psbtB64: TEST_PSBT_B64,
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
    });

    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--subtract-fee",
      ],
      { from: "user" },
    );

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ subtractFeeFromAmount: true }),
    );
    const lines = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(lines).toContain("Recipient receives:");
    expect(lines).toContain("19999692 sat");
  });

  it("does not set anti-fee-sniping by default", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
      ],
      { from: "user" },
    );

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ antiFeeSniping: false }),
    );
  });

  it("sweeps the balance with --send-all (no --amount) and marks it", async () => {
    mockCreateTransaction.mockResolvedValueOnce({
      changeAddress: null,
      fee: 308n,
      feeRateSatPerKvB: 1_000n,
      lockTime: 0,
      subtractFee: true,
      recipientAmount: 24_999_692n,
      recipients: [
        {
          address: "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
          amount: 25_000_000n,
          receives: 24_999_692n,
        },
      ],
      changeAmount: 0n,
      selectedInputs: [{ txid: "funding-txid", vout: 0, value: 25_000_000n }],
      psbtB64: TEST_PSBT_B64,
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
    });

    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--send-all",
      ],
      { from: "user" },
    );

    // sendAll forwarded; amount is a placeholder the engine ignores.
    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ sendAll: true, amount: 0n }),
    );
    const lines = logSpy.mock.calls.map((c) => c[0]).join("\n");
    // Gross amount = recipientAmount + fee = 25000000, marked "(send all)".
    expect(lines).toContain("25000000 sat");
    expect(lines).toContain("(send all)");
    expect(lines).toContain("Recipient receives:");
    expect(lines).toContain("24999692 sat");
  });

  it("ignores --amount with a warning when --send-all is set", async () => {
    mockCreateTransaction.mockResolvedValueOnce({
      changeAddress: null,
      fee: 308n,
      feeRateSatPerKvB: 1_000n,
      lockTime: 0,
      subtractFee: true,
      recipientAmount: 24_999_692n,
      recipients: [
        {
          address: "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
          amount: 25_000_000n,
          receives: 24_999_692n,
        },
      ],
      changeAmount: 0n,
      selectedInputs: [{ txid: "funding-txid", vout: 0, value: 25_000_000n }],
      psbtB64: TEST_PSBT_B64,
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
    });

    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--amount",
        "0.2",
        "--currency",
        "btc",
        "--send-all",
      ],
      { from: "user" },
    );

    expect(errSpy).toHaveBeenCalledWith("Warning: --amount is ignored when --send-all is set.");
    expect(mockCreateTransaction).toHaveBeenCalledWith(expect.objectContaining({ sendAll: true }));
  });

  it("errors when neither --amount nor --send-all is given", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    // The action throws, printError reports it and calls process.exit(1) (which
    // surfaces as a rejection in tests).
    await expect(
      root.parseAsync(
        [
          "tx",
          "create",
          "--wallet",
          "jk74e3up",
          "--to",
          "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        ],
        { from: "user" },
      ),
    ).rejects.toThrow();

    expect(mockCreateTransaction).not.toHaveBeenCalled();
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringContaining("Provide --amount, or use --send-all"),
    );
  });
});

describe("tx fees", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEstimateFeeRateLevels.mockResolvedValue({
      priority: 6_000n,
      standard: 5_000n,
      economy: 1_000n,
    });
    mockGetDefaultFeeLevel.mockReset();
    mockGetDefaultFeeLevel.mockReturnValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("lists the three recommended rates in sat/vB, marking the default", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(["tx", "fees"], { from: "user" });

    const lines = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(lines).toContain("Priority");
    expect(lines).toContain("6 sat/vB");
    expect(lines).toContain("Standard");
    expect(lines).toContain("5 sat/vB");
    expect(lines).toContain("Economy");
    expect(lines).toContain("1 sat/vB");
    // Default (economy when unset) is marked.
    expect(lines).toMatch(/Economy\s+1 sat\/vB {2}\(default\)/);
    // minimumFee is not surfaced.
    expect(lines.toLowerCase()).not.toContain("minimum");
  });

  it("emits the three rates as JSON with raw sat/kvB values", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.option("--json", "Output as JSON");
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(["--json", "tx", "fees"], { from: "user" });

    const payload = JSON.parse(logSpy.mock.calls.at(-1)?.[0] as string);
    expect(payload).toMatchObject({
      priority: "6",
      standard: "5",
      economy: "1",
      prioritySatPerKvB: "6000",
      standardSatPerKvB: "5000",
      economySatPerKvB: "1000",
      defaultFeeLevel: "economy",
    });
  });
});

describe("tx draft", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockHeadersSubscribe.mockResolvedValue({ height: 900_000, hex: "tip-header" });
    mockGetDefaultFeeLevel.mockReturnValue(undefined);
    mockCreateTransaction.mockResolvedValue({
      changeAddress: "bc1qchangeaddress0000000000000000000000000000000000000000",
      fee: 308n,
      feeRateSatPerKvB: 1_000n,
      feeLevel: "economy",
      lockTime: 0,
      subtractFee: false,
      recipientAmount: 20_000_000n,
      recipients: [
        {
          address: "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
          amount: 20_000_000n,
          receives: 20_000_000n,
        },
      ],
      changeAmount: 5_000_000n,
      selectedInputs: [{ txid: "funding-txid", vout: 0, value: 25_000_308n }],
      psbtB64: TEST_PSBT_B64,
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
    });
    mockFetchPsbtInputTimelockMetadata.mockResolvedValue([
      { blocktime: 1_891_360_074, height: 880_000, txHash: "funding-txid", txPos: 0 },
    ]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const baseArgs = [
    "tx",
    "draft",
    "--wallet",
    "jk74e3up",
    "--to",
    "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
    "--amount",
    "0.2",
    "--currency",
    "btc",
  ];

  it("previews the transaction without uploading it", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(baseArgs, { from: "user" });

    // The draft never creates the real transaction.
    expect(mockUploadTransaction).not.toHaveBeenCalled();
    expect(mockCreateTransaction).toHaveBeenCalledTimes(1);

    const out = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(out).toContain("Draft transaction (not created)");
    expect(out).toContain("Estimated fee:");
    // Total amount = recipientAmount + fee = 20000000 + 308.
    expect(out).toContain("Total amount:");
    expect(out).toContain("20000308 sat");
    expect(out).toContain("Change: bc1qchangeaddress");
    expect(out).toContain("Input coins:");
    expect(out).toContain("funding-txid:0");
    // Auto-estimate caveat shown when no --fee-rate.
    expect(out).toContain("pass --fee-rate");
  });

  it("previews the change tags without storing an intent", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    mockPlanChangeTags.mockReturnValueOnce({ tagIds: [1], tagNames: ["kyc"] });

    await root.parseAsync(baseArgs, { from: "user" });

    expect(mockPlanChangeTags).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      expect.any(Array),
      undefined,
    );
    expect(mockStoreChangeTagIntent).not.toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledWith("  Change tags: #kyc");
  });

  it("forwards the same options as tx create and omits the caveat with --fee-rate", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [...baseArgs, "--fee-rate", "2", "--subtract-fee", "--anti-fee-sniping"],
      {
        from: "user",
      },
    );

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({
        feeRateSatPerKvB: 2_000n,
        subtractFeeFromAmount: true,
        antiFeeSniping: true,
      }),
    );
    const out = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(out).not.toContain("pass --fee-rate");
  });

  it("forwards --from-tag and --from-collection like tx create", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    vi.spyOn(console, "log").mockImplementation(() => {});
    const resolvedTag = { name: "kyc", outpoints: new Set(["a".repeat(64) + ":0"]) };
    const resolvedCollection = { name: "Exchange A", outpoints: new Set(["b".repeat(64) + ":1"]) };
    mockGetOutpointsByTag.mockReturnValue(resolvedTag);
    mockGetOutpointsByCollection.mockReturnValue(resolvedCollection);

    await root.parseAsync([...baseArgs, "--from-tag", "kyc", "--from-collection", "Exchange A"], {
      from: "user",
    });

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ fromTag: resolvedTag, fromCollection: resolvedCollection }),
    );
  });

  it("forwards --coin outpoints and marks the input list as manually selected", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const txidA = "a".repeat(64);
    await root.parseAsync([...baseArgs, "--coin", `${txidA}:1`], { from: "user" });

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ presetCoins: [{ txid: txidA, vout: 1 }] }),
    );
    const out = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(out).toContain("Input coins (selected manually):");
  });

  it("previews a send-all sweep without uploading", async () => {
    mockCreateTransaction.mockResolvedValueOnce({
      changeAddress: null,
      fee: 308n,
      feeRateSatPerKvB: 1_000n,
      feeLevel: "economy",
      lockTime: 0,
      subtractFee: true,
      recipientAmount: 24_999_692n,
      recipients: [
        {
          address: "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
          amount: 25_000_000n,
          receives: 24_999_692n,
        },
      ],
      changeAmount: 0n,
      selectedInputs: [{ txid: "funding-txid", vout: 0, value: 25_000_000n }],
      psbtB64: TEST_PSBT_B64,
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
    });

    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      [
        "tx",
        "draft",
        "--wallet",
        "jk74e3up",
        "--to",
        "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z",
        "--send-all",
      ],
      { from: "user" },
    );

    expect(mockUploadTransaction).not.toHaveBeenCalled();
    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ sendAll: true, amount: 0n }),
    );
    const out = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(out).toContain("Draft transaction (not created)");
    expect(out).toContain("(send all)");
    expect(out).toContain("Recipient receives:");
    expect(out).toContain("24999692 sat");
  });
});

describe("tx sign", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockHeadersSubscribe.mockResolvedValue({ height: 900_000, hex: "tip-header" });
    mockFetchPendingTransaction.mockResolvedValue({ psbt: TEST_PSBT_B64, txId: "tx-id" });
    mockCombinePendingPsbt.mockReturnValue({ changed: false, psbtB64: TEST_PSBT_B64 });
    mockFetchPsbtInputTimelockMetadata.mockResolvedValue([
      {
        blocktime: 1_891_360_074,
        height: 880_000,
        txHash: "funding-txid",
        txPos: 0,
      },
    ]);
    mockDecodePsbtDetail.mockReturnValue({
      fee: "308 sat",
      feeBtc: "0.00000308 BTC",
      outputs: [],
      requiredCount: 1,
      signers: { "6cbbb5d0": false },
      signedCount: 0,
      status: "PENDING_SIGNATURES",
      subAmount: "20000000 sat",
      subAmountBtc: "0.20000000 BTC",
      timelockedUntil: {
        based: "TIME_LOCK",
        mature: false,
        value: 1_893_508_506,
      },
      txId: "tx-id",
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("prints enriched timelock metadata after signing", async () => {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(txCommand);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(
      ["tx", "sign", "--wallet", "jk74e3up", "--tx-id", "tx-id", "--psbt", TEST_PSBT_B64],
      { from: "user" },
    );

    expect(mockCombinePendingPsbt).toHaveBeenCalledWith(TEST_PSBT_B64, expect.any(String), {
      descriptor: TEST_WALLET.descriptor,
      network: "mainnet",
    });
    expect(mockFetchPsbtInputTimelockMetadata).toHaveBeenCalledWith(
      TEST_PSBT_B64,
      expect.any(Object),
      "mainnet",
    );
    expect(logSpy).toHaveBeenCalledWith(
      "  Timelock: pending TIME_LOCK until 1893508506 (2030-01-01 14:35:06 UTC)",
    );
  });
});

describe("tx import", () => {
  const IMPORT_DETAIL = {
    fee: "308 sat",
    feeBtc: "0.00000308 BTC",
    outputs: [
      {
        address: "bc1qrecipient",
        amount: "20000000 sat",
        amountBtc: "0.20000000 BTC",
        isChange: false,
      },
    ],
    requiredCount: 1,
    signers: { "6cbbb5d0": false },
    signedCount: 0,
    status: "PENDING_SIGNATURES",
    subAmount: "20000000 sat",
    subAmountBtc: "0.20000000 BTC",
    txId: "",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockHeadersSubscribe.mockResolvedValue({ height: 900_000, hex: "tip-header" });
    mockFetchPsbtInputTimelockMetadata.mockResolvedValue([]);
    mockReadPsbtFile.mockReturnValue(TEST_PSBT_B64);
    mockDecodePsbtDetail.mockReturnValue(IMPORT_DETAIL);
    mockImportPsbt.mockResolvedValue({
      txId: "imported-tx-id",
      action: "created",
      psbtB64: TEST_PSBT_B64,
      updated: true,
      warnings: [],
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function runImport(extraArgs: string[] = []) {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    root.option("--json");
    root.addCommand(txCommand);
    await root.parseAsync(
      ["tx", "import", "--wallet", "jk74e3up", "--file", "/tmp/a.psbt", ...extraArgs],
      { from: "user" },
    );
  }

  it("reads the file, imports it with the open electrum client, and prints the created summary", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await runImport();

    expect(mockReadPsbtFile).toHaveBeenCalledWith("/tmp/a.psbt");
    expect(mockImportPsbt).toHaveBeenCalledWith(
      expect.objectContaining({
        wallet: TEST_WALLET,
        network: "mainnet",
        psbtB64: TEST_PSBT_B64,
        electrum: expect.any(Object),
      }),
    );
    expect(logSpy).toHaveBeenCalledWith("Transaction imported and uploaded to group server.");
    expect(logSpy).toHaveBeenCalledWith("  Transaction ID: imported-tx-id");
    expect(logSpy).toHaveBeenCalledWith("  Action: created");
    expect(logSpy).toHaveBeenCalledWith("  Status: PENDING_SIGNATURES (0/1 signatures)");
    expect(logSpy).toHaveBeenCalledWith(
      "\nSign with: nunchuk tx sign --wallet jk74e3up --tx-id imported-tx-id",
    );
  });

  it("prints the merged wording and a broadcast hint once ready", async () => {
    mockImportPsbt.mockResolvedValue({
      txId: "imported-tx-id",
      action: "merged",
      psbtB64: TEST_PSBT_B64,
      updated: true,
      warnings: [],
    });
    mockDecodePsbtDetail.mockReturnValue({
      ...IMPORT_DETAIL,
      signedCount: 1,
      status: "READY_TO_BROADCAST",
    });
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await runImport();

    expect(logSpy).toHaveBeenCalledWith("Transaction PSBT combined and uploaded to group server.");
    expect(logSpy).toHaveBeenCalledWith(
      "\nBroadcast with: nunchuk tx broadcast --wallet jk74e3up --tx-id imported-tx-id",
    );
  });

  it("prints the unchanged wording and surfaces warnings on stderr", async () => {
    mockImportPsbt.mockResolvedValue({
      txId: "imported-tx-id",
      action: "unchanged",
      psbtB64: TEST_PSBT_B64,
      updated: false,
      warnings: ["Chain unavailable; skipped the spent-input check."],
    });
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await runImport();

    expect(logSpy).toHaveBeenCalledWith(
      "Imported PSBT added no new data. Group server PSBT unchanged.",
    );
    expect(errSpy).toHaveBeenCalledWith(
      "Warning: Chain unavailable; skipped the spent-input check.",
    );
  });

  it("emits the action and detail fields as JSON", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await runImport(["--json"]);

    const payload = JSON.parse(logSpy.mock.calls[0][0] as string);
    expect(payload).toMatchObject({
      txId: "imported-tx-id",
      action: "created",
      updated: true,
      status: "PENDING_SIGNATURES",
      signatures: "0/1",
      fee: "308 sat",
      signers: { "6cbbb5d0": false },
    });
  });

  it("reports a wallet mismatch through printError and exits 1", async () => {
    mockImportPsbt.mockRejectedValue({
      error: "PSBT_WALLET_MISMATCH",
      message:
        "PSBT does not belong to wallet jk74e3up (input 0: abc:0 not an address of wallet jk74e3up)",
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit");
    }) as never);

    await expect(runImport()).rejects.toThrow("process.exit");

    expect(errSpy).toHaveBeenCalledWith(
      "Error: PSBT does not belong to wallet jk74e3up (input 0: abc:0 not an address of wallet jk74e3up)",
    );
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("reports a missing file without contacting the server", async () => {
    mockReadPsbtFile.mockImplementation(() => {
      throw { error: "FILE_NOT_FOUND", message: "Could not read file: /tmp/a.psbt" };
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit");
    }) as never);

    await expect(runImport()).rejects.toThrow("process.exit");

    expect(errSpy).toHaveBeenCalledWith("Error: Could not read file: /tmp/a.psbt");
    expect(mockImportPsbt).not.toHaveBeenCalled();
  });
});

describe("tx create / tx draft with multiple recipients", () => {
  const ADDR_A = "bc1qvqglvj69qw82984ap5gdre5egae8p50wets0rukfek2ettknp2pq7j2n9z";
  const ADDR_B = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
  const ADDR_C = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
  const TWO_RECIPIENTS = [
    { address: ADDR_A, amount: 100_000n, receives: 100_000n },
    { address: ADDR_B, amount: 250_000n, receives: 250_000n },
  ];
  const tempDirs: string[] = [];

  function writeTemp(name: string, content: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nunchuk-tx-batch-"));
    tempDirs.push(dir);
    const file = path.join(dir, name);
    fs.writeFileSync(file, content);
    return file;
  }

  function batchResult(recipients = TWO_RECIPIENTS, overrides: Record<string, unknown> = {}) {
    return {
      changeAddress: "bc1qchangeaddress0000000000000000000000000000000000000000",
      fee: 612n,
      feeRateSatPerKvB: 3_000n,
      feeLevel: "economy",
      lockTime: 0,
      subtractFee: false,
      recipients,
      recipientAmount: recipients[0].receives,
      changeAmount: 5_000_000n,
      selectedInputs: [{ txid: "funding-txid", vout: 0, value: 5_350_612n }],
      psbtB64: TEST_PSBT_B64,
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
      ...overrides,
    };
  }

  async function run(args: string[], json = false) {
    const { txCommand } = await import("../tx.js");
    const root = new Command();
    root.exitOverride();
    if (json) root.option("--json", "Output as JSON");
    root.addCommand(txCommand);
    // Parse errors surface in the subcommand, which needs its own exit override.
    for (const sub of txCommand.commands) sub.exitOverride();
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const parse = root.parseAsync(json ? ["--json", ...args] : args, { from: "user" });
    return { parse, logSpy, errSpy };
  }

  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockHeadersSubscribe.mockResolvedValue({ height: 900_000, hex: "tip-header" });
    mockGetDefaultFeeLevel.mockReturnValue(undefined);
    mockCreateTransaction.mockResolvedValue(batchResult());
    mockFetchPsbtInputTimelockMetadata.mockResolvedValue([
      { blocktime: 1_891_360_074, height: 880_000, txHash: "funding-txid", txPos: 0 },
    ]);
    mockDecodePsbtDetail.mockReturnValue({
      fee: "612 sat",
      feeBtc: "0.00000612 BTC",
      outputs: [],
      requiredCount: 1,
      signers: { "6cbbb5d0": false },
      signedCount: 0,
      status: "PENDING_SIGNATURES",
      subAmount: "350000 sat",
      subAmountBtc: "0.00350000 BTC",
      txId: "f05830ac99fb27096ddd4b1c05352830b9bbf5462cb2807116baf1ab8b0282e5",
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("forwards repeated --recipient flags as a recipient list and prints the block", async () => {
    const { parse, logSpy } = await run([
      "tx",
      "create",
      "--wallet",
      "jk74e3up",
      "--recipient",
      `${ADDR_A}:100000`,
      "--recipient",
      `${ADDR_B}:250000`,
    ]);
    await parse;

    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({
        recipients: [
          { address: ADDR_A, amount: 100_000n },
          { address: ADDR_B, amount: 250_000n },
        ],
        toAddress: undefined,
        amount: undefined,
        sendAll: false,
      }),
    );
    expect(mockUploadTransaction).toHaveBeenCalledTimes(1);
    const out = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(out).toContain("Recipients (2):");
    expect(out).toContain(`${ADDR_A}  0.00100000 BTC (100000 sat)`);
    expect(out).toContain(`${ADDR_B}  0.00250000 BTC (250000 sat)`);
    expect(out).toContain("Amount: 0.00350000 BTC (350000 sat)");
    expect(out).not.toContain("Recipient:");
    expect(out).not.toContain("Recipient receives");
  });

  it("applies --currency to every --recipient amount and lets a row unit override it", async () => {
    const { parse } = await run([
      "tx",
      "draft",
      "--wallet",
      "jk74e3up",
      "--recipient",
      `${ADDR_A}:0.001`,
      "--recipient",
      `${ADDR_B}:250000:sat`,
      "--currency",
      "btc",
    ]);
    await parse;
    expect(mockCreateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({
        recipients: [
          { address: ADDR_A, amount: 100_000n },
          { address: ADDR_B, amount: 250_000n },
        ],
      }),
    );
    expect(mockUploadTransaction).not.toHaveBeenCalled();
  });

  it("reads recipients from a CSV file and from a JSON file", async () => {
    const csv = writeTemp("payouts.csv", `address,amount\n${ADDR_A},100000\n${ADDR_B},250000\n`);
    const { parse } = await run(["tx", "create", "--wallet", "jk74e3up", "--recipients-file", csv]);
    await parse;
    expect(mockCreateTransaction).toHaveBeenLastCalledWith(
      expect.objectContaining({
        recipients: [
          { address: ADDR_A, amount: 100_000n },
          { address: ADDR_B, amount: 250_000n },
        ],
      }),
    );

    const json = writeTemp(
      "payouts.json",
      JSON.stringify([
        { address: ADDR_A, amount: "0.001", currency: "BTC" },
        { address: ADDR_C, amount: 250000 },
      ]),
    );
    vi.resetModules();
    const second = await run(["tx", "create", "--wallet", "jk74e3up", "--recipients-file", json]);
    await second.parse;
    expect(mockCreateTransaction).toHaveBeenLastCalledWith(
      expect.objectContaining({
        recipients: [
          { address: ADDR_A, amount: 100_000n },
          { address: ADDR_C, amount: 250_000n },
        ],
      }),
    );
  });

  it("emits recipients[] in JSON and omits recipientAmount when there are several", async () => {
    mockCreateTransaction.mockResolvedValueOnce(
      batchResult(
        [
          { address: ADDR_A, amount: 100_000n, receives: 99_795n },
          { address: ADDR_B, amount: 250_000n, receives: 249_796n },
        ],
        { subtractFee: true, fee: 613n },
      ),
    );
    const { parse, logSpy } = await run(
      [
        "tx",
        "create",
        "--wallet",
        "jk74e3up",
        "--recipient",
        `${ADDR_A}:100000`,
        "--recipient",
        `${ADDR_B}:250000`,
        "--subtract-fee",
      ],
      true,
    );
    await parse;
    const payload = JSON.parse(logSpy.mock.calls.at(-1)![0] as string);
    expect(payload.recipients).toEqual([
      { address: ADDR_A, amount: "100000", receives: "99795" },
      { address: ADDR_B, amount: "250000", receives: "249796" },
    ]);
    expect(payload.amount).toBe("350000");
    expect(payload.subtractFee).toBe(true);
    expect(payload).not.toHaveProperty("recipientAmount");
  });

  it("keeps the single-recipient output and JSON fields for one --recipient", async () => {
    mockCreateTransaction.mockResolvedValue(
      batchResult([{ address: ADDR_A, amount: 100_000n, receives: 100_000n }]),
    );
    const human = await run([
      "tx",
      "create",
      "--wallet",
      "jk74e3up",
      "--recipient",
      `${ADDR_A}:100000`,
    ]);
    await human.parse;
    const out = human.logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(out).toContain(`Recipient: ${ADDR_A}`);
    expect(out).not.toContain("Recipients (");

    vi.resetModules();
    const json = await run(
      ["tx", "draft", "--wallet", "jk74e3up", "--recipient", `${ADDR_A}:100000`],
      true,
    );
    await json.parse;
    const payload = JSON.parse(json.logSpy.mock.calls.at(-1)![0] as string);
    expect(payload.recipient).toBe(ADDR_A);
    expect(payload.recipientAmount).toBe("100000");
    expect(payload.recipients).toEqual([{ address: ADDR_A, amount: "100000", receives: "100000" }]);
  });

  it("previews a batch draft with per-recipient receives and the batch total", async () => {
    mockCreateTransaction.mockResolvedValueOnce(
      batchResult(
        [
          { address: ADDR_A, amount: 100_000n, receives: 99_795n },
          { address: ADDR_B, amount: 250_000n, receives: 249_796n },
        ],
        { subtractFee: true, fee: 613n },
      ),
    );
    const { parse, logSpy } = await run([
      "tx",
      "draft",
      "--wallet",
      "jk74e3up",
      "--recipient",
      `${ADDR_A}:100000`,
      "--recipient",
      `${ADDR_B}:250000`,
      "--subtract-fee",
    ]);
    await parse;
    const out = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(out).toContain("Draft transaction (not created)");
    expect(out).toContain("Recipients (2):");
    expect(out).toContain("→ receives 0.00099795 BTC (99795 sat)");
    expect(out).toContain("→ receives 0.00249796 BTC (249796 sat)");
    // Total = Σ receives + fee = 349591 + 613 = 350204.
    expect(out).toContain("Total amount: 0.00350204 BTC (350204 sat)");
    expect(mockUploadTransaction).not.toHaveBeenCalled();
  });

  it("rejects mixing input forms, --send-all with a batch, and --amount with --recipient", async () => {
    const cases: Array<[string[], string]> = [
      [
        ["--to", ADDR_A, "--amount", "1000", "--recipient", `${ADDR_B}:1000`],
        "Provide exactly one of --to, --recipient, or --recipients-file.",
      ],
      [["--amount", "1000"], "Provide exactly one of --to, --recipient, or --recipients-file."],
      [
        ["--recipient", `${ADDR_A}:1000`, "--send-all"],
        "--send-all supports a single recipient (--to).",
      ],
      [
        ["--recipient", `${ADDR_A}:1000`, "--amount", "5"],
        "--amount applies to --to only; put each amount in the --recipient value or file row.",
      ],
    ];
    for (const [args, message] of cases) {
      vi.resetModules();
      const { parse, errSpy } = await run(["tx", "create", "--wallet", "jk74e3up", ...args]);
      await expect(parse).rejects.toThrow();
      expect(errSpy).toHaveBeenCalledWith(`Error: ${message}`);
      expect(mockCreateTransaction).not.toHaveBeenCalled();
    }
  });

  it("reports validation errors as structured JSON and never as {}", async () => {
    const invalid = await run(
      ["tx", "create", "--wallet", "jk74e3up", "--recipient", `${ADDR_A}:1000`, "--send-all"],
      true,
    );
    await expect(invalid.parse).rejects.toThrow();
    expect(invalid.errSpy).toHaveBeenCalledWith(
      JSON.stringify({
        error: "INVALID_PARAM",
        message: "--send-all supports a single recipient (--to).",
      }),
    );

    vi.resetModules();
    const duplicate = await run(
      [
        "tx",
        "draft",
        "--wallet",
        "jk74e3up",
        "--recipient",
        `${ADDR_A}:1000`,
        "--recipient",
        `${ADDR_A}:2000`,
      ],
      true,
    );
    await expect(duplicate.parse).rejects.toThrow();
    expect(duplicate.errSpy).toHaveBeenCalledWith(
      JSON.stringify({
        error: "INVALID_PARAM",
        message: `Duplicate recipient ${ADDR_A} (--recipient #2); merge the amounts into one row.`,
      }),
    );
    expect(mockCreateTransaction).not.toHaveBeenCalled();

    // A plain Error from the core is mapped to TX_BUILD_FAILED instead of {}.
    vi.resetModules();
    mockCreateTransaction.mockRejectedValueOnce(
      new Error("Insufficient funds to cover amount + fee."),
    );
    const core = await run(
      ["tx", "create", "--wallet", "jk74e3up", "--to", ADDR_A, "--amount", "1000"],
      true,
    );
    await expect(core.parse).rejects.toThrow();
    expect(core.errSpy).toHaveBeenCalledWith(
      JSON.stringify({
        error: "TX_BUILD_FAILED",
        message: "Insufficient funds to cover amount + fee.",
      }),
    );
  });

  it("rejects a malformed --recipient value and a missing recipients file", async () => {
    const malformed = await run(["tx", "create", "--wallet", "jk74e3up", "--recipient", ADDR_A]);
    await expect(malformed.parse).rejects.toThrow(/expected <address>:<amount>\[:<currency>\]/);

    vi.resetModules();
    const missing = await run(
      ["tx", "create", "--wallet", "jk74e3up", "--recipients-file", "/nonexistent/payouts.csv"],
      true,
    );
    await expect(missing.parse).rejects.toThrow();
    expect(missing.errSpy).toHaveBeenCalledWith(
      JSON.stringify({
        error: "FILE_NOT_FOUND",
        message: "Could not read file: /nonexistent/payouts.csv",
      }),
    );
    expect(mockCreateTransaction).not.toHaveBeenCalled();
  });
});
