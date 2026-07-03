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
  mockGetOutpointsByTag,
  mockReconcileNewCoins,
  mockHeadersSubscribe,
  mockLoadWallet,
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
  mockGetOutpointsByTag: vi.fn(),
  mockReconcileNewCoins: vi.fn(),
  mockHeadersSubscribe: vi.fn(),
  mockLoadWallet: vi.fn(),
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

vi.mock("../../core/coin-rules.js", () => ({
  reconcileNewCoins: mockReconcileNewCoins,
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
