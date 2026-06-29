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
