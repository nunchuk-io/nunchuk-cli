import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WalletData } from "../../core/storage.js";

const {
  mockCreateTransaction,
  mockDecodePsbtDetail,
  mockFetchPsbtInputTimelockMetadata,
  mockHeadersSubscribe,
  mockLoadWallet,
  mockUploadTransaction,
} = vi.hoisted(() => ({
  mockCreateTransaction: vi.fn(),
  mockDecodePsbtDetail: vi.fn(),
  mockFetchPsbtInputTimelockMetadata: vi.fn(),
  mockHeadersSubscribe: vi.fn(),
  mockLoadWallet: vi.fn(),
  mockUploadTransaction: vi.fn(),
}));

vi.mock("../../core/config.js", () => ({
  getElectrumServer: vi.fn(() => ({ host: "electrum.example.com", port: 50002, protocol: "ssl" })),
  getNetwork: vi.fn(() => "mainnet"),
  requireApiKey: vi.fn(() => "api-key"),
  requireEmail: vi.fn(() => "user@example.com"),
}));

vi.mock("../../core/api-client.js", () => ({
  ApiClient: vi.fn(class MockApiClient {}),
}));

vi.mock("../../core/storage.js", () => ({
  loadWallet: mockLoadWallet,
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
  combinePendingPsbt: vi.fn(),
  createTransaction: mockCreateTransaction,
  decodePsbtDetail: mockDecodePsbtDetail,
  deleteTransaction: vi.fn(),
  fetchConfirmedTransactions: vi.fn(),
  fetchPendingTransaction: vi.fn(),
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

describe("tx create", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockHeadersSubscribe.mockResolvedValue({ height: 900_000, hex: "tip-header" });
    mockCreateTransaction.mockResolvedValue({
      changeAddress: "bc1qchangeaddress0000000000000000000000000000000000000000",
      fee: 308n,
      feePerByte: 1n,
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
      psbtB64:
        "cHNidP8BAHECAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AQEAAAAAAAAAFgAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
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
      "cHNidP8BAHECAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AQEAAAAAAAAAFgAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
      expect.any(Object),
      "mainnet",
    );
    expect(mockDecodePsbtDetail).toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledWith(
      "  Timelock: pending TIME_LOCK until 1893508506 (2030-01-01 14:35:06 UTC)",
    );
  });
});
