import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WalletData } from "../../core/storage.js";

const { mockGetLockedOutpoints, mockListCoins, mockLoadWallet, mockSetCoinLock } = vi.hoisted(
  () => ({
    mockGetLockedOutpoints: vi.fn(() => new Set<string>()),
    mockListCoins: vi.fn(),
    mockLoadWallet: vi.fn(),
    mockSetCoinLock: vi.fn(),
  }),
);

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

vi.mock("../../core/coins.js", () => ({
  listCoins: mockListCoins,
}));

vi.mock("../../core/coin-store.js", () => ({
  getLockedOutpoints: mockGetLockedOutpoints,
  setCoinLock: mockSetCoinLock,
}));

vi.mock("../../core/electrum.js", () => ({
  ElectrumClient: vi.fn(
    class MockElectrumClient {
      close = vi.fn();
      connect = vi.fn();
      serverVersion = vi.fn();
    },
  ),
}));

const TEST_WALLET = { walletId: "jk74e3up" } as WalletData;
const TXID = "ab".repeat(32);

async function runCoin(args: string[]): Promise<void> {
  const { coinCommand } = await import("../coin.js");
  const root = new Command();
  root.exitOverride();
  root.addCommand(coinCommand);
  await root.parseAsync(["coin", ...args], { from: "user" });
}

describe("coin lock / unlock", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockGetLockedOutpoints.mockReturnValue(new Set<string>());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("coin lock sets the lock flag", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin(["lock", "--wallet", "jk74e3up", "--coin", `${TXID}:1`]);
    expect(mockSetCoinLock).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      TXID,
      1,
      true,
    );
    expect(logSpy).toHaveBeenCalledWith(`Locked ${TXID}:1`);
  });

  it("coin unlock clears the lock flag", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin(["unlock", "--wallet", "jk74e3up", "--coin", `${TXID}:1`]);
    expect(mockSetCoinLock).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      TXID,
      1,
      false,
    );
    expect(logSpy).toHaveBeenCalledWith(`Unlocked ${TXID}:1`);
  });

  it("rejects a malformed --coin outpoint", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const { coinCommand } = await import("../coin.js");
    const root = new Command();
    root.exitOverride();
    root.addCommand(coinCommand);
    for (const sub of coinCommand.commands) sub.exitOverride();

    await expect(
      root.parseAsync(["coin", "lock", "--wallet", "jk74e3up", "--coin", "bad"], {
        from: "user",
      }),
    ).rejects.toThrow(/--coin must be/);
    expect(mockSetCoinLock).not.toHaveBeenCalled();
  });
});

describe("coin list locked column", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockListCoins.mockResolvedValue([
      {
        txid: TXID,
        vout: 0,
        address: "bc1qaddr",
        amount: 10_000n,
        height: 100,
        confirmations: 5,
        status: "CONFIRMED",
        isChange: false,
      },
      {
        txid: TXID,
        vout: 1,
        address: "bc1qaddr2",
        amount: 20_000n,
        height: 100,
        confirmations: 5,
        status: "CONFIRMED",
        isChange: false,
      },
    ]);
    mockGetLockedOutpoints.mockReturnValue(new Set([`${TXID}:1`]));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("marks locked coins in the human output", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin(["list", "--wallet", "jk74e3up"]);
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain(`${TXID}:1 [locked]`);
    expect(out).not.toContain(`${TXID}:0 [locked]`);
  });
});
