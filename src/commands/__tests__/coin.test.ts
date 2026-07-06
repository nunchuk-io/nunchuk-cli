import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WalletData } from "../../core/storage.js";

const {
  mockAddCoinTag,
  mockAddCoinToCollection,
  mockApplyCollectionToExisting,
  mockCreateCollection,
  mockCreateTag,
  mockGetCoinCollectionNames,
  mockGetCoinTagNames,
  mockGetLockedOutpoints,
  mockListCoins,
  mockLoadWallet,
  mockReconcileNewCoins,
  mockSetCoinLock,
  mockUpdateCollection,
} = vi.hoisted(() => ({
  mockAddCoinTag: vi.fn(),
  mockAddCoinToCollection: vi.fn(),
  mockApplyCollectionToExisting: vi.fn(),
  mockCreateCollection: vi.fn(),
  mockCreateTag: vi.fn(),
  mockGetCoinCollectionNames: vi.fn(() => new Map<string, string[]>()),
  mockGetCoinTagNames: vi.fn(() => new Map<string, string[]>()),
  mockGetLockedOutpoints: vi.fn(() => new Set<string>()),
  mockListCoins: vi.fn(),
  mockLoadWallet: vi.fn(),
  mockReconcileNewCoins: vi.fn(),
  mockSetCoinLock: vi.fn(),
  mockUpdateCollection: vi.fn(),
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

vi.mock("../../core/coins.js", () => ({
  listCoins: mockListCoins,
}));

vi.mock("../../core/coin-store.js", () => ({
  getLockedOutpoints: mockGetLockedOutpoints,
  setCoinLock: mockSetCoinLock,
}));

vi.mock("../../core/tag-store.js", () => ({
  addCoinTag: mockAddCoinTag,
  createTag: mockCreateTag,
  deleteTag: vi.fn(),
  getCoinTagNames: mockGetCoinTagNames,
  listTags: vi.fn(() => []),
  removeCoinTag: vi.fn(),
  renameTag: vi.fn(),
}));

vi.mock("../../core/collection-store.js", () => ({
  addCoinToCollection: mockAddCoinToCollection,
  applyCollectionToExisting: mockApplyCollectionToExisting,
  createCollection: mockCreateCollection,
  deleteCollection: vi.fn(),
  getCoinCollectionNames: mockGetCoinCollectionNames,
  listCollections: vi.fn(() => []),
  removeCoinFromCollection: vi.fn(),
  updateCollection: mockUpdateCollection,
}));

vi.mock("../../core/coin-rules.js", () => ({
  reconcileNewCoins: mockReconcileNewCoins,
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
  // Commander keeps parsed option values on the (singleton) command instance;
  // re-import per invocation so repeated calls in one test don't leak options.
  vi.resetModules();
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

  it("coin lock locks every repeated --coin (regression: last one won)", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const TXID2 = "cd".repeat(32);
    await runCoin(["lock", "--wallet", "jk74e3up", "--coin", `${TXID}:0`, "--coin", `${TXID2}:1`]);
    expect(mockSetCoinLock).toHaveBeenCalledTimes(2);
    expect(mockSetCoinLock).toHaveBeenNthCalledWith(
      1,
      "user@example.com",
      "mainnet",
      "jk74e3up",
      TXID,
      0,
      true,
    );
    expect(mockSetCoinLock).toHaveBeenNthCalledWith(
      2,
      "user@example.com",
      "mainnet",
      "jk74e3up",
      TXID2,
      1,
      true,
    );
    expect(logSpy).toHaveBeenCalledWith(`Locked ${TXID}:0`);
    expect(logSpy).toHaveBeenCalledWith(`Locked ${TXID2}:1`);
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

  it("shows tags and filters with --tag and --untagged", async () => {
    mockGetCoinTagNames.mockReturnValue(new Map([[`${TXID}:0`, ["kyc"]]]));

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin(["list", "--wallet", "jk74e3up"]);
    let out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("Tags: #kyc");

    logSpy.mockClear();
    await runCoin(["list", "--wallet", "jk74e3up", "--tag", "kyc"]);
    out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain(`${TXID}:0`);
    expect(out).not.toContain(`${TXID}:1`);

    logSpy.mockClear();
    await runCoin(["list", "--wallet", "jk74e3up", "--untagged"]);
    out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain(`${TXID}:1`);
    expect(out).not.toContain(`${TXID}:0:`);
  });
});

describe("coin tag commands", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockCreateTag.mockReturnValue({ id: 1, name: "kyc" });
    mockAddCoinTag.mockReturnValue({ id: 1, name: "kyc" });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("coin tag create forwards the name", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin(["tag", "create", "kyc", "--wallet", "jk74e3up"]);
    expect(mockCreateTag).toHaveBeenCalledWith("user@example.com", "mainnet", "jk74e3up", "kyc");
    expect(logSpy).toHaveBeenCalledWith("Created tag #kyc");
  });

  it("coin tag add forwards the outpoint and name", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin(["tag", "add", "kyc", "--wallet", "jk74e3up", "--coin", `${TXID}:0`]);
    expect(mockAddCoinTag).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      TXID,
      0,
      "kyc",
    );
    expect(logSpy).toHaveBeenCalledWith(`Tagged ${TXID}:0 with #kyc`);
  });

  it("coin tag add tags every repeated --coin (regression: last one won)", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const TXID2 = "cd".repeat(32);
    const TXID3 = "ef".repeat(32);
    await runCoin([
      "tag",
      "add",
      "kyc",
      "--wallet",
      "jk74e3up",
      "--coin",
      `${TXID}:0`,
      "--coin",
      `${TXID2}:0`,
      "--coin",
      `${TXID3}:0`,
    ]);
    expect(mockAddCoinTag).toHaveBeenCalledTimes(3);
    expect(mockAddCoinTag).toHaveBeenNthCalledWith(
      1,
      "user@example.com",
      "mainnet",
      "jk74e3up",
      TXID,
      0,
      "kyc",
    );
    expect(mockAddCoinTag).toHaveBeenNthCalledWith(
      3,
      "user@example.com",
      "mainnet",
      "jk74e3up",
      TXID3,
      0,
      "kyc",
    );
    expect(logSpy).toHaveBeenCalledWith(`Tagged ${TXID2}:0 with #kyc`);
  });
});

describe("coin collection commands", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockCreateCollection.mockReturnValue({
      id: 1,
      name: "Exchange A",
      addUntagged: false,
      autoLock: false,
      addTags: [],
    });
    mockUpdateCollection.mockReturnValue({
      id: 1,
      name: "Exchange A",
      addUntagged: true,
      autoLock: false,
      addTags: [],
    });
    mockAddCoinToCollection.mockReturnValue({ id: 1, name: "Exchange A" });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("coin collection create forwards name and rule flags", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin([
      "collection",
      "create",
      "Exchange A",
      "--wallet",
      "jk74e3up",
      "--add-untagged",
      "--add-tag",
      "kyc",
      "--add-tag",
      "cold",
      "--auto-lock",
    ]);
    expect(mockCreateCollection).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      "Exchange A",
      { addUntagged: true, autoLock: true, addTagNames: ["kyc", "cold"] },
    );
    expect(logSpy).toHaveBeenCalledWith(`Created collection "Exchange A"`);
  });

  it("coin collection update forwards tri-state flags and --no- variants", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin([
      "collection",
      "update",
      "Exchange A",
      "--wallet",
      "jk74e3up",
      "--add-untagged",
      "--no-auto-lock",
      "--clear-add-tags",
    ]);
    expect(mockUpdateCollection).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      "Exchange A",
      {
        name: undefined,
        addUntagged: true,
        autoLock: false,
        addTagNames: undefined,
        clearAddTags: true,
      },
    );
  });

  it("coin collection update rejects --add-tag with --clear-add-tags and empty updates", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await runCoin([
      "collection",
      "update",
      "Exchange A",
      "--wallet",
      "jk74e3up",
      "--add-tag",
      "kyc",
      "--clear-add-tags",
    ]);
    expect(mockUpdateCollection).not.toHaveBeenCalled();
    let err = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(err).toContain("--add-tag and --clear-add-tags cannot be combined.");

    errSpy.mockClear();
    await runCoin(["collection", "update", "Exchange A", "--wallet", "jk74e3up"]);
    expect(mockUpdateCollection).not.toHaveBeenCalled();
    err = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(err).toContain("Nothing to update.");
  });

  it("coin collection add forwards the outpoint and name", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin([
      "collection",
      "add",
      "Exchange A",
      "--wallet",
      "jk74e3up",
      "--coin",
      `${TXID}:0`,
    ]);
    expect(mockAddCoinToCollection).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      TXID,
      0,
      "Exchange A",
    );
    expect(logSpy).toHaveBeenCalledWith(`Added ${TXID}:0 to "Exchange A"`);
  });
});

describe("coin list --collection", () => {
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
    mockGetLockedOutpoints.mockReturnValue(new Set<string>());
    mockGetCoinTagNames.mockReturnValue(new Map<string, string[]>());
    mockGetCoinCollectionNames.mockReturnValue(new Map([[`${TXID}:0`, ["Exchange A"]]]));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows collections and filters with --collection", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin(["list", "--wallet", "jk74e3up"]);
    let out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("Collections: Exchange A");

    logSpy.mockClear();
    await runCoin(["list", "--wallet", "jk74e3up", "--collection", "Exchange A"]);
    out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain(`${TXID}:0`);
    expect(out).not.toContain(`${TXID}:1`);
  });

  it("reconciles first-seen rules over the scanned coins before rendering", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin(["list", "--wallet", "jk74e3up"]);
    expect(mockReconcileNewCoins).toHaveBeenCalledWith("user@example.com", "mainnet", "jk74e3up", [
      { txid: TXID, vout: 0, address: "bc1qaddr", amountSats: 10_000n },
      { txid: TXID, vout: 1, address: "bc1qaddr2", amountSats: 20_000n },
    ]);
    // The rule pass runs before the lock/tag/collection state is loaded.
    expect(mockReconcileNewCoins.mock.invocationCallOrder[0]).toBeLessThan(
      mockGetLockedOutpoints.mock.invocationCallOrder[0],
    );
  });
});

describe("coin collection --apply-to-existing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    mockLoadWallet.mockReturnValue(TEST_WALLET);
    mockCreateCollection.mockReturnValue({
      id: 1,
      name: "quarantine",
      addUntagged: true,
      autoLock: true,
      addTags: [],
    });
    mockApplyCollectionToExisting.mockReturnValue({ name: "quarantine", joined: 2 });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("create --apply-to-existing runs the one-shot walk and reports the count", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin([
      "collection",
      "create",
      "quarantine",
      "--wallet",
      "jk74e3up",
      "--add-untagged",
      "--auto-lock",
      "--apply-to-existing",
    ]);
    expect(mockApplyCollectionToExisting).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      "quarantine",
    );
    expect(logSpy).toHaveBeenCalledWith("Added 2 existing coins.");
  });

  it("update with only --apply-to-existing skips the patch and applies", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin([
      "collection",
      "update",
      "quarantine",
      "--wallet",
      "jk74e3up",
      "--apply-to-existing",
    ]);
    expect(mockUpdateCollection).not.toHaveBeenCalled();
    expect(mockApplyCollectionToExisting).toHaveBeenCalledWith(
      "user@example.com",
      "mainnet",
      "jk74e3up",
      "quarantine",
    );
    expect(logSpy).toHaveBeenCalledWith("Added 2 existing coins.");
  });

  it("create without the flag does not run the walk", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    await runCoin(["collection", "create", "quarantine", "--wallet", "jk74e3up"]);
    expect(mockApplyCollectionToExisting).not.toHaveBeenCalled();
  });
});
