import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { mockListKeys, mockPrint, mockPrintError, mockPrintTable, mockSaveKey } = vi.hoisted(() => ({
  mockListKeys: vi.fn(),
  mockPrint: vi.fn(),
  mockPrintError: vi.fn(),
  mockPrintTable: vi.fn(),
  mockSaveKey: vi.fn(),
}));

vi.mock("../../core/config.js", () => ({
  getNetwork: vi.fn((network?: string) => network ?? "testnet"),
  requireEmail: vi.fn(() => "user@example.com"),
}));

vi.mock("../../core/storage.js", () => ({
  listKeys: mockListKeys,
  saveKey: mockSaveKey,
}));

vi.mock("../../output.js", () => ({
  print: mockPrint,
  printError: mockPrintError,
  printTable: mockPrintTable,
}));

const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const TEST_FINGERPRINT = "73c5da0a";

async function runKeyCommand(args: string[]): Promise<void> {
  vi.resetModules();
  const { keyCommand } = await import("../key.js");
  const root = new Command();
  root.exitOverride();
  root.option("--json", "Output in JSON format");
  root.option("--network <network>", "Override network");
  root.addCommand(keyCommand);
  await root.parseAsync(args, { from: "user" });
}

describe("key import", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListKeys.mockReturnValue([]);
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("imports a space-separated BIP39 mnemonic with a default name", async () => {
    await runKeyCommand(["key", "import", ...TEST_MNEMONIC.split(" ")]);

    expect(mockSaveKey).toHaveBeenCalledWith(
      "user@example.com",
      "testnet",
      expect.objectContaining({
        name: "My key #1",
        mnemonic: TEST_MNEMONIC,
        fingerprint: TEST_FINGERPRINT,
        createdAt: expect.any(String),
      }),
    );

    const saved = mockSaveKey.mock.calls[0]?.[2];
    expect(new Date(saved.createdAt).toISOString()).toBe(saved.createdAt);
    const logSpy = vi.mocked(console.log);
    expect(logSpy.mock.calls.flat().join("\n")).toContain("Key imported to local storage.");
    expect(logSpy.mock.calls.flat().join("\n")).not.toContain(TEST_MNEMONIC);
  });

  it("imports a quoted mnemonic with an explicit name", async () => {
    await runKeyCommand(["key", "import", "--name", "Alice", TEST_MNEMONIC]);

    expect(mockSaveKey).toHaveBeenCalledWith(
      "user@example.com",
      "testnet",
      expect.objectContaining({
        name: "Alice",
        mnemonic: TEST_MNEMONIC,
        fingerprint: TEST_FINGERPRINT,
      }),
    );
  });

  it("uses the next default name based on stored key count", async () => {
    mockListKeys.mockReturnValue([
      {
        name: "Key 1",
        mnemonic: TEST_MNEMONIC,
        fingerprint: "11111111",
        createdAt: "2026-01-01T00:00:00.000Z",
      },
      {
        name: "Key 2",
        mnemonic: TEST_MNEMONIC,
        fingerprint: "22222222",
        createdAt: "2026-01-01T00:00:00.000Z",
      },
    ]);

    await runKeyCommand(["key", "import", TEST_MNEMONIC]);

    expect(mockSaveKey).toHaveBeenCalledWith(
      "user@example.com",
      "testnet",
      expect.objectContaining({ name: "My key #3" }),
    );
  });

  it("rejects invalid mnemonics without saving", async () => {
    await runKeyCommand(["key", "import", "not", "a", "valid", "mnemonic"]);

    expect(mockPrintError).toHaveBeenCalledWith(
      { error: "INVALID_MNEMONIC", message: "Invalid BIP39 mnemonic" },
      expect.any(Command),
    );
    expect(mockSaveKey).not.toHaveBeenCalled();
  });

  it("rejects duplicate fingerprints without saving", async () => {
    mockListKeys.mockReturnValue([
      {
        name: "Existing",
        mnemonic: TEST_MNEMONIC,
        fingerprint: TEST_FINGERPRINT,
        createdAt: "2026-01-01T00:00:00.000Z",
      },
    ]);

    await runKeyCommand(["key", "import", TEST_MNEMONIC]);

    expect(mockPrintError).toHaveBeenCalledWith(
      { error: "ALREADY_EXISTS", message: `Key ${TEST_FINGERPRINT} already exists` },
      expect.any(Command),
    );
    expect(mockSaveKey).not.toHaveBeenCalled();
  });

  it("prints JSON output without exposing the mnemonic", async () => {
    await runKeyCommand(["--json", "key", "import", "--name", "Alice", TEST_MNEMONIC]);

    expect(mockPrint).toHaveBeenCalledWith(
      { status: "imported", name: "Alice", fingerprint: TEST_FINGERPRINT },
      expect.any(Command),
    );
    expect(JSON.stringify(mockPrint.mock.calls[0]?.[0])).not.toContain("abandon");
  });

  it("normalizes h hardened suffixes for key info custom paths", async () => {
    mockListKeys.mockReturnValue([
      {
        name: "Existing",
        mnemonic: TEST_MNEMONIC,
        fingerprint: TEST_FINGERPRINT,
        createdAt: "2026-01-01T00:00:00.000Z",
      },
    ]);

    await runKeyCommand([
      "key",
      "info",
      "--fingerprint",
      TEST_FINGERPRINT,
      "--path",
      "m/48h/1h/0h/2h",
    ]);

    const output = vi.mocked(console.log).mock.calls.flat().join("\n");
    expect(output).toContain("Path:          m/48'/1'/0'/2'");
    expect(output).toContain(`Descriptor:    [${TEST_FINGERPRINT}/48'/1'/0'/2']`);
    expect(mockPrintError).not.toHaveBeenCalled();
  });
});
