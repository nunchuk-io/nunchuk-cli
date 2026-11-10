import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockIsInteractiveInput,
  mockIsInteractiveOutput,
  mockListKeys,
  mockPrint,
  mockPrintError,
  mockPrintTable,
  mockPromptSecret,
  mockReadSecretFromFile,
  mockReadStdinLines,
  mockSaveKey,
  mockWarnSecrets,
} = vi.hoisted(() => ({
  mockIsInteractiveInput: vi.fn(() => false),
  mockIsInteractiveOutput: vi.fn(() => true),
  mockListKeys: vi.fn(),
  mockPrint: vi.fn(),
  mockPrintError: vi.fn(),
  mockPrintTable: vi.fn(),
  mockPromptSecret: vi.fn(),
  mockReadSecretFromFile: vi.fn(),
  mockReadStdinLines: vi.fn(),
  mockSaveKey: vi.fn(),
  mockWarnSecrets: vi.fn(),
}));

vi.mock("../../core/prompt.js", () => ({
  isInteractiveInput: mockIsInteractiveInput,
  isInteractiveOutput: mockIsInteractiveOutput,
  promptSecret: mockPromptSecret,
  readSecretFromFile: mockReadSecretFromFile,
  readStdinLines: mockReadStdinLines,
  warnSecretsOnCommandLine: mockWarnSecrets,
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

function resetInteractivity(): void {
  mockIsInteractiveInput.mockReturnValue(false);
  mockIsInteractiveOutput.mockReturnValue(true);
}

describe("key import", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetInteractivity();
    mockListKeys.mockReturnValue([]);
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("imports a space-separated BIP39 mnemonic with a default name", async () => {
    await runKeyCommand(["key", "import", ...TEST_MNEMONIC.split(" ")]);

    expect(mockWarnSecrets).toHaveBeenCalledTimes(1);
    expect(mockWarnSecrets).toHaveBeenCalledWith(
      ["seed words"],
      "nunchuk key import (prompt), --stdin, or --file",
    );

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

describe("key import secret channels", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetInteractivity();
    mockListKeys.mockReturnValue([]);
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("reads the mnemonic from standard input with --stdin and prints no warning", async () => {
    mockReadStdinLines.mockResolvedValue([`  ${TEST_MNEMONIC}  `]);
    await runKeyCommand(["key", "import", "--stdin", "--name", "Piped"]);

    expect(mockReadStdinLines).toHaveBeenCalledWith(1);
    expect(mockSaveKey).toHaveBeenCalledWith(
      "user@example.com",
      "testnet",
      expect.objectContaining({
        name: "Piped",
        mnemonic: TEST_MNEMONIC,
        fingerprint: TEST_FINGERPRINT,
      }),
    );
    expect(mockWarnSecrets).not.toHaveBeenCalled();
  });

  it("reads the mnemonic from a file with --file", async () => {
    mockReadSecretFromFile.mockReturnValue(TEST_MNEMONIC);
    await runKeyCommand(["--json", "key", "import", "--file", "seed.txt"]);

    expect(mockReadSecretFromFile).toHaveBeenCalledWith("seed.txt");
    expect(mockSaveKey).toHaveBeenCalledTimes(1);
    expect(mockPrint).toHaveBeenCalledWith(
      { status: "imported", name: "My key #1", fingerprint: TEST_FINGERPRINT },
      expect.any(Command),
    );
    expect(JSON.stringify(mockPrint.mock.calls[0]?.[0])).not.toContain("abandon");
  });

  it("asks at a masked prompt when no source is given at a terminal", async () => {
    mockIsInteractiveInput.mockReturnValue(true);
    mockPromptSecret.mockResolvedValue(TEST_MNEMONIC);
    await runKeyCommand(["key", "import"]);

    expect(mockPromptSecret).toHaveBeenCalledWith("Enter seed words: ");
    expect(mockSaveKey).toHaveBeenCalledTimes(1);
  });

  it("fails with MISSING_PARAM when no source is given from a pipe", async () => {
    await runKeyCommand(["key", "import"]);

    expect(mockPromptSecret).not.toHaveBeenCalled();
    expect(mockSaveKey).not.toHaveBeenCalled();
    expect(mockPrintError).toHaveBeenCalledWith(
      {
        error: "MISSING_PARAM",
        message: "No seed words given and standard input is not a terminal. Use --stdin or --file.",
      },
      expect.any(Command),
    );
  });

  it("rejects more than one source", async () => {
    await runKeyCommand(["key", "import", "--stdin", "--file", "seed.txt"]);

    expect(mockPrintError).toHaveBeenCalledWith(
      {
        error: "INVALID_PARAM",
        message: "Provide the seed words in one way only: as arguments, --stdin, or --file",
      },
      expect.any(Command),
    );
    expect(mockReadStdinLines).not.toHaveBeenCalled();
    expect(mockSaveKey).not.toHaveBeenCalled();
  });

  it("reports a missing file without saving", async () => {
    mockReadSecretFromFile.mockImplementation(() => {
      throw { error: "FILE_NOT_FOUND", message: "Could not read file: nope.txt" };
    });
    await runKeyCommand(["key", "import", "--file", "nope.txt"]);

    expect(mockPrintError).toHaveBeenCalledWith(
      { error: "FILE_NOT_FOUND", message: "Could not read file: nope.txt" },
      expect.any(Command),
    );
    expect(mockSaveKey).not.toHaveBeenCalled();
  });
});

describe("key generate output guard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetInteractivity();
    mockListKeys.mockReturnValue([]);
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("prints the seed words at a terminal exactly as before", async () => {
    await runKeyCommand(["key", "generate", "--words", "12"]);

    expect(mockSaveKey).toHaveBeenCalledTimes(1);
    const saved = mockSaveKey.mock.calls[0]?.[2];
    const output = vi.mocked(console.log).mock.calls.flat().join("\n");
    expect(output).toContain("MNEMONIC (back up these words securely!):");
    expect(output).toContain(saved.mnemonic);
    expect(mockPrintError).not.toHaveBeenCalled();
  });

  it("refuses when output is a pipe and no key is stored", async () => {
    mockIsInteractiveOutput.mockReturnValue(false);
    await runKeyCommand(["--json", "key", "generate"]);

    expect(mockSaveKey).not.toHaveBeenCalled();
    expect(mockPrint).not.toHaveBeenCalled();
    expect(mockPrintError).toHaveBeenCalledWith(
      {
        error: "NOT_INTERACTIVE",
        message:
          "key generate prints seed words that must be backed up. Run it at a terminal, or pass --show-mnemonic if you accept the words going to this output.",
      },
      expect.any(Command),
    );
  });

  it("proceeds on a pipe with --show-mnemonic and includes the mnemonic in JSON", async () => {
    mockIsInteractiveOutput.mockReturnValue(false);
    await runKeyCommand(["--json", "key", "generate", "--show-mnemonic", "--name", "Agent key"]);

    expect(mockSaveKey).toHaveBeenCalledTimes(1);
    const saved = mockSaveKey.mock.calls[0]?.[2];
    expect(mockPrint).toHaveBeenCalledWith(
      { mnemonic: saved.mnemonic, name: "Agent key", fingerprint: saved.fingerprint },
      expect.any(Command),
    );
  });
});

describe("key info secret channels", () => {
  const STORED = {
    name: "Existing",
    mnemonic: TEST_MNEMONIC,
    fingerprint: TEST_FINGERPRINT,
    createdAt: "2026-01-01T00:00:00.000Z",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    resetInteractivity();
    mockListKeys.mockReturnValue([STORED]);
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function infoFingerprintFromJson(): string | undefined {
    return mockPrint.mock.calls[0]?.[0]?.fingerprint;
  }

  it("keeps --mnemonic and --passphrase working with one combined warning and no prompt", async () => {
    await runKeyCommand([
      "--json",
      "key",
      "info",
      "--mnemonic",
      TEST_MNEMONIC,
      "--passphrase",
      "secret",
    ]);

    expect(mockPromptSecret).not.toHaveBeenCalled();
    expect(mockReadStdinLines).not.toHaveBeenCalled();
    expect(mockWarnSecrets).toHaveBeenCalledTimes(1);
    expect(mockWarnSecrets).toHaveBeenCalledWith(
      ["--mnemonic", "--passphrase"],
      "the -stdin options or the prompt",
    );
    expect(infoFingerprintFromJson()).toBeDefined();
    expect(infoFingerprintFromJson()).not.toBe(TEST_FINGERPRINT); // passphrase changes the key
  });

  it("reads mnemonic then passphrase from standard input in that order", async () => {
    // Baseline: same inputs via flags.
    await runKeyCommand([
      "--json",
      "key",
      "info",
      "--mnemonic",
      TEST_MNEMONIC,
      "--passphrase",
      "secret",
    ]);
    const viaFlags = infoFingerprintFromJson();
    vi.clearAllMocks();
    resetInteractivity();
    mockListKeys.mockReturnValue([STORED]);

    mockReadStdinLines.mockResolvedValue([TEST_MNEMONIC, "secret"]);
    await runKeyCommand(["--json", "key", "info", "--mnemonic-stdin", "--passphrase-stdin"]);

    expect(mockReadStdinLines).toHaveBeenCalledWith(2);
    expect(mockWarnSecrets).toHaveBeenCalledWith([], "the -stdin options or the prompt");
    expect(infoFingerprintFromJson()).toBe(viaFlags);
  });

  it("rejects --passphrase-prompt together with a -stdin option before reading anything", async () => {
    await runKeyCommand(["key", "info", "--mnemonic-stdin", "--passphrase-prompt"]);

    expect(mockReadStdinLines).not.toHaveBeenCalled();
    expect(mockPrintError).toHaveBeenCalledWith(
      {
        error: "INVALID_PARAM",
        message:
          "--passphrase-prompt needs the keyboard; use --passphrase-stdin when the seed words come from standard input",
      },
      expect.any(Command),
    );
  });

  it("asks for the seed words and then the passphrase at a terminal", async () => {
    mockIsInteractiveInput.mockReturnValue(true);
    mockPromptSecret.mockResolvedValueOnce(TEST_MNEMONIC).mockResolvedValueOnce("");
    await runKeyCommand(["--json", "key", "info", "--passphrase-prompt"]);

    expect(mockPromptSecret).toHaveBeenNthCalledWith(1, "Enter seed words: ");
    expect(mockPromptSecret).toHaveBeenNthCalledWith(2, "Enter BIP39 passphrase: ");
    expect(infoFingerprintFromJson()).toBe(TEST_FINGERPRINT);
    expect(mockPrintError).not.toHaveBeenCalled();
  });

  it("still fails with MISSING_PARAM from a pipe when no source is given", async () => {
    await runKeyCommand(["key", "info"]);

    expect(mockPrintError).toHaveBeenCalledWith(
      {
        error: "MISSING_PARAM",
        message: "Provide --fingerprint, --mnemonic, --mnemonic-stdin, --xprv, or --xprv-stdin",
      },
      expect.any(Command),
    );
  });
});
