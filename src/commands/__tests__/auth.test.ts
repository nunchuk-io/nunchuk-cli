import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockGetMe,
  mockIsInteractiveInput,
  mockPrint,
  mockPrintError,
  mockPromptSecret,
  mockReadStdinLines,
  mockSetAuthProfile,
} = vi.hoisted(() => ({
  mockGetMe: vi.fn(),
  mockIsInteractiveInput: vi.fn(),
  mockPrint: vi.fn(),
  mockPrintError: vi.fn(),
  mockPromptSecret: vi.fn(),
  mockReadStdinLines: vi.fn(),
  mockSetAuthProfile: vi.fn(),
}));

vi.mock("../../core/config.js", () => ({
  loadConfig: vi.fn(() => ({})),
  saveConfig: vi.fn(),
  getApiKey: vi.fn(),
  getNetwork: vi.fn(() => "testnet"),
  getAuthProfile: vi.fn(),
  getEphemeralKeypair: vi.fn(() => ({ pub: "pub", priv: "priv" })),
  setAuthProfile: mockSetAuthProfile,
  clearAuthProfile: vi.fn(),
  setEphemeralKeypair: vi.fn(),
}));

vi.mock("../../core/crypto.js", () => ({
  generateKeypair: vi.fn(() => ({ pub: "pub", priv: "priv" })),
}));

vi.mock("../../core/api-client.js", () => ({
  ApiClient: vi.fn(
    class MockApiClient {
      getMe = mockGetMe;
    },
  ),
}));

vi.mock("../../output.js", () => ({
  print: mockPrint,
  printError: mockPrintError,
}));

vi.mock("../../core/prompt.js", () => ({
  isInteractiveInput: mockIsInteractiveInput,
  promptSecret: mockPromptSecret,
  readStdinLines: mockReadStdinLines,
}));

const ME = { email: "user@example.com", id: "u1", name: "User" };

async function runAuth(args: string[]): Promise<void> {
  vi.resetModules();
  const { authCommand } = await import("../auth.js");
  const root = new Command();
  root.exitOverride();
  root.option("--json", "Output in JSON format");
  root.option("--network <network>", "Override network");
  root.option("--api-key <key>", "Override stored API key");
  root.addCommand(authCommand);
  await root.parseAsync(args, { from: "user" });
}

function savedApiKey(): string | undefined {
  return mockSetAuthProfile.mock.calls[0]?.[2]?.apiKey;
}

describe("auth login key resolution", () => {
  const envBackup = process.env.NUNCHUK_API_KEY;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.NUNCHUK_API_KEY;
    mockGetMe.mockResolvedValue(ME);
    mockIsInteractiveInput.mockReturnValue(false);
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    if (envBackup === undefined) delete process.env.NUNCHUK_API_KEY;
    else process.env.NUNCHUK_API_KEY = envBackup;
    vi.restoreAllMocks();
  });

  it("uses --api-key first, exactly as before, with no warning", async () => {
    process.env.NUNCHUK_API_KEY = "env-key";
    await runAuth(["--api-key", "flag-key", "auth", "login"]);
    expect(savedApiKey()).toBe("flag-key");
    expect(mockReadStdinLines).not.toHaveBeenCalled();
    expect(mockPromptSecret).not.toHaveBeenCalled();
    expect(console.error).not.toHaveBeenCalled();
    expect(mockPrint).toHaveBeenCalledWith(
      { status: "authenticated", email: ME.email },
      expect.any(Command),
    );
  });

  it("reads the key from standard input with --api-key-stdin", async () => {
    mockReadStdinLines.mockResolvedValue(["stdin-key"]);
    await runAuth(["auth", "login", "--api-key-stdin"]);
    expect(mockReadStdinLines).toHaveBeenCalledWith(1);
    expect(savedApiKey()).toBe("stdin-key");
    expect(mockPromptSecret).not.toHaveBeenCalled();
  });

  it("falls back to NUNCHUK_API_KEY and says so on standard error", async () => {
    process.env.NUNCHUK_API_KEY = "env-key";
    await runAuth(["auth", "login"]);
    expect(savedApiKey()).toBe("env-key");
    expect(mockPromptSecret).not.toHaveBeenCalled();
    expect(console.error).toHaveBeenCalledWith("Using API key from NUNCHUK_API_KEY.");
    expect(JSON.stringify(mockPrint.mock.calls[0]?.[0])).not.toContain("env-key");
  });

  it("prompts at an interactive terminal when nothing else is given", async () => {
    mockIsInteractiveInput.mockReturnValue(true);
    mockPromptSecret.mockResolvedValue("typed-key");
    await runAuth(["auth", "login"]);
    expect(mockPromptSecret).toHaveBeenCalledWith("Enter API secret key: ");
    expect(savedApiKey()).toBe("typed-key");
  });

  it("fails cleanly from a pipe with no key, naming the alternatives", async () => {
    await runAuth(["auth", "login"]);
    expect(mockPromptSecret).not.toHaveBeenCalled();
    expect(mockSetAuthProfile).not.toHaveBeenCalled();
    expect(mockPrintError).toHaveBeenCalledWith(
      {
        error: "NOT_INTERACTIVE",
        message:
          "No API key given and standard input is not a terminal. Use --api-key-stdin, set NUNCHUK_API_KEY, or run at a terminal.",
      },
      expect.any(Command),
    );
  });

  it("rejects an empty key from the prompt", async () => {
    mockIsInteractiveInput.mockReturnValue(true);
    mockPromptSecret.mockResolvedValue("");
    await runAuth(["auth", "login"]);
    expect(mockPrintError).toHaveBeenCalledWith(
      { error: "INVALID_KEY", message: "API key cannot be empty" },
      expect.any(Command),
    );
  });
});
