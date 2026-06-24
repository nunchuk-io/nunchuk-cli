import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildAnyDescriptor,
  buildWalletDescriptor,
  descriptorChecksum,
  getUnspendableXpub,
} from "../../core/descriptor.js";

const { mockLoadWallet, mockPrint, mockPrintError, mockPrintTable } = vi.hoisted(() => ({
  mockLoadWallet: vi.fn(),
  mockPrint: vi.fn(),
  mockPrintError: vi.fn(),
  mockPrintTable: vi.fn(),
}));

vi.mock("../../core/config.js", () => ({
  getElectrumServer: vi.fn(() => ({ host: "127.0.0.1", port: 50001, protocol: "tcp" })),
  getEphemeralKeypair: vi.fn(() => ({ pub: "ephemeral-pub", priv: "ephemeral-priv" })),
  getNetwork: vi.fn(() => "testnet"),
  loadConfig: vi.fn(() => ({})),
  requireApiKey: vi.fn(() => "api-key"),
  requireEmail: vi.fn(() => "user@example.com"),
}));

vi.mock("../../core/storage.js", () => ({
  ReplaceGroupStatus: { Accepted: "ACCEPTED" },
  addSandboxId: vi.fn(),
  getReplaceGroupStatuses: vi.fn(() => ({})),
  getSandboxIds: vi.fn(() => []),
  listWallets: vi.fn(() => []),
  loadWallet: mockLoadWallet,
  removeWallet: vi.fn(),
  saveWallet: vi.fn(),
  setReplaceGroupStatus: vi.fn(),
}));

vi.mock("../../output.js", () => ({
  print: mockPrint,
  printError: mockPrintError,
  printSandboxResult: vi.fn(),
  printTable: mockPrintTable,
  printWalletResult: vi.fn(),
}));

const TEST_SIGNERS = [
  "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
];

const TAPROOT_MINISCRIPT_BODY = `tr(${getUnspendableXpub(TEST_SIGNERS)}/<0;1>/*,and_v(v:pk(${TEST_SIGNERS[0]}/<0;1>/*),pk(${TEST_SIGNERS[1]}/<0;1>/*)))`;
const TAPROOT_MINISCRIPT_DESCRIPTOR = `${TAPROOT_MINISCRIPT_BODY}#${descriptorChecksum(
  TAPROOT_MINISCRIPT_BODY,
)}`;

function makeWallet(descriptor: string) {
  return {
    addressType: "TAPROOT",
    createdAt: "2026-06-24T00:00:00.000Z",
    descriptor,
    gid: "gid",
    id: "wallet-id",
    m: 2,
    n: 2,
    name: "wallet",
    secretboxKey: "",
    signers: TEST_SIGNERS,
  };
}

async function runWalletCommand(args: string[]): Promise<void> {
  vi.resetModules();
  const { walletCommand } = await import("../wallet.js");
  const root = new Command();
  root.exitOverride();
  root.option("--json", "Output in JSON format");
  root.option("--network <network>", "Override network");
  root.option("--api-key <apiKey>", "Override API key");
  root.addCommand(walletCommand);
  await root.parseAsync(args, { from: "user" });
}

describe("wallet export", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("exports miniscript BSMS descriptors in external/internal form", async () => {
    mockLoadWallet.mockReturnValue(makeWallet(TAPROOT_MINISCRIPT_DESCRIPTOR));

    await runWalletCommand(["wallet", "export", "wallet-id", "--type", "bsms"]);

    const output = vi.mocked(console.log).mock.calls.map((call) => String(call[0]));
    expect(output[0]).toBe("BSMS 1.0");
    expect(output[1]).toBe(TAPROOT_MINISCRIPT_DESCRIPTOR);
    expect(output[1]).toContain("/<0;1>/*");
  });

  it("keeps multisig BSMS descriptors in any-path form", async () => {
    mockLoadWallet.mockReturnValue(makeWallet(buildWalletDescriptor(TEST_SIGNERS, 2, "TAPROOT")));

    await runWalletCommand(["wallet", "export", "wallet-id", "--type", "bsms"]);

    const output = vi.mocked(console.log).mock.calls.map((call) => String(call[0]));
    expect(output[1]).toBe(buildAnyDescriptor(TEST_SIGNERS, 2, "TAPROOT"));
  });
});
