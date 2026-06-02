import { Command } from "commander";
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockBuildCreateGroupBody,
  mockBuildFinalizeBody,
  mockClientGet,
  mockClientPost,
  mockGetGroupDisplayState,
  mockIsGroupFinalized,
  mockRemoveSandboxId,
  mockSaveWallet,
} = vi.hoisted(() => ({
  mockBuildCreateGroupBody: vi.fn(),
  mockBuildFinalizeBody: vi.fn(),
  mockClientGet: vi.fn(),
  mockClientPost: vi.fn(),
  mockGetGroupDisplayState: vi.fn(),
  mockIsGroupFinalized: vi.fn(),
  mockRemoveSandboxId: vi.fn(),
  mockSaveWallet: vi.fn(),
}));

vi.mock("../../core/config.js", () => ({
  getEphemeralKeypair: vi.fn(() => ({ pub: "ephemeral-pub", priv: "ephemeral-priv" })),
  getNetwork: vi.fn(() => "testnet"),
  loadConfig: vi.fn(() => ({})),
  requireApiKey: vi.fn(() => "api-key"),
  requireEmail: vi.fn(() => "user@example.com"),
}));

vi.mock("../../core/api-client.js", () => ({
  ApiClient: vi.fn(
    class MockApiClient {
      get = mockClientGet;
      post = mockClientPost;
      del = vi.fn();
    },
  ),
}));

vi.mock("../../core/storage.js", () => ({
  ReplaceGroupStatus: { Accepted: "ACCEPTED" },
  addSandboxId: vi.fn(),
  getReplaceGroupStatuses: vi.fn(() => ({})),
  getSandboxIds: vi.fn(() => []),
  listWallets: vi.fn(() => []),
  loadKey: vi.fn(),
  removeSandboxId: mockRemoveSandboxId,
  saveWallet: mockSaveWallet,
}));

vi.mock("../../core/sandbox.js", () => ({
  buildAddKeyBody: vi.fn(),
  buildCreateGroupBody: mockBuildCreateGroupBody,
  buildDisablePlatformKeyBody: vi.fn(),
  buildEnablePlatformKeyBody: vi.fn(),
  buildFinalizeBody: mockBuildFinalizeBody,
  buildGroupStateBroadcastBodyIfNeeded: vi.fn(() => null),
  buildJoinGroupEvent: vi.fn(),
  buildSetPlatformKeyPolicyBody: vi.fn(),
  buildSignerDescriptor: vi.fn(),
  getGroupDisplayState: mockGetGroupDisplayState,
  getGroupPlatformKeyState: vi.fn(),
  isGroupFinalized: mockIsGroupFinalized,
  recoverFinalizedGroup: vi.fn(),
}));

vi.mock("../../core/wallet-replacement.js", () => ({
  getDeprecatedWalletName: vi.fn((name: string) => name),
  getGroupReplaceWalletId: vi.fn(() => undefined),
}));

const finalizeResult = {
  addressType: "TAPROOT",
  body: "{}",
  descriptor: "tr(...)",
  gid: "gid",
  m: 2,
  n: 3,
  name: "Taproot",
  secretboxKey: new Uint8Array([1, 2, 3]),
  signers: [],
  walletId: "wallet-id",
};

const taprootTemplate =
  "thresh(3,pk(key_0_0),s:pk(key_1_0),s:pk(key_2_0),s:pk(key_3_0),sln:after(1842652800),sln:after(1937260800))";

async function runSandboxCommand(args: string[]): Promise<void> {
  const { sandboxCommand } = await import("../sandbox.js");
  const root = new Command();
  root.exitOverride();
  root.addCommand(sandboxCommand);
  await root.parseAsync(args, { from: "user" });
}

describe("sandbox finalize", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockClientGet.mockResolvedValue({ group: { id: "g1", status: "PENDING", init: {} } });
    mockClientPost.mockResolvedValue({});
    mockIsGroupFinalized.mockReturnValue(false);
    mockGetGroupDisplayState.mockReturnValue({
      signers: [
        "[249fdf68/87'/1'/0']tpubA",
        "[86d82f57/87'/1'/0']tpubB",
        "[480101ce/87'/1'/0']tpubC",
      ],
    });
    mockBuildFinalizeBody.mockResolvedValue(finalizeResult);
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  it("passes value key set slot indexes to finalize", async () => {
    await runSandboxCommand(["sandbox", "finalize", "g1", "--value-key-set", "0,2"]);

    expect(mockBuildFinalizeBody).toHaveBeenCalledWith(
      "g1",
      { id: "g1", status: "PENDING", init: {} },
      "ephemeral-pub",
      "ephemeral-priv",
      "testnet",
      [0, 2],
    );
  });

  it("resolves value key set fingerprints to signer slot indexes", async () => {
    await runSandboxCommand(["sandbox", "finalize", "g1", "--value-key-set", "249fdf68,480101ce"]);

    expect(mockBuildFinalizeBody).toHaveBeenCalledWith(
      "g1",
      { id: "g1", status: "PENDING", init: {} },
      "ephemeral-pub",
      "ephemeral-priv",
      "testnet",
      [0, 2],
    );
  });
});

describe("sandbox create", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBuildCreateGroupBody.mockReturnValue("{}");
    mockClientPost.mockResolvedValue({ group: { id: "g1" } });
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  it("allows taproot miniscript templates", async () => {
    await runSandboxCommand([
      "sandbox",
      "create",
      "--name",
      "mini1",
      "--miniscript-template",
      taprootTemplate,
      "--address-type",
      "TAPROOT",
    ]);

    expect(mockBuildCreateGroupBody).toHaveBeenCalledWith(
      "mini1",
      0,
      0,
      "TAPROOT",
      "ephemeral-pub",
      "ephemeral-priv",
      taprootTemplate,
    );
  });
});
