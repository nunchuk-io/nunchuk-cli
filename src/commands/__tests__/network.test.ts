import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockClose,
  mockConnect,
  mockGetElectrumServer,
  mockGetNetwork,
  mockHeadersSubscribe,
  mockLoadConfig,
  mockParseBlockTime,
  mockSaveConfig,
} = vi.hoisted(() => ({
  mockClose: vi.fn(),
  mockConnect: vi.fn(),
  mockGetElectrumServer: vi.fn(),
  mockGetNetwork: vi.fn(),
  mockHeadersSubscribe: vi.fn(),
  mockLoadConfig: vi.fn(),
  mockParseBlockTime: vi.fn(),
  mockSaveConfig: vi.fn(),
}));

vi.mock("../../core/config.js", () => ({
  getElectrumServer: mockGetElectrumServer,
  getNetwork: mockGetNetwork,
  loadConfig: mockLoadConfig,
  saveConfig: mockSaveConfig,
}));

vi.mock("../../core/electrum.js", () => ({
  ElectrumClient: vi.fn(
    class MockElectrumClient {
      close = mockClose;
      connect = mockConnect;
      headersSubscribe = mockHeadersSubscribe;
    },
  ),
  parseBlockTime: mockParseBlockTime,
}));

function buildRoot(networkCommand: Command): Command {
  const root = new Command();
  root.exitOverride();
  root.option("--json", "Output in JSON format");
  root.option("--network <network>", "Override network");
  root.addCommand(networkCommand);
  return root;
}

describe("network tip", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetNetwork.mockImplementation((network?: string) => network ?? "mainnet");
    mockGetElectrumServer.mockReturnValue({
      host: "mainnet.nunchuk.io",
      port: 52002,
      protocol: "ssl",
      url: "ssl://mainnet.nunchuk.io:52002",
    });
    mockHeadersSubscribe.mockResolvedValue({ height: 900_000, hex: "tip-header" });
    mockParseBlockTime.mockReturnValue(1_735_689_600);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches the current tip from the configured electrum server", async () => {
    const { fetchNetworkTip } = await import("../network.js");

    await expect(fetchNetworkTip("mainnet")).resolves.toEqual({
      network: "mainnet",
      height: 900_000,
      blocktime: 1_735_689_600,
      datetime: "2025-01-01 00:00:00 UTC",
    });
    expect(mockConnect).toHaveBeenCalledWith("mainnet.nunchuk.io", 52002, "ssl");
    expect(mockHeadersSubscribe).toHaveBeenCalledOnce();
    expect(mockParseBlockTime).toHaveBeenCalledWith("tip-header");
    expect(mockClose).toHaveBeenCalledOnce();
  });

  it("prints JSON output", async () => {
    const { networkCommand } = await import("../network.js");
    const root = buildRoot(networkCommand);
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(["--json", "network", "tip"], { from: "user" });

    expect(logSpy).toHaveBeenCalledWith(
      JSON.stringify(
        {
          network: "mainnet",
          height: 900_000,
          blocktime: 1_735_689_600,
          datetime: "2025-01-01 00:00:00 UTC",
        },
        null,
        2,
      ),
    );
  });

  it("uses the network override", async () => {
    const { networkCommand } = await import("../network.js");
    const root = buildRoot(networkCommand);
    vi.spyOn(console, "log").mockImplementation(() => {});

    await root.parseAsync(["--network", "testnet", "network", "tip"], { from: "user" });

    expect(mockGetNetwork).toHaveBeenCalledWith("testnet");
    expect(mockGetElectrumServer).toHaveBeenCalledWith("testnet");
  });

  it("prints a structured error when electrum fails", async () => {
    const { networkCommand } = await import("../network.js");
    const root = buildRoot(networkCommand);
    mockConnect.mockRejectedValueOnce(new Error("connection refused"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process, "exit").mockImplementation(((code?: string | number | null) => {
      throw new Error(`process.exit ${code}`);
    }) as never);

    await expect(root.parseAsync(["--json", "network", "tip"], { from: "user" })).rejects.toThrow(
      "process.exit 1",
    );

    expect(errorSpy).toHaveBeenCalledWith(
      JSON.stringify({
        error: "ELECTRUM_TIP_ERROR",
        message: "Failed to get network tip: connection refused",
      }),
    );
    expect(mockClose).toHaveBeenCalledOnce();
  });
});
