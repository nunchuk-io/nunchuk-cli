import { describe, expect, it, vi } from "vitest";
import type { ElectrumServer } from "../../core/config.js";
import { resolveElectrumServerInput } from "../config.js";

describe("resolveElectrumServerInput", () => {
  it("accepts an explicit ssl electrum server when probe succeeds", async () => {
    const probe = vi.fn(async (_server: ElectrumServer) => {});

    const server = await resolveElectrumServerInput("ssl://mainnet.nunchuk.io:52002", probe);

    expect(server).toEqual({
      protocol: "ssl",
      host: "mainnet.nunchuk.io",
      port: 52002,
      url: "ssl://mainnet.nunchuk.io:52002",
    });
    expect(probe).toHaveBeenCalledTimes(1);
  });

  it("prefers ssl when the protocol is omitted and ssl probe succeeds", async () => {
    const probe = vi.fn(async (_server: ElectrumServer) => {});

    const server = await resolveElectrumServerInput("mainnet.nunchuk.io:52002", probe);

    expect(server).toEqual({
      protocol: "ssl",
      host: "mainnet.nunchuk.io",
      port: 52002,
      url: "ssl://mainnet.nunchuk.io:52002",
    });
    expect(probe).toHaveBeenCalledWith(server);
    expect(probe).toHaveBeenCalledTimes(1);
  });

  it("falls back to tcp when ssl probe fails", async () => {
    const probe = vi.fn(async (server: ElectrumServer) => {
      if (server.protocol === "ssl") {
        throw new Error("tls handshake failed");
      }
    });

    const server = await resolveElectrumServerInput("electrum.example.com:50001", probe);

    expect(server).toEqual({
      protocol: "tcp",
      host: "electrum.example.com",
      port: 50001,
      url: "tcp://electrum.example.com:50001",
    });
    expect(probe).toHaveBeenNthCalledWith(1, {
      protocol: "ssl",
      host: "electrum.example.com",
      port: 50001,
      url: "ssl://electrum.example.com:50001",
    });
    expect(probe).toHaveBeenNthCalledWith(2, server);
  });

  it("rejects the input when both ssl and tcp probes fail", async () => {
    const probe = vi.fn(async (_server: ElectrumServer) => {
      throw new Error("connection refused");
    });

    await expect(resolveElectrumServerInput("electrum.example.com:50001", probe)).rejects.toThrow(
      /Tried ssl:\/\/ then tcp:\/\//,
    );
    expect(probe).toHaveBeenCalledTimes(2);
  });

  it("rejects an explicit protocol when the connection probe fails", async () => {
    const probe = vi.fn(async (_server: ElectrumServer) => {
      throw new Error("connection refused");
    });

    await expect(
      resolveElectrumServerInput("tcp://electrum.example.com:50001", probe),
    ).rejects.toThrow(/Failed to connect to Electrum server tcp:\/\/electrum\.example\.com:50001/);
    expect(probe).toHaveBeenCalledTimes(1);
  });
});
