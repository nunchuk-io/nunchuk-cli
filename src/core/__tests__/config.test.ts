import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import {
  clearAuthProfile,
  getDefaultElectrumServer,
  getElectrumServerFromConfig,
  getAuthProfile,
  getConfiguredNetworks,
  getEphemeralKeypair,
  parseElectrumServer,
  resetElectrumServer,
  setElectrumServer,
  setEphemeralKeypair,
  setAuthProfile,
  type Config,
} from "../config.js";
import { saveProfile, type Profile } from "../storage.js";

const { profileStore } = vi.hoisted(() => ({
  profileStore: new Map<string, Profile>(),
}));

vi.mock("../storage.js", () => ({
  saveProfile(email: string, network: "mainnet" | "testnet", profile: Profile) {
    profileStore.set(`${email}:${network}`, { ...profile });
  },
  loadProfile(email: string, network: "mainnet" | "testnet") {
    return (profileStore.get(`${email}:${network}`) as Profile | undefined) ?? null;
  },
}));

// Helper to create a profile for testing read-through functions
function setupProfile(email: string, network: string, data: Partial<Profile>): void {
  const full: Profile = {
    apiKey: data.apiKey ?? "",
    email,
    userId: data.userId ?? "",
    name: data.name ?? "",
    ephemeralPub: data.ephemeralPub ?? "",
    ephemeralPriv: data.ephemeralPriv ?? "",
  };
  saveProfile(email, network as "mainnet" | "testnet", full);
}

beforeEach(() => {
  profileStore.clear();
});

afterEach(() => {
  profileStore.clear();
});

describe("getAuthProfile", () => {
  it("returns profile from encrypted storage via email pointer", () => {
    setupProfile("main@example.com", "mainnet", {
      apiKey: "mainnet-key",
    });
    setupProfile("test@example.com", "testnet", {
      apiKey: "testnet-key",
    });

    const config: Config = {
      mainnet: { email: "main@example.com" },
      testnet: { email: "test@example.com" },
    };

    expect(getAuthProfile(config, "mainnet")).toEqual({
      apiKey: "mainnet-key",
      email: "main@example.com",
      userId: "",
      name: "",
    });
    expect(getAuthProfile(config, "testnet")).toEqual({
      apiKey: "testnet-key",
      email: "test@example.com",
      userId: "",
      name: "",
    });
  });

  it("returns undefined when no email in config", () => {
    const config: Config = {};
    expect(getAuthProfile(config, "mainnet")).toBeUndefined();
  });
});

describe("setAuthProfile", () => {
  it("sets email in config and writes encrypted profile storage", () => {
    const config: Config = {};

    setAuthProfile(config, "testnet", {
      apiKey: "testnet-key",
      email: "test@example.com",
      userId: "u2",
      name: "Test",
    });

    // Config should have email pointer only
    expect(config.testnet).toEqual({ email: "test@example.com" });

    // Profile.json should have full data
    const profile = getAuthProfile(config, "testnet");
    expect(profile).toEqual({
      apiKey: "testnet-key",
      email: "test@example.com",
      userId: "u2",
      name: "Test",
    });
  });
});

describe("clearAuthProfile", () => {
  it("removes email pointer from config, stored profile stays", () => {
    setupProfile("main@example.com", "mainnet", { apiKey: "mainnet-key" });
    setupProfile("test@example.com", "testnet", { apiKey: "testnet-key" });

    const config: Config = {
      mainnet: { email: "main@example.com" },
      testnet: { email: "test@example.com" },
    };

    clearAuthProfile(config, "testnet");

    expect(config.mainnet).toEqual({ email: "main@example.com" });
    expect(config.testnet).toBeUndefined();

    // Stored profile should still exist (can reconnect on next login)
    const mainProfile = getAuthProfile(config, "mainnet");
    expect(mainProfile?.apiKey).toBe("mainnet-key");
  });
});

describe("getConfiguredNetworks", () => {
  it("returns networks with email set", () => {
    const config: Config = {
      mainnet: { email: "main@example.com" },
      testnet: { email: "test@example.com" },
    };

    expect(getConfiguredNetworks(config)).toEqual(["mainnet", "testnet"]);
  });

  it("returns empty for no configured networks", () => {
    const config: Config = {};
    expect(getConfiguredNetworks(config)).toEqual([]);
  });
});

describe("getEphemeralKeypair", () => {
  it("returns keypair from encrypted storage", () => {
    setupProfile("main@example.com", "mainnet", {
      ephemeralPub: "main-pub",
      ephemeralPriv: "main-priv",
    });
    setupProfile("test@example.com", "testnet", {
      ephemeralPub: "test-pub",
      ephemeralPriv: "test-priv",
    });

    const config: Config = {
      mainnet: { email: "main@example.com" },
      testnet: { email: "test@example.com" },
    };

    expect(getEphemeralKeypair(config, "mainnet")).toEqual({
      pub: "main-pub",
      priv: "main-priv",
    });
    expect(getEphemeralKeypair(config, "testnet")).toEqual({
      pub: "test-pub",
      priv: "test-priv",
    });
  });

  it("returns undefined when no email in config", () => {
    const config: Config = {};
    expect(getEphemeralKeypair(config, "mainnet")).toBeUndefined();
  });
});

describe("setEphemeralKeypair", () => {
  it("writes keypair to encrypted storage", () => {
    setupProfile("test@example.com", "testnet", {});

    const config: Config = { testnet: { email: "test@example.com" } };

    setEphemeralKeypair(config, "testnet", {
      pub: "test-pub",
      priv: "test-priv",
    });

    const kp = getEphemeralKeypair(config, "testnet");
    expect(kp).toEqual({ pub: "test-pub", priv: "test-priv" });
  });

  it("preserves existing profile data when setting keypair", () => {
    setupProfile("test@example.com", "testnet", {
      apiKey: "testnet-key",
      userId: "u2",
      name: "Test",
    });

    const config: Config = { testnet: { email: "test@example.com" } };

    setEphemeralKeypair(config, "testnet", {
      pub: "test-pub",
      priv: "test-priv",
    });

    const profile = getAuthProfile(config, "testnet");
    expect(profile?.apiKey).toBe("testnet-key");
  });
});

describe("Electrum server config", () => {
  it("parses ssl electrum servers", () => {
    expect(parseElectrumServer("ssl://mainnet.nunchuk.io:52002")).toEqual({
      protocol: "ssl",
      host: "mainnet.nunchuk.io",
      port: 52002,
      url: "ssl://mainnet.nunchuk.io:52002",
    });
  });

  it("rejects invalid electrum server strings", () => {
    expect(() => parseElectrumServer("mainnet.nunchuk.io:52002")).toThrow(/tcp:\/\/|ssl:\/\//);
    expect(() => parseElectrumServer("http://mainnet.nunchuk.io:52002")).toThrow(
      /tcp:\/\/|ssl:\/\//,
    );
  });

  it("returns the new mainnet default electrum server", () => {
    expect(getDefaultElectrumServer("mainnet")).toEqual({
      protocol: "ssl",
      host: "mainnet.nunchuk.io",
      port: 52002,
      url: "ssl://mainnet.nunchuk.io:52002",
    });
  });

  it("stores and resolves a custom electrum server override", () => {
    const config: Config = {};

    const server = setElectrumServer(config, "mainnet", "ssl://electrum.example.com:60002");

    expect(server).toEqual({
      protocol: "ssl",
      host: "electrum.example.com",
      port: 60002,
      url: "ssl://electrum.example.com:60002",
    });
    expect(config.mainnet).toEqual({
      electrumServer: "ssl://electrum.example.com:60002",
    });
    expect(getElectrumServerFromConfig(config, "mainnet")).toEqual(server);
  });

  it("resets a custom electrum server without dropping auth state", () => {
    const config: Config = {
      mainnet: {
        email: "main@example.com",
        electrumServer: "tcp://electrum.example.com:50001",
      },
    };

    const server = resetElectrumServer(config, "mainnet");

    expect(server).toEqual(getDefaultElectrumServer("mainnet"));
    expect(config.mainnet).toEqual({ email: "main@example.com" });
  });
});
