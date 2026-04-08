import fs from "node:fs";
import { loadProfile, saveProfile, type Profile } from "./storage.js";
import { getCliHome, getConfigFile } from "./paths.js";

export type Network = "mainnet" | "testnet";
export type ElectrumProtocol = "tcp" | "ssl";

// Config.json stores session state only — no secrets.
// Secrets live in encrypted profile storage.

export interface NetworkSession {
  email?: string; // active user for this network
  electrumServer?: string;
}

export interface Config {
  network?: Network;
  mainnet?: NetworkSession;
  testnet?: NetworkSession;
}

export interface AuthProfile {
  apiKey?: string;
  email?: string;
  userId?: string;
  name?: string;
}

export interface EphemeralKeypair {
  pub?: string;
  priv?: string;
}

export interface ElectrumServer {
  protocol: ElectrumProtocol;
  host: string;
  port: number;
  url: string;
}

export interface ElectrumServerAddress {
  host: string;
  port: number;
}

export function getNetwork(flagNetwork?: string): Network {
  return (flagNetwork as Network) || loadConfig().network || "mainnet";
}

export function loadConfig(): Config {
  try {
    const data = fs.readFileSync(getConfigFile(), "utf-8");
    return JSON.parse(data);
  } catch {
    return {};
  }
}

export function saveConfig(config: Config): void {
  fs.mkdirSync(getCliHome(), { recursive: true });
  // Only persist session fields — strip any legacy secrets
  const clean: Config = {};
  if (config.network) clean.network = config.network;
  if (config.mainnet?.email || config.mainnet?.electrumServer) {
    clean.mainnet = {};
    if (config.mainnet.email) clean.mainnet.email = config.mainnet.email;
    if (config.mainnet.electrumServer) clean.mainnet.electrumServer = config.mainnet.electrumServer;
  }
  if (config.testnet?.email || config.testnet?.electrumServer) {
    clean.testnet = {};
    if (config.testnet.email) clean.testnet.email = config.testnet.email;
    if (config.testnet.electrumServer) clean.testnet.electrumServer = config.testnet.electrumServer;
  }
  fs.writeFileSync(getConfigFile(), JSON.stringify(clean, null, 2), { mode: 0o600 });
}

export function deleteConfig(): void {
  try {
    fs.unlinkSync(getConfigFile());
  } catch {
    // ignore if file doesn't exist
  }
}

export function getAuthProfile(config: Config, network: Network): AuthProfile | undefined {
  const email = config[network]?.email;
  if (!email) return undefined;
  const profile = loadProfile(email, network);
  if (!profile) return undefined;
  return {
    apiKey: profile.apiKey,
    email: profile.email,
    userId: profile.userId,
    name: profile.name,
  };
}

export function setAuthProfile(config: Config, network: Network, profile: AuthProfile): void {
  const email = profile.email;
  if (!email) return;

  // Set email pointer in config
  if (!config[network]) config[network] = {};
  config[network]!.email = email;

  // Load existing profile to preserve ephemeral keys
  const existing = loadProfile(email, network);
  const merged: Profile = {
    apiKey: profile.apiKey ?? existing?.apiKey ?? "",
    email,
    userId: profile.userId ?? existing?.userId ?? "",
    name: profile.name ?? existing?.name ?? "",
    ephemeralPub: existing?.ephemeralPub ?? "",
    ephemeralPriv: existing?.ephemeralPriv ?? "",
  };
  saveProfile(email, network, merged);
}

export function clearAuthProfile(config: Config, network: Network): void {
  const email = config[network]?.email;

  // Clear the stored API identity, but keep the ephemeral keypair.
  if (email) {
    const existing = loadProfile(email, network);
    if (existing) {
      existing.apiKey = "";
      existing.userId = "";
      existing.name = "";
      saveProfile(email, network, existing);
    }
  }

  // Clear email pointer from config
  if (config[network]) {
    delete config[network]!.email;
    if (Object.values(config[network]!).every((v) => v === undefined)) {
      delete config[network];
    }
  }
}

export function getConfiguredNetworks(config: Config): Network[] {
  const configured = new Set<Network>();
  for (const network of ["mainnet", "testnet"] as const) {
    if (config[network]?.email) {
      configured.add(network);
    }
  }
  return Array.from(configured);
}

export function getEphemeralKeypair(
  config: Config,
  network: Network,
): EphemeralKeypair | undefined {
  const email = config[network]?.email;
  if (!email) return undefined;
  const profile = loadProfile(email, network);
  if (!profile) return undefined;
  return {
    pub: profile.ephemeralPub || undefined,
    priv: profile.ephemeralPriv || undefined,
  };
}

export function setEphemeralKeypair(
  config: Config,
  network: Network,
  keypair: EphemeralKeypair,
): void {
  const email = config[network]?.email;
  if (!email) return;
  const existing = loadProfile(email, network);
  if (!existing) return;
  existing.ephemeralPub = keypair.pub ?? existing.ephemeralPub;
  existing.ephemeralPriv = keypair.priv ?? existing.ephemeralPriv;
  saveProfile(email, network, existing);
}

export function getApiKey(flagApiKey?: string, flagNetwork?: string): string | undefined {
  if (flagApiKey) {
    return flagApiKey;
  }
  if (process.env.NUNCHUK_API_KEY) {
    return process.env.NUNCHUK_API_KEY;
  }

  const network = getNetwork(flagNetwork);
  return getAuthProfile(loadConfig(), network)?.apiKey;
}

export function requireApiKey(flagApiKey?: string, flagNetwork?: string): string {
  const key = getApiKey(flagApiKey, flagNetwork);
  if (!key) {
    console.error('Error: Not authenticated. Run "nunchuk auth login" first.');
    process.exit(1);
  }
  return key;
}

export function requireEmail(flagNetwork?: string): string {
  const network = getNetwork(flagNetwork);
  const email = loadConfig()[network]?.email;
  if (!email) {
    console.error('Error: No user profile. Run "nunchuk auth login" first.');
    process.exit(1);
  }
  return email;
}

// Electrum server addresses
// Reference: libnunchuk examples/groupwallet.cpp:624-625
const ELECTRUM_SERVERS: Record<Network, string> = {
  mainnet: "ssl://mainnet.nunchuk.io:52002",
  testnet: "tcp://testnet.nunchuk.io:50001",
};

function formatElectrumHost(host: string): string {
  return host.includes(":") ? `[${host}]` : host;
}

export function hasElectrumProtocol(server: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(server);
}

export function buildElectrumServer(
  protocol: ElectrumProtocol,
  host: string,
  port: number,
): ElectrumServer {
  return {
    protocol,
    host,
    port,
    url: `${protocol}://${formatElectrumHost(host)}:${port}`,
  };
}

export function parseElectrumServer(server: string): ElectrumServer {
  let parsed: URL;
  try {
    parsed = new URL(server);
  } catch {
    throw new Error('Electrum server must use "tcp://host:port" or "ssl://host:port"');
  }

  const protocol = parsed.protocol.slice(0, -1);
  if (protocol !== "tcp" && protocol !== "ssl") {
    throw new Error('Electrum server must use "tcp://" or "ssl://"');
  }
  if (!parsed.hostname) {
    throw new Error("Electrum server host is required");
  }
  if (!parsed.port) {
    throw new Error("Electrum server port is required");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Electrum server must not include credentials");
  }
  if (parsed.pathname && parsed.pathname !== "/") {
    throw new Error("Electrum server must not include a path");
  }
  if (parsed.search || parsed.hash) {
    throw new Error("Electrum server must not include query params or fragments");
  }

  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Electrum server port must be between 1 and 65535");
  }

  const host = parsed.hostname;
  return buildElectrumServer(protocol, host, port);
}

export function parseElectrumAddress(server: string): ElectrumServerAddress {
  return parseElectrumServer(`tcp://${server}`);
}

export function getDefaultElectrumServer(network: Network): ElectrumServer {
  return parseElectrumServer(ELECTRUM_SERVERS[network]);
}

export function getElectrumServerFromConfig(config: Config, network: Network): ElectrumServer {
  const server = config[network]?.electrumServer ?? ELECTRUM_SERVERS[network];
  return parseElectrumServer(server);
}

export function setElectrumServer(
  config: Config,
  network: Network,
  server: string,
): ElectrumServer {
  const parsed = parseElectrumServer(server);
  if (!config[network]) config[network] = {};
  config[network]!.electrumServer = parsed.url;
  return parsed;
}

export function resetElectrumServer(config: Config, network: Network): ElectrumServer {
  if (config[network]) {
    delete config[network]!.electrumServer;
    if (Object.values(config[network]!).every((v) => v === undefined)) {
      delete config[network];
    }
  }
  return getDefaultElectrumServer(network);
}

export function getElectrumServer(network: Network): ElectrumServer {
  return getElectrumServerFromConfig(loadConfig(), network);
}
