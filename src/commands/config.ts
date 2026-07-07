import { Command } from "commander";
import {
  buildElectrumServer,
  clearDefaultFeeLevel,
  DEFAULT_FEE_LEVEL,
  FEE_LEVELS,
  getAuthProfile,
  getDefaultElectrumServer,
  getDefaultFeeLevel,
  getElectrumServerFromConfig,
  getEphemeralKeypair,
  getNetwork,
  hasElectrumProtocol,
  isFeeLevel,
  loadConfig,
  parseElectrumAddress,
  parseElectrumServer,
  resetElectrumServer,
  requireEmail,
  saveConfig,
  setDefaultFeeLevel,
  setElectrumServer,
  type ElectrumServer,
} from "../core/config.js";
import { ElectrumClient } from "../core/electrum.js";
import { print, printError } from "../output.js";

type ElectrumProbe = (server: ElectrumServer) => Promise<void>;

export async function probeElectrumServer(server: ElectrumServer): Promise<void> {
  const electrum = new ElectrumClient();
  try {
    await electrum.connect(server.host, server.port, server.protocol);
    await electrum.serverVersion("nunchuk-cli", "1.4");
  } finally {
    electrum.close();
  }
}

export async function resolveElectrumServerInput(
  serverInput: string,
  probe: ElectrumProbe = probeElectrumServer,
): Promise<ElectrumServer> {
  if (hasElectrumProtocol(serverInput)) {
    const server = parseElectrumServer(serverInput);
    try {
      await probe(server);
      return server;
    } catch (err) {
      throw new Error(
        `Failed to connect to Electrum server ${server.url}: ${(err as Error).message}`,
        {
          cause: err,
        },
      );
    }
  }

  const { host, port } = parseElectrumAddress(serverInput);
  const candidates = [
    buildElectrumServer("ssl", host, port),
    buildElectrumServer("tcp", host, port),
  ] as const;
  const failures: string[] = [];

  for (const candidate of candidates) {
    try {
      await probe(candidate);
      return candidate;
    } catch (err) {
      failures.push(`${candidate.protocol}: ${(err as Error).message}`);
    }
  }

  throw new Error(
    `Failed to connect to Electrum server ${host}:${port}. Tried ssl:// then tcp://. ${failures.join(" | ")}`,
  );
}

export const configCommand = new Command("config").description("Show current configuration");

configCommand
  .command("show")
  .description("Display all config values")
  .action((_options, cmd) => {
    const config = loadConfig();
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const profile = getAuthProfile(config, network);
    const ephemeralKeys = getEphemeralKeypair(config, network);
    const electrumServer = getElectrumServerFromConfig(config, network);
    const masked = profile?.apiKey
      ? `${profile.apiKey.slice(0, 8)}...${profile.apiKey.slice(-4)}`
      : "not set";
    const savedFeeLevel = profile?.email ? getDefaultFeeLevel(config, profile.email) : undefined;

    print(
      {
        network,
        apiKey: masked,
        email: profile?.email ?? "not set",
        ephemeralPub: ephemeralKeys?.pub ?? "not generated",
        ephemeralPriv: ephemeralKeys?.priv ? "(hidden)" : "not generated",
        electrumServer: electrumServer.url,
        electrumServerSource: config[network]?.electrumServer ? "custom" : "default",
        defaultFeeLevel: savedFeeLevel ?? `${DEFAULT_FEE_LEVEL} (default)`,
      },
      cmd,
    );
  });

const electrumCommand = new Command("electrum").description(
  "Manage the Electrum server for the selected network",
);

electrumCommand
  .command("get")
  .description("Show the active Electrum server")
  .action((_options, cmd) => {
    const config = loadConfig();
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const electrumServer = getElectrumServerFromConfig(config, network);
    const defaultServer = getDefaultElectrumServer(network);

    print(
      {
        network,
        electrumServer: electrumServer.url,
        electrumServerSource: config[network]?.electrumServer ? "custom" : "default",
        defaultElectrumServer: defaultServer.url,
      },
      cmd,
    );
  });

electrumCommand
  .command("set")
  .description("Set a custom Electrum server")
  .argument("<server>", 'Electrum endpoint, for example "ssl://host:port" or "host:port"')
  .action(async (server, _options, cmd) => {
    try {
      const config = loadConfig();
      const globals = cmd.optsWithGlobals();
      const network = getNetwork(globals.network);
      const resolvedServer = await resolveElectrumServerInput(server);
      const electrumServer = setElectrumServer(config, network, resolvedServer.url);
      saveConfig(config);

      print(
        {
          network,
          electrumServer: electrumServer.url,
          electrumServerSource: "custom",
          input: server,
          message: `Electrum server set for ${network}`,
        },
        cmd,
      );
    } catch (err) {
      printError(
        {
          error: "INVALID_ELECTRUM_SERVER",
          message: (err as Error).message,
        },
        cmd,
      );
    }
  });

electrumCommand
  .command("reset")
  .description("Reset the Electrum server to the network default")
  .action((_options, cmd) => {
    const config = loadConfig();
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const electrumServer = resetElectrumServer(config, network);
    saveConfig(config);

    print(
      {
        network,
        electrumServer: electrumServer.url,
        electrumServerSource: "default",
        message: `Electrum server reset for ${network}`,
      },
      cmd,
    );
  });

configCommand.addCommand(electrumCommand);

const feeRateCommand = new Command("fee-rate").description(
  "Manage the default fee rate level for the active account",
);

feeRateCommand
  .command("get")
  .description("Show the active account's default fee rate level")
  .action((_options, cmd) => {
    const config = loadConfig();
    const globals = cmd.optsWithGlobals();
    const email = requireEmail(globals.network);
    const level = getDefaultFeeLevel(config, email);

    print(
      {
        defaultFeeLevel: level ?? DEFAULT_FEE_LEVEL,
        source: level ? "custom" : "default",
      },
      cmd,
    );
  });

feeRateCommand
  .command("set")
  .description("Set the default fee rate level for the active account")
  .argument("<level>", `Fee level: ${FEE_LEVELS.join(", ")}`)
  .action((level: string, _options, cmd) => {
    const globals = cmd.optsWithGlobals();
    if (!isFeeLevel(level)) {
      printError(
        {
          error: "INVALID_FEE_LEVEL",
          message: `Fee level must be one of: ${FEE_LEVELS.join(", ")}`,
        },
        cmd,
      );
      return;
    }
    const config = loadConfig();
    const email = requireEmail(globals.network);
    setDefaultFeeLevel(config, email, level);
    saveConfig(config);

    print(
      {
        defaultFeeLevel: level,
        source: "custom",
        message: `Default fee rate set to ${level} for ${email}`,
      },
      cmd,
    );
  });

feeRateCommand
  .command("reset")
  .description("Remove the saved default fee rate level (falls back to the built-in default)")
  .action((_options, cmd) => {
    const config = loadConfig();
    const globals = cmd.optsWithGlobals();
    const email = requireEmail(globals.network);
    clearDefaultFeeLevel(config, email);
    saveConfig(config);

    print(
      {
        defaultFeeLevel: DEFAULT_FEE_LEVEL,
        source: "default",
        message: `Default fee rate reset for ${email}`,
      },
      cmd,
    );
  });

configCommand.addCommand(feeRateCommand);
