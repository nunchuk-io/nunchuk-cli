import { Command } from "commander";
import {
  getElectrumServer,
  getNetwork,
  loadConfig,
  saveConfig,
  type Network,
} from "../core/config.js";
import { ElectrumClient, parseBlockTime } from "../core/electrum.js";
import { formatDate } from "../core/format.js";
import { print, printError } from "../output.js";

const VALID_NETWORKS: Network[] = ["mainnet", "testnet"];

export const networkCommand = new Command("network").description(
  "Select network (mainnet or testnet)",
);

export interface NetworkTip {
  network: Network;
  height: number;
  blocktime: number;
  datetime: string;
}

export async function fetchNetworkTip(network: Network): Promise<NetworkTip> {
  const server = getElectrumServer(network);
  const electrum = new ElectrumClient();
  try {
    await electrum.connect(server.host, server.port, server.protocol);
    const tip = await electrum.headersSubscribe();
    const blocktime = parseBlockTime(tip.hex);
    return {
      network,
      height: tip.height,
      blocktime,
      datetime: formatDate(blocktime),
    };
  } finally {
    electrum.close();
  }
}

networkCommand
  .command("set")
  .description("Set the active network")
  .argument("<network>", "Network to use (mainnet or testnet)")
  .action((network, _options, cmd) => {
    if (!VALID_NETWORKS.includes(network)) {
      printError(
        {
          error: "INVALID_NETWORK",
          message: `Invalid network. Use: ${VALID_NETWORKS.join(", ")}`,
        },
        cmd,
      );
      return;
    }
    const config = loadConfig();
    config.network = network;
    saveConfig(config);
    print({ network, message: `Network set to ${network}` }, cmd);
  });

networkCommand
  .command("get")
  .description("Show the active network")
  .action((_options, cmd) => {
    const config = loadConfig();
    print({ network: config.network ?? "mainnet" }, cmd);
  });

networkCommand
  .command("tip")
  .description("Show the current chain tip from Electrum")
  .action(async (_options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const network = getNetwork(globals.network);
      print(await fetchNetworkTip(network), cmd);
    } catch (err) {
      printError(
        {
          error: "ELECTRUM_TIP_ERROR",
          message: `Failed to get network tip: ${(err as Error).message}`,
        },
        cmd,
      );
    }
  });
