import { Command } from "commander";
import { loadConfig, saveConfig, type Network } from "../core/config.js";
import { print, printError } from "../output.js";

const VALID_NETWORKS: Network[] = ["mainnet", "testnet"];

export const networkCommand = new Command("network").description(
  "Select network (mainnet or testnet)",
);

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
