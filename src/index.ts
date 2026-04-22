#!/usr/bin/env node

import { Command } from "commander";
import { authCommand } from "./commands/auth.js";
import { networkCommand } from "./commands/network.js";
import { sandboxCommand } from "./commands/sandbox.js";
import { invitationCommand } from "./commands/invitation.js";
import { walletCommand } from "./commands/wallet.js";
import { miniscriptCommand } from "./commands/miniscript.js";
import { txCommand } from "./commands/tx.js";
import { configCommand } from "./commands/config.js";
import { currencyCommand } from "./commands/currency.js";
import { keyCommand } from "./commands/key.js";

const program = new Command();

program
  .name("nunchuk")
  .description("Nunchuk CLI for group wallet management")
  .version("0.1.0")
  .option("--json", "Output in JSON format")
  .option("--api-key <key>", "Override stored API key for this command")
  .option("--network <network>", "Override network (mainnet or testnet)");

program.addCommand(authCommand);
program.addCommand(networkCommand);
program.addCommand(sandboxCommand);
program.addCommand(invitationCommand);
program.addCommand(walletCommand);
program.addCommand(miniscriptCommand);
program.addCommand(txCommand);
program.addCommand(configCommand);
program.addCommand(currencyCommand);
program.addCommand(keyCommand);

program.parse();
