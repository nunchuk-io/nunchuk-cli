import { Command } from "commander";
import {
  loadConfig,
  saveConfig,
  getApiKey,
  getNetwork,
  getAuthProfile,
  getEphemeralKeypair,
  setAuthProfile,
  clearAuthProfile,
  setEphemeralKeypair,
} from "../core/config.js";
import { generateKeypair } from "../core/crypto.js";
import { ApiClient } from "../core/api-client.js";
import { print, printError } from "../output.js";

async function promptSecret(prompt: string): Promise<string> {
  process.stdout.write(prompt);
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf-8");

    let input = "";
    const onData = (ch: string) => {
      if (ch === "\r" || ch === "\n") {
        stdin.setRawMode(wasRaw ?? false);
        stdin.pause();
        stdin.removeListener("data", onData);
        process.stdout.write("\n");
        resolve(input.trim());
      } else if (ch === "\u007F" || ch === "\b") {
        // backspace
        if (input.length > 0) {
          input = input.slice(0, -1);
        }
      } else if (ch === "\u0003") {
        // Ctrl+C
        process.exit(0);
      } else {
        input += ch;
      }
    };
    stdin.on("data", onData);
  });
}

export const authCommand = new Command("auth").description("Authenticate with the Nunchuk API");

authCommand
  .command("login")
  .description("Login with API secret key")
  .action(async (_options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const apiKey = globals.apiKey || (await promptSecret("Enter API secret key: "));
      if (!apiKey) {
        printError({ error: "INVALID_KEY", message: "API key cannot be empty" }, cmd);
        return;
      }

      // Validate the API key by calling getMe()
      const network = getNetwork(globals.network);
      const client = new ApiClient(apiKey, network);
      const me = await client.getMe();

      const config = loadConfig();
      setAuthProfile(config, network, {
        apiKey,
        email: me.email,
        userId: me.id,
        name: me.name,
      });

      // Generate an ephemeral keypair for the selected network on first login.
      if (
        !getEphemeralKeypair(config, network)?.pub ||
        !getEphemeralKeypair(config, network)?.priv
      ) {
        const kp = generateKeypair();
        setEphemeralKeypair(config, network, {
          pub: kp.pub,
          priv: kp.priv,
        });
      }

      saveConfig(config);

      print({ status: "authenticated", email: me.email }, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

authCommand
  .command("status")
  .description("Check current authentication status")
  .action((_options, cmd) => {
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const apiKey = getApiKey(globals.apiKey, globals.network);
    if (!apiKey) {
      print({ status: "not_authenticated", network }, cmd);
    } else {
      const config = loadConfig();
      const profile = getAuthProfile(config, network);
      const ephemeralKeys = getEphemeralKeypair(config, network);
      const masked = `${apiKey.slice(0, 8)}...${apiKey.slice(-4)}`;
      print(
        {
          status: "authenticated",
          network,
          apiKey: masked,
          email: profile?.email ?? "unknown",
          ephemeralPub: ephemeralKeys?.pub ?? "not generated",
        },
        cmd,
      );
    }
  });

authCommand
  .command("logout")
  .description("Remove stored API key for the selected network")
  .action((_options, cmd) => {
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const config = loadConfig();
    clearAuthProfile(config, network);
    saveConfig(config);
    print({ status: "logged_out", network, message: "Logged out" }, cmd);
  });
