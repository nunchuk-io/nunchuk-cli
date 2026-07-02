import { Command, InvalidArgumentError } from "commander";
import { getElectrumServer, getNetwork, requireApiKey, requireEmail } from "../core/config.js";
import type { Network } from "../core/config.js";
import { ApiClient } from "../core/api-client.js";
import { ElectrumClient } from "../core/electrum.js";
import { loadWallet } from "../core/storage.js";
import type { WalletData } from "../core/storage.js";
import { listCoins, type CoinStatus } from "../core/coins.js";
import { getLockedOutpoints, setCoinLock } from "../core/coin-store.js";
import { formatBtc, formatSats } from "../core/format.js";
import { print, printError } from "../output.js";

const COIN_STATUSES: CoinStatus[] = [
  "INCOMING_PENDING_CONFIRMATION",
  "CONFIRMED",
  "OUTGOING_PENDING_SIGNATURES",
  "OUTGOING_PENDING_BROADCAST",
  "OUTGOING_PENDING_CONFIRMATION",
  "SPENT",
];

function parseStatusOption(value: string): CoinStatus {
  const upper = value.toUpperCase();
  if (!COIN_STATUSES.includes(upper as CoinStatus)) {
    throw new InvalidArgumentError(`--status must be one of: ${COIN_STATUSES.join(", ")}`);
  }
  return upper as CoinStatus;
}

function parseCoinOption(value: string): { txid: string; vout: number } {
  const match = /^([0-9a-fA-F]{64}):(\d+)$/.exec(value);
  if (!match) {
    throw new InvalidArgumentError(
      "--coin must be <txid>:<vout> (64-character hex transaction ID, then the output index)",
    );
  }
  return { txid: match[1].toLowerCase(), vout: Number(match[2]) };
}

function getGlobals(cmd: Command): { apiKey: string; network: Network; email: string } {
  const globals = cmd.optsWithGlobals();
  return {
    apiKey: requireApiKey(globals.apiKey, globals.network),
    network: getNetwork(globals.network),
    email: requireEmail(globals.network),
  };
}

function requireWallet(email: string, network: Network, walletId: string): WalletData {
  const wallet = loadWallet(email, network, walletId);
  if (!wallet) {
    console.error(
      `Error: Wallet "${walletId}" not found locally. Run "nunchuk wallet finalize" first.`,
    );
    process.exit(1);
  }
  return wallet;
}

export const coinCommand = new Command("coin").description(
  "Inspect and manage wallet UTXOs (coins)",
);

coinCommand
  .command("list")
  .description("List UTXOs (coins) for a wallet with status")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .option(
    "--status <status>",
    `Filter by coin status: ${COIN_STATUSES.join(", ")}`,
    parseStatusOption,
  )
  .action(async (options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const client = new ApiClient(apiKey, network);
      const server = getElectrumServer(network);
      const electrum = new ElectrumClient();
      let coins;
      try {
        await electrum.connect(server.host, server.port, server.protocol);
        await electrum.serverVersion("nunchuk-cli", "1.4");
        coins = await listCoins({ wallet, network, electrum, client });
      } finally {
        electrum.close();
      }

      let filtered = coins;
      if (options.status) {
        filtered = filtered.filter((c) => c.status === options.status);
      }

      const locked = getLockedOutpoints(email, network, wallet.walletId);
      const isLocked = (c: { txid: string; vout: number }): boolean =>
        locked.has(`${c.txid}:${c.vout}`);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            coins: filtered.map((c) => ({
              txid: c.txid,
              vout: c.vout,
              address: c.address,
              amount: c.amount.toString(),
              amountBtc: formatBtc(c.amount),
              height: c.height,
              confirmations: c.confirmations,
              status: c.status,
              isChange: c.isChange,
              locked: isLocked(c),
            })),
          },
          cmd,
        );
        return;
      }

      if (filtered.length === 0) {
        console.log("No coins found.");
        return;
      }

      filtered.forEach((c, i) => {
        const label = `${c.isChange ? " [change]" : ""}${isLocked(c) ? " [locked]" : ""}`;
        console.log(`  ${i}: ${c.txid}:${c.vout}${label}`);
        console.log(`     Address: ${c.address}`);
        console.log(`     Amount: ${formatBtc(c.amount)} (${formatSats(c.amount)})`);
        console.log(`     Status: ${c.status}`);
        console.log(`     Confirmations: ${c.confirmations}`);
      });
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

coinCommand
  .command("lock")
  .description("Lock a coin so automatic coin selection skips it (spend it explicitly with --coin)")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint (txid:vout)", parseCoinOption)
  .action((options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const { txid, vout } = options.coin as { txid: string; vout: number };
      setCoinLock(email, network, wallet.walletId, txid, vout, true);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ txid, vout, locked: true }, cmd);
        return;
      }
      console.log(`Locked ${txid}:${vout}`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

coinCommand
  .command("unlock")
  .description("Unlock a coin so automatic coin selection can use it again")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint (txid:vout)", parseCoinOption)
  .action((options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const { txid, vout } = options.coin as { txid: string; vout: number };
      setCoinLock(email, network, wallet.walletId, txid, vout, false);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ txid, vout, locked: false }, cmd);
        return;
      }
      console.log(`Unlocked ${txid}:${vout}`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
