import { Command, InvalidArgumentError } from "commander";
import { getElectrumServer, getNetwork, requireApiKey, requireEmail } from "../core/config.js";
import type { Network } from "../core/config.js";
import { ApiClient } from "../core/api-client.js";
import { ElectrumClient } from "../core/electrum.js";
import { loadWallet } from "../core/storage.js";
import type { WalletData } from "../core/storage.js";
import { listCoins, type CoinStatus } from "../core/coins.js";
import { setCoinLock, setCoinMemo } from "../core/coin-store.js";
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
  const idx = value.lastIndexOf(":");
  if (idx <= 0 || idx === value.length - 1) {
    throw new InvalidArgumentError("--coin must be in the form <txid>:<vout>");
  }
  const txid = value.slice(0, idx);
  const voutStr = value.slice(idx + 1);
  if (!/^[0-9a-fA-F]{64}$/.test(txid)) {
    throw new InvalidArgumentError("--coin txid must be a 64-char hex string");
  }
  const vout = Number(voutStr);
  if (!Number.isSafeInteger(vout) || vout < 0) {
    throw new InvalidArgumentError("--coin vout must be a non-negative integer");
  }
  return { txid, vout };
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
  "List, lock, unlock, and annotate wallet UTXOs (coins)",
);

coinCommand
  .command("list")
  .description("List UTXOs (coins) for a wallet with status, memo, and lock flag")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .option(
    "--status <status>",
    `Filter by coin status: ${COIN_STATUSES.join(", ")}`,
    parseStatusOption,
  )
  .option("--include-locked", "Include locked coins (default: included)", true)
  .option("--no-include-locked", "Exclude locked coins")
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
        coins = await listCoins({ email, wallet, network, electrum, client });
      } finally {
        electrum.close();
      }

      let filtered = coins;
      if (options.status) {
        filtered = filtered.filter((c) => c.status === options.status);
      }
      if (!options.includeLocked) {
        filtered = filtered.filter((c) => !c.locked);
      }

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
              memo: c.memo,
              locked: c.locked,
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
        const labels: string[] = [];
        if (c.isChange) labels.push("change");
        if (c.locked) labels.push("locked");
        const label = labels.length > 0 ? ` [${labels.join(", ")}]` : "";
        console.log(`  ${i}: ${c.txid}:${c.vout}${label}`);
        console.log(`     Address: ${c.address}`);
        console.log(`     Amount: ${formatBtc(c.amount)} (${formatSats(c.amount)})`);
        console.log(`     Status: ${c.status}`);
        console.log(`     Confirmations: ${c.confirmations}`);
        if (c.memo) console.log(`     Memo: ${c.memo}`);
      });
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

coinCommand
  .command("lock")
  .description("Lock a coin so coin selection skips it on subsequent transactions")
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
  .description("Unlock a previously locked coin")
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

coinCommand
  .command("memo")
  .description("Set or clear a coin's memo")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint (txid:vout)", parseCoinOption)
  .option("--set <text>", 'Memo text to attach (use --set "" to clear)')
  .action((options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const { txid, vout } = options.coin as { txid: string; vout: number };
      const memo: string | null =
        options.set === undefined || options.set === "" ? null : String(options.set);
      setCoinMemo(email, network, wallet.walletId, txid, vout, memo);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ txid, vout, memo }, cmd);
        return;
      }
      console.log(
        memo == null ? `Cleared memo for ${txid}:${vout}` : `Memo set for ${txid}:${vout}`,
      );
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
