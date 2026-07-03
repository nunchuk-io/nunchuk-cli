import { Command, InvalidArgumentError } from "commander";
import { getElectrumServer, getNetwork, requireApiKey, requireEmail } from "../core/config.js";
import type { Network } from "../core/config.js";
import { ApiClient } from "../core/api-client.js";
import { ElectrumClient } from "../core/electrum.js";
import { loadWallet } from "../core/storage.js";
import type { WalletData } from "../core/storage.js";
import { listCoins, type CoinStatus } from "../core/coins.js";
import { getLockedOutpoints, setCoinLock } from "../core/coin-store.js";
import {
  addCoinTag,
  createTag,
  deleteTag,
  getCoinTagNames,
  listTags,
  removeCoinTag,
  renameTag,
} from "../core/tag-store.js";
import {
  addCoinToCollection,
  createCollection,
  deleteCollection,
  getCoinCollectionNames,
  listCollections,
  removeCoinFromCollection,
  updateCollection,
} from "../core/collection-store.js";
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
  .option("--tag <name>", "Only coins carrying this tag (case-sensitive)")
  .option("--untagged", "Only coins with no tags")
  .option("--collection <name>", "Only coins in this collection (case-sensitive)")
  .action(async (options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      if (options.tag && options.untagged) {
        throw new Error("--tag and --untagged cannot be combined.");
      }
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
      const tagNames = getCoinTagNames(email, network, wallet.walletId);
      const collectionNames = getCoinCollectionNames(email, network, wallet.walletId);
      const isLocked = (c: { txid: string; vout: number }): boolean =>
        locked.has(`${c.txid}:${c.vout}`);
      const tagsOf = (c: { txid: string; vout: number }): string[] =>
        tagNames.get(`${c.txid}:${c.vout}`) ?? [];
      const collectionsOf = (c: { txid: string; vout: number }): string[] =>
        collectionNames.get(`${c.txid}:${c.vout}`) ?? [];

      if (options.tag) {
        const wanted = String(options.tag).startsWith("#")
          ? String(options.tag).slice(1)
          : String(options.tag);
        filtered = filtered.filter((c) => tagsOf(c).includes(wanted));
      } else if (options.untagged) {
        filtered = filtered.filter((c) => tagsOf(c).length === 0);
      }
      if (options.collection) {
        filtered = filtered.filter((c) => collectionsOf(c).includes(String(options.collection)));
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
              locked: isLocked(c),
              tags: tagsOf(c),
              collections: collectionsOf(c),
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
        const tags = tagsOf(c);
        if (tags.length > 0) {
          console.log(`     Tags: ${tags.map((t) => `#${t}`).join(" ")}`);
        }
        const collections = collectionsOf(c);
        if (collections.length > 0) {
          // Collection names may contain spaces, so join with commas.
          console.log(`     Collections: ${collections.join(", ")}`);
        }
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

const tagCommand = new Command("tag").description(
  "Manage coin tags (reusable labels; names are case-sensitive, no whitespace)",
);
coinCommand.addCommand(tagCommand);

tagCommand
  .command("create")
  .description("Create a tag")
  .argument("<name>", "Tag name (no whitespace; a leading # is accepted and stripped)")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const tag = createTag(email, network, wallet.walletId, name);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ id: tag.id, name: tag.name }, cmd);
        return;
      }
      console.log(`Created tag #${tag.name}`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

tagCommand
  .command("list")
  .description("List tags with their coin counts")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .action((options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const tags = listTags(email, network, wallet.walletId);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ tags: tags.map((t) => ({ id: t.id, name: t.name, coinCount: t.coinCount })) }, cmd);
        return;
      }
      if (tags.length === 0) {
        console.log("No tags.");
        return;
      }
      for (const t of tags) {
        console.log(`  #${t.name} (${t.coinCount} coin${t.coinCount === 1 ? "" : "s"})`);
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

tagCommand
  .command("rename")
  .description("Rename a tag (coins keep the tag)")
  .argument("<name>", "Current tag name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--name <new-name>", "New tag name")
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const tag = renameTag(email, network, wallet.walletId, name, options.name);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ id: tag.id, name: tag.name }, cmd);
        return;
      }
      console.log(`Renamed tag to #${tag.name}`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

tagCommand
  .command("delete")
  .description("Delete a tag and remove it from every coin")
  .argument("<name>", "Tag name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      deleteTag(email, network, wallet.walletId, name);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ deleted: true }, cmd);
        return;
      }
      console.log("Tag deleted.");
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

tagCommand
  .command("add")
  .description("Add a tag to a coin")
  .argument("<name>", "Tag name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint (txid:vout)", parseCoinOption)
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const { txid, vout } = options.coin as { txid: string; vout: number };
      const tag = addCoinTag(email, network, wallet.walletId, txid, vout, name);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ txid, vout, tag: tag.name }, cmd);
        return;
      }
      console.log(`Tagged ${txid}:${vout} with #${tag.name}`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

tagCommand
  .command("remove")
  .description("Remove a tag from a coin")
  .argument("<name>", "Tag name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint (txid:vout)", parseCoinOption)
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const { txid, vout } = options.coin as { txid: string; vout: number };
      const tag = removeCoinTag(email, network, wallet.walletId, txid, vout, name);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ txid, vout, tag: tag.name }, cmd);
        return;
      }
      console.log(`Removed #${tag.name} from ${txid}:${vout}`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

function collectTag(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function describeRules(c: {
  addUntagged: boolean;
  autoLock: boolean;
  addTagNames: string[];
}): string {
  const rules: string[] = [];
  if (c.addUntagged) rules.push("add-untagged");
  for (const t of c.addTagNames) rules.push(`add-tag #${t}`);
  if (c.autoLock) rules.push("auto-lock");
  return rules.length > 0 ? rules.join(", ") : "none";
}

const collectionCommand = new Command("collection").description(
  "Manage coin collections (named groups with optional auto-membership rules)",
);
coinCommand.addCommand(collectionCommand);

collectionCommand
  .command("create")
  .description("Create a collection")
  .argument("<name>", "Collection name (case-sensitive; spaces allowed)")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .option("--add-untagged", "Rule: new coins without tags join this collection")
  .option("--add-tag <tag>", "Rule: coins carrying this tag join (repeatable)", collectTag, [])
  .option("--auto-lock", "Lock coins when they join this collection")
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const collection = createCollection(email, network, wallet.walletId, name, {
        addUntagged: Boolean(options.addUntagged),
        autoLock: Boolean(options.autoLock),
        addTagNames: options.addTag as string[],
      });

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            id: collection.id,
            name: collection.name,
            addUntagged: collection.addUntagged,
            autoLock: collection.autoLock,
            addTags: options.addTag,
          },
          cmd,
        );
        return;
      }
      console.log(`Created collection "${collection.name}"`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

collectionCommand
  .command("update")
  .description("Update a collection's name or rules (members are kept)")
  .argument("<name>", "Current collection name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .option("--name <new-name>", "New collection name")
  .option("--add-untagged", "Rule on: new coins without tags join this collection")
  .option("--no-add-untagged", "Rule off: stop adding untagged coins")
  .option("--add-tag <tag>", "Add a tag to the join rule (repeatable)", collectTag, [])
  .option("--clear-add-tags", "Remove every tag from the join rule")
  .option("--auto-lock", "Rule on: lock coins when they join")
  .option("--no-auto-lock", "Rule off: stop locking joining coins")
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const addTagNames = options.addTag as string[];
      if (options.clearAddTags && addTagNames.length > 0) {
        throw new Error("--add-tag and --clear-add-tags cannot be combined.");
      }
      if (
        options.name === undefined &&
        options.addUntagged === undefined &&
        options.autoLock === undefined &&
        !options.clearAddTags &&
        addTagNames.length === 0
      ) {
        throw new Error("Nothing to update. Pass at least one option.");
      }
      const collection = updateCollection(email, network, wallet.walletId, name, {
        name: options.name,
        addUntagged: options.addUntagged,
        autoLock: options.autoLock,
        addTagNames: addTagNames.length > 0 ? addTagNames : undefined,
        clearAddTags: Boolean(options.clearAddTags),
      });

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            id: collection.id,
            name: collection.name,
            addUntagged: collection.addUntagged,
            autoLock: collection.autoLock,
          },
          cmd,
        );
        return;
      }
      console.log(`Updated collection "${collection.name}"`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

collectionCommand
  .command("list")
  .description("List collections with their rules and coin counts")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .action((options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const collections = listCollections(email, network, wallet.walletId);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            collections: collections.map((c) => ({
              id: c.id,
              name: c.name,
              addUntagged: c.addUntagged,
              autoLock: c.autoLock,
              addTags: c.addTagNames,
              coinCount: c.coinCount,
            })),
          },
          cmd,
        );
        return;
      }
      if (collections.length === 0) {
        console.log("No collections.");
        return;
      }
      for (const c of collections) {
        console.log(`  "${c.name}" (${c.coinCount} coin${c.coinCount === 1 ? "" : "s"})`);
        console.log(`     Rules: ${describeRules(c)}`);
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

collectionCommand
  .command("delete")
  .description("Delete a collection (member coins keep their lock state)")
  .argument("<name>", "Collection name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      deleteCollection(email, network, wallet.walletId, name);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ deleted: true }, cmd);
        return;
      }
      console.log("Collection deleted.");
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

collectionCommand
  .command("add")
  .description("Add a coin to a collection (locks the coin if the collection auto-locks)")
  .argument("<name>", "Collection name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint (txid:vout)", parseCoinOption)
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const { txid, vout } = options.coin as { txid: string; vout: number };
      const collection = addCoinToCollection(email, network, wallet.walletId, txid, vout, name);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ txid, vout, collection: collection.name }, cmd);
        return;
      }
      console.log(`Added ${txid}:${vout} to "${collection.name}"`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

collectionCommand
  .command("remove")
  .description("Remove a coin from a collection (the coin keeps its lock state)")
  .argument("<name>", "Collection name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint (txid:vout)", parseCoinOption)
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const { txid, vout } = options.coin as { txid: string; vout: number };
      const collection = removeCoinFromCollection(
        email,
        network,
        wallet.walletId,
        txid,
        vout,
        name,
      );

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ txid, vout, collection: collection.name }, cmd);
        return;
      }
      console.log(`Removed ${txid}:${vout} from "${collection.name}"`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
