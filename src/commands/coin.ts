import { Command, InvalidArgumentError } from "commander";
import { getElectrumServer, getNetwork, requireApiKey, requireEmail } from "../core/config.js";
import type { Network } from "../core/config.js";
import { ApiClient } from "../core/api-client.js";
import { ElectrumClient } from "../core/electrum.js";
import { loadWallet } from "../core/storage.js";
import type { WalletData } from "../core/storage.js";
import { listCoins, type CoinDetail, type CoinStatus } from "../core/coins.js";
import { getLockedOutpoints, setCoinLock } from "../core/coin-store.js";
import {
  addCoinTag,
  createTag,
  deleteTag,
  getCoinTagNames,
  getTagDetail,
  listTags,
  removeCoinTag,
  renameTag,
} from "../core/tag-store.js";
import type { TaggedCoinDetail } from "../core/tag-store.js";
import {
  addCoinToCollection,
  applyCollectionToExisting,
  createCollection,
  deleteCollection,
  getCoinCollectionNames,
  getCollectionDetail,
  listCollections,
  removeCoinFromCollection,
  updateCollection,
} from "../core/collection-store.js";
import { reconcileNewCoins } from "../core/coin-rules.js";
import { formatBtc, formatDateTime, formatSats } from "../core/format.js";
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

type Outpoint = { txid: string; vout: number };

// Repeatable --coin collector (same grammar as tx create --coin).
function parseCoinOption(value: string, previous: Outpoint[] | undefined): Outpoint[] {
  const match = /^([0-9a-fA-F]{64}):(\d+)$/.exec(value);
  if (!match) {
    throw new InvalidArgumentError(
      "--coin must be <txid>:<vout> (64-character hex transaction ID, then the output index)",
    );
  }
  return [...(previous ?? []), { txid: match[1].toLowerCase(), vout: Number(match[2]) }];
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

// Scan the wallet's live coins (Electrum unspent set + group-server statuses)
// and run the coin-control reconciliation pass on the result.
async function scanAndReconcileCoins(
  apiKey: string,
  network: Network,
  email: string,
  wallet: WalletData,
): Promise<CoinDetail[]> {
  const client = new ApiClient(apiKey, network);
  const server = getElectrumServer(network);
  const electrum = new ElectrumClient();
  let coins: CoinDetail[];
  try {
    await electrum.connect(server.host, server.port, server.protocol);
    await electrum.serverVersion("nunchuk-cli", "1.4");
    coins = await listCoins({ wallet, network, electrum, client });
  } finally {
    electrum.close();
  }
  // Change-tag intents and first-seen collection rules run before the caller
  // consumes the scan, so a new coin already shows its inherited tags,
  // rule-applied collections, and lock.
  reconcileNewCoins(
    email,
    network,
    wallet.walletId,
    coins.map((c) => ({ txid: c.txid, vout: c.vout, address: c.address, amountSats: c.amount })),
  );
  return coins;
}

// A locally recorded tag/collection member joined with its live coin (absent
// when the coin is no longer in the wallet's unspent set).
type MemberCoin = TaggedCoinDetail & { live?: CoinDetail };

function joinMembersWithLiveCoins(
  members: TaggedCoinDetail[],
  liveCoins: CoinDetail[],
): { coins: MemberCoin[]; spentCount: number; totalSats: bigint } {
  const byOutpoint = new Map(liveCoins.map((c) => [`${c.txid}:${c.vout}`, c]));
  const coins = members.map((m) => ({ ...m, live: byOutpoint.get(`${m.txid}:${m.vout}`) }));
  let totalSats = 0n;
  let spentCount = 0;
  for (const c of coins) {
    if (c.live) totalSats += c.live.amount;
    else spentCount += 1;
  }
  return { coins, spentCount, totalSats };
}

function describeMemberCount(count: number, spentCount: number): string {
  return `${count} coin${count === 1 ? "" : "s"}${spentCount > 0 ? `, ${spentCount} spent` : ""}`;
}

function memberCoinJson(c: MemberCoin): Record<string, unknown> {
  return {
    txid: c.txid,
    vout: c.vout,
    locked: c.locked,
    tags: c.tags,
    spent: !c.live,
    ...(c.live
      ? {
          amount: c.live.amount.toString(),
          amountBtc: formatBtc(c.live.amount),
          status: c.live.status,
          blocktime: c.live.blocktime,
          receivedAt: c.live.blocktime > 0 ? formatDateTime(c.live.blocktime) : null,
        }
      : {}),
  };
}

function printMemberCoinLines(coins: MemberCoin[]): void {
  if (coins.length === 0) {
    console.log("  Coins: none");
    return;
  }
  console.log("  Coins:");
  for (const c of coins) {
    const labels = `${c.locked ? " [locked]" : ""}${c.live ? "" : " [spent]"}`;
    const amount = c.live ? `  ${formatBtc(c.live.amount)} (${formatSats(c.live.amount)})` : "";
    const receivedAt = c.live
      ? `  ${c.live.blocktime > 0 ? formatDateTime(c.live.blocktime) : "unconfirmed"}`
      : "";
    const tags = c.tags.length > 0 ? `  ${c.tags.map((t) => `#${t}`).join(" ")}` : "";
    console.log(`    ${c.txid}:${c.vout}${labels}${amount}${receivedAt}${tags}`);
  }
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
      const coins = await scanAndReconcileCoins(apiKey, network, email, wallet);

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
              blocktime: c.blocktime,
              receivedAt: c.blocktime > 0 ? formatDateTime(c.blocktime) : null,
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
        if (c.blocktime > 0) {
          console.log(`     Received: ${formatDateTime(c.blocktime)}`);
        }
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
  .description("Lock coins so automatic coin selection skips them (spend explicitly with --coin)")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint; repeat for multiple", parseCoinOption)
  .action((options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const coins = options.coin as Outpoint[];
      for (const { txid, vout } of coins) {
        setCoinLock(email, network, wallet.walletId, txid, vout, true);
      }

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ coins, locked: true }, cmd);
        return;
      }
      for (const { txid, vout } of coins) {
        console.log(`Locked ${txid}:${vout}`);
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

coinCommand
  .command("unlock")
  .description("Unlock coins so automatic coin selection can use them again")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint; repeat for multiple", parseCoinOption)
  .action((options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const coins = options.coin as Outpoint[];
      for (const { txid, vout } of coins) {
        setCoinLock(email, network, wallet.walletId, txid, vout, false);
      }

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ coins, locked: false }, cmd);
        return;
      }
      for (const { txid, vout } of coins) {
        console.log(`Unlocked ${txid}:${vout}`);
      }
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
  .command("get")
  .description("Show a tag's member coins with live amounts and the spendable total")
  .argument("<name>", "Tag name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .action(async (name, options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const liveCoins = await scanAndReconcileCoins(apiKey, network, email, wallet);
      const detail = getTagDetail(email, network, wallet.walletId, name);
      const { coins, spentCount, totalSats } = joinMembersWithLiveCoins(detail.coins, liveCoins);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            id: detail.id,
            name: detail.name,
            coinCount: coins.length,
            spentCount,
            total: totalSats.toString(),
            totalBtc: formatBtc(totalSats),
            coins: coins.map(memberCoinJson),
          },
          cmd,
        );
        return;
      }
      console.log(`#${detail.name} (${describeMemberCount(coins.length, spentCount)})`);
      console.log(`  Total: ${formatBtc(totalSats)} (${formatSats(totalSats)})`);
      printMemberCoinLines(coins);
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
  .description("Add a tag to one or more coins")
  .argument("<name>", "Tag name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint; repeat for multiple", parseCoinOption)
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const coins = options.coin as Outpoint[];
      let tagName = "";
      for (const { txid, vout } of coins) {
        tagName = addCoinTag(email, network, wallet.walletId, txid, vout, name).name;
      }

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ tag: tagName, coins }, cmd);
        return;
      }
      for (const { txid, vout } of coins) {
        console.log(`Tagged ${txid}:${vout} with #${tagName}`);
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

tagCommand
  .command("remove")
  .description("Remove a tag from one or more coins")
  .argument("<name>", "Tag name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint; repeat for multiple", parseCoinOption)
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const coins = options.coin as Outpoint[];
      let tagName = "";
      for (const { txid, vout } of coins) {
        tagName = removeCoinTag(email, network, wallet.walletId, txid, vout, name).name;
      }

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ tag: tagName, coins }, cmd);
        return;
      }
      for (const { txid, vout } of coins) {
        console.log(`Removed #${tagName} from ${txid}:${vout}`);
      }
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
  .option("--apply-to-existing", "Also run the rules over currently known coins once")
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const collection = createCollection(email, network, wallet.walletId, name, {
        addUntagged: Boolean(options.addUntagged),
        autoLock: Boolean(options.autoLock),
        addTagNames: options.addTag as string[],
      });
      const joined = options.applyToExisting
        ? applyCollectionToExisting(email, network, wallet.walletId, collection.name).joined
        : undefined;

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            id: collection.id,
            name: collection.name,
            addUntagged: collection.addUntagged,
            autoLock: collection.autoLock,
            addTags: options.addTag,
            ...(joined !== undefined ? { appliedToExisting: joined } : {}),
          },
          cmd,
        );
        return;
      }
      console.log(`Created collection "${collection.name}"`);
      if (joined !== undefined) {
        console.log(`Added ${joined} existing coin${joined === 1 ? "" : "s"}.`);
      }
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
  .option("--apply-to-existing", "Run the rules over currently known coins once")
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const addTagNames = options.addTag as string[];
      if (options.clearAddTags && addTagNames.length > 0) {
        throw new Error("--add-tag and --clear-add-tags cannot be combined.");
      }
      const hasPatch =
        options.name !== undefined ||
        options.addUntagged !== undefined ||
        options.autoLock !== undefined ||
        Boolean(options.clearAddTags) ||
        addTagNames.length > 0;
      if (!hasPatch && !options.applyToExisting) {
        throw new Error("Nothing to update. Pass at least one option.");
      }
      const collection = hasPatch
        ? updateCollection(email, network, wallet.walletId, name, {
            name: options.name,
            addUntagged: options.addUntagged,
            autoLock: options.autoLock,
            addTagNames: addTagNames.length > 0 ? addTagNames : undefined,
            clearAddTags: Boolean(options.clearAddTags),
          })
        : undefined;
      const currentName = collection?.name ?? name;
      const joined = options.applyToExisting
        ? applyCollectionToExisting(email, network, wallet.walletId, currentName).joined
        : undefined;

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            name: currentName,
            ...(collection
              ? {
                  id: collection.id,
                  addUntagged: collection.addUntagged,
                  autoLock: collection.autoLock,
                }
              : {}),
            ...(joined !== undefined ? { appliedToExisting: joined } : {}),
          },
          cmd,
        );
        return;
      }
      if (collection) {
        console.log(`Updated collection "${collection.name}"`);
      }
      if (joined !== undefined) {
        console.log(`Added ${joined} existing coin${joined === 1 ? "" : "s"}.`);
      }
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
  .command("get")
  .description(
    "Show a collection's rules and member coins with live amounts and the spendable total",
  )
  .argument("<name>", "Collection name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .action(async (name, options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const liveCoins = await scanAndReconcileCoins(apiKey, network, email, wallet);
      const detail = getCollectionDetail(email, network, wallet.walletId, name);
      const { coins, spentCount, totalSats } = joinMembersWithLiveCoins(detail.coins, liveCoins);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            id: detail.id,
            name: detail.name,
            addUntagged: detail.addUntagged,
            autoLock: detail.autoLock,
            addTags: detail.addTagNames,
            coinCount: coins.length,
            spentCount,
            total: totalSats.toString(),
            totalBtc: formatBtc(totalSats),
            coins: coins.map(memberCoinJson),
          },
          cmd,
        );
        return;
      }
      console.log(`"${detail.name}" (${describeMemberCount(coins.length, spentCount)})`);
      console.log(`  Rules: ${describeRules(detail)}`);
      console.log(`  Total: ${formatBtc(totalSats)} (${formatSats(totalSats)})`);
      printMemberCoinLines(coins);
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
  .description("Add one or more coins to a collection (locks them if the collection auto-locks)")
  .argument("<name>", "Collection name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint; repeat for multiple", parseCoinOption)
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const coins = options.coin as Outpoint[];
      let collectionName = "";
      for (const { txid, vout } of coins) {
        collectionName = addCoinToCollection(
          email,
          network,
          wallet.walletId,
          txid,
          vout,
          name,
        ).name;
      }

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ collection: collectionName, coins }, cmd);
        return;
      }
      for (const { txid, vout } of coins) {
        console.log(`Added ${txid}:${vout} to "${collectionName}"`);
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

collectionCommand
  .command("remove")
  .description("Remove one or more coins from a collection (they keep their lock state)")
  .argument("<name>", "Collection name")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--coin <txid:vout>", "Coin outpoint; repeat for multiple", parseCoinOption)
  .action((name, options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const coins = options.coin as Outpoint[];
      let collectionName = "";
      for (const { txid, vout } of coins) {
        collectionName = removeCoinFromCollection(
          email,
          network,
          wallet.walletId,
          txid,
          vout,
          name,
        ).name;
      }

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ collection: collectionName, coins }, cmd);
        return;
      }
      for (const { txid, vout } of coins) {
        console.log(`Removed ${txid}:${vout} from "${collectionName}"`);
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
