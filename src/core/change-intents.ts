// Change-tag inheritance intents. The app prompts the user to copy the parent
// coins' tags onto the change output; the CLI does it automatically at
// tx create: the chosen tags are stored as a pending intent keyed by the CHANGE
// ADDRESS (single-use, so it identifies the change coin regardless of the final
// txid or who broadcasts). A scan-time reconciliation pass applies the tags
// when the change coin first appears.

import type { Network } from "./config.js";
import { loadCoinControl, mutateCoinControl, outpointKey } from "./coin-store.js";
import { getTagByName } from "./tag-store.js";

export interface ChangeTagPlan {
  tagIds: number[];
  tagNames: string[];
}

// Resolve the tags the change coin should inherit.
// requested: undefined → all tags carried by the input coins (the default);
// "none" → nothing; otherwise a comma-separated list that must be a subset of
// the input coins' tags (inheritance copies, it never invents classification).
export function planChangeTags(
  email: string,
  network: Network,
  walletId: string,
  inputs: Array<{ txid: string; vout: number }>,
  requested?: string,
): ChangeTagPlan {
  const doc = loadCoinControl(email, network, walletId);
  const unionIds: number[] = [];
  for (const input of inputs) {
    const entry = doc.coins[outpointKey(input.txid, input.vout)];
    for (const id of entry?.tags ?? []) {
      if (!unionIds.includes(id)) unionIds.push(id);
    }
  }
  const nameById = new Map(doc.tags.map((t) => [t.id, t.name]));

  if (requested === undefined) {
    const tagIds = unionIds.filter((id) => nameById.has(id));
    return { tagIds, tagNames: tagIds.map((id) => nameById.get(id)!) };
  }
  if (requested.trim() === "none") {
    return { tagIds: [], tagNames: [] };
  }

  const tagIds: number[] = [];
  const tagNames: string[] = [];
  for (const raw of requested.split(",")) {
    const item = raw.trim();
    if (item.length === 0) continue;
    const tag = getTagByName(doc, item);
    if (!unionIds.includes(tag.id)) {
      throw new Error(`Tag "#${tag.name}" is not on any selected input coin.`);
    }
    if (!tagIds.includes(tag.id)) {
      tagIds.push(tag.id);
      tagNames.push(tag.name);
    }
  }
  return { tagIds, tagNames };
}

// Record the intent. An identical (address, amount) pair replaces the older
// intent — re-creating the same transaction must not stack duplicates; distinct
// amounts on a shared address are kept (concurrent drafts, amount tiebreak).
export function storeChangeTagIntent(
  email: string,
  network: Network,
  walletId: string,
  intent: { address: string; amountSats: bigint; tagIds: number[] },
): void {
  const amount = intent.amountSats.toString();
  mutateCoinControl(email, network, walletId, (doc) => {
    doc.changeTagIntents = doc.changeTagIntents.filter(
      (i) => !(i.address === intent.address && i.amount === amount),
    );
    doc.changeTagIntents.push({
      address: intent.address,
      amount,
      tagIds: intent.tagIds,
      createdAt: new Date().toISOString(),
    });
  });
}
