// Collection rule engine. The app applies collection rules on events
// (AutoAddNewCoins on transaction insert, AddToCoinTag walks); the CLI has no
// daemon, so rules run lazily at the equivalent moments: first-seen detection
// during any UTXO scan, a tag-added hook, and the one-shot --apply-to-existing
// walk. Membership is apply-on-arrival: joins are never re-evaluated and never
// auto-removed; auto-lock fires once, on insert.

import type { Network } from "./config.js";
import type { CoinCollection, CoinControlDoc, CoinControlEntry } from "./coin-store.js";
import { ensureCoinEntry, loadCoinControl, mutateCoinControl, outpointKey } from "./coin-store.js";

// Idempotent membership insert; returns whether the coin newly joined.
export function joinCollection(entry: CoinControlEntry, collection: CoinCollection): boolean {
  if (entry.collections.includes(collection.id)) return false;
  entry.collections.push(collection.id);
  if (collection.autoLock) entry.locked = true;
  return true;
}

// First-seen rules: an untagged new coin joins every add-untagged collection.
// Tag-carrying coins (change-tag intents applied earlier in the same scan) are
// deliberately excluded — divergence from the app, documented in the design.
export function applyFirstSeenRules(doc: CoinControlDoc, entry: CoinControlEntry): void {
  if (entry.tags.length > 0) return;
  for (const collection of doc.collections) {
    if (collection.addUntagged) joinCollection(entry, collection);
  }
}

// Tag-added rules: the coin joins every collection whose rule list has the tag.
export function applyTagAddedRules(
  doc: CoinControlDoc,
  entry: CoinControlEntry,
  tagId: number,
): void {
  for (const collection of doc.collections) {
    if (collection.addTags.includes(tagId)) joinCollection(entry, collection);
  }
}

// One-shot --apply-to-existing walk over every known coin; returns join count.
export function applyRulesToExistingCoins(doc: CoinControlDoc, collection: CoinCollection): number {
  let joined = 0;
  for (const entry of Object.values(doc.coins)) {
    const matches =
      (collection.addUntagged && entry.tags.length === 0) ||
      entry.tags.some((id) => collection.addTags.includes(id));
    if (matches && joinCollection(entry, collection)) joined += 1;
  }
  return joined;
}

// Scan-time reconciliation: record every scanned outpoint as seen and run
// first-seen rules on the ones without an entry. Runs before the calling
// command consumes the scan, so a new coin is already collected and locked
// when it is first listed or considered for selection. A scan with no unseen
// coins writes nothing.
export function reconcileNewCoins(
  email: string,
  network: Network,
  walletId: string,
  scanned: Array<{ txid: string; vout: number }>,
): void {
  if (scanned.length === 0) return;
  const current = loadCoinControl(email, network, walletId);
  if (scanned.every((c) => current.coins[outpointKey(c.txid, c.vout)] !== undefined)) return;
  mutateCoinControl(email, network, walletId, (doc) => {
    for (const c of scanned) {
      if (doc.coins[outpointKey(c.txid, c.vout)]) continue;
      const entry = ensureCoinEntry(doc, c.txid, c.vout);
      applyFirstSeenRules(doc, entry);
    }
  });
}
