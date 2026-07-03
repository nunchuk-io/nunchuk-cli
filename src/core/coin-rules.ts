// Collection rule engine. The app applies collection rules on events
// (AutoAddNewCoins on transaction insert, AddToCoinTag walks); the CLI has no
// daemon, so rules run lazily at the equivalent moments: first-seen detection
// during any UTXO scan, a tag-added hook, and the one-shot --apply-to-existing
// walk. Membership is apply-on-arrival: joins are never re-evaluated and never
// auto-removed; auto-lock fires once, on insert.
//
// The same scan pass reconciles pending change-tag intents (change-intents.ts):
// a new coin whose address matches an intent inherits the intent's tags FIRST,
// so tagged change never joins add-untagged collections, and the tag-added
// rules fire for the inherited tags.

import type { Network } from "./config.js";
import type { CoinCollection, CoinControlDoc, CoinControlEntry } from "./coin-store.js";
import { ensureCoinEntry, loadCoinControl, mutateCoinControl, outpointKey } from "./coin-store.js";

// Unmatched intents (replaced drafts, replacements built elsewhere with a new
// change address) are dropped after this window; tags can always be fixed
// manually with `coin tag add`.
const CHANGE_INTENT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

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

// Applies the best-matching pending change-tag intent to a newly seen coin:
// address match, then exact-amount tiebreak (concurrent drafts can share a
// change address), then newest-first. The intent is consumed on match and its
// tags fire the tag-added rules. Matching is txid-independent by design — it
// works for legacy txid changes on signing and for app/backend broadcasts.
export function applyChangeTagIntents(
  doc: CoinControlDoc,
  entry: CoinControlEntry,
  coin: { address: string; amountSats: bigint },
): boolean {
  const candidates = doc.changeTagIntents
    .map((intent, index) => ({ intent, index }))
    .filter((c) => c.intent.address === coin.address);
  if (candidates.length === 0) return false;
  const amount = coin.amountSats.toString();
  const exact = candidates.filter((c) => c.intent.amount === amount);
  const pool = exact.length > 0 ? exact : candidates;
  pool.sort((a, b) => b.intent.createdAt.localeCompare(a.intent.createdAt));
  const matched = pool[0];

  const knownTagIds = new Set(doc.tags.map((t) => t.id));
  for (const tagId of matched.intent.tagIds) {
    if (!knownTagIds.has(tagId) || entry.tags.includes(tagId)) continue;
    entry.tags.push(tagId);
    applyTagAddedRules(doc, entry, tagId);
  }
  doc.changeTagIntents.splice(matched.index, 1);
  return true;
}

function isStaleIntent(createdAt: string, nowMs: number): boolean {
  const created = Date.parse(createdAt);
  return Number.isFinite(created) && created < nowMs - CHANGE_INTENT_RETENTION_MS;
}

// Scan-time reconciliation: record every scanned outpoint as seen; for the
// ones without an entry, apply a matching change-tag intent first, then the
// first-seen rules. Runs before the calling command consumes the scan, so a
// new coin is already tagged, collected, and locked when it is first listed
// or considered for selection. Stale intents are dropped in the same pass.
// A scan with nothing new and nothing stale writes nothing.
export function reconcileNewCoins(
  email: string,
  network: Network,
  walletId: string,
  scanned: Array<{ txid: string; vout: number; address: string; amountSats: bigint }>,
): void {
  if (scanned.length === 0) return;
  const now = Date.now();
  const current = loadCoinControl(email, network, walletId);
  const allSeen = scanned.every((c) => current.coins[outpointKey(c.txid, c.vout)] !== undefined);
  const hasStale = current.changeTagIntents.some((i) => isStaleIntent(i.createdAt, now));
  if (allSeen && !hasStale) return;
  mutateCoinControl(email, network, walletId, (doc) => {
    doc.changeTagIntents = doc.changeTagIntents.filter((i) => !isStaleIntent(i.createdAt, now));
    for (const c of scanned) {
      if (doc.coins[outpointKey(c.txid, c.vout)]) continue;
      const entry = ensureCoinEntry(doc, c.txid, c.vout);
      applyChangeTagIntents(doc, entry, c);
      applyFirstSeenRules(doc, entry);
    }
  });
}
