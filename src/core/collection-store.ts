// Coin collections: named groups of coins with optional membership rules
// (add-untagged, add-tag filters) and an auto-lock action, mirroring the mobile
// app's collection settings. Stored in the wallet's encrypted coin-control
// document (coin-store.ts).
//
// Name semantics: case-SENSITIVE, unique per wallet, whitespace ALLOWED inside
// (unlike tags — the app's own example is "auto lock"). Rule flags are stored
// here; the scan-time rule engine that evaluates them lives elsewhere. Auto-lock
// is membership semantics, not a scan rule: it fires once, on insert.

import type { Network } from "./config.js";
import type { CoinCollection, CoinControlDoc } from "./coin-store.js";
import { ensureCoinEntry, loadCoinControl, mutateCoinControl, outpointKey } from "./coin-store.js";
import { applyRulesToExistingCoins, joinCollection } from "./coin-rules.js";
import { getTagByName } from "./tag-store.js";
import type { TaggedCoinDetail } from "./tag-store.js";

const MAX_COLLECTION_NAME_LENGTH = 64;

export function validateCollectionName(raw: string): string {
  if (raw.length === 0) {
    throw new Error("Collection name must not be empty.");
  }
  if (raw !== raw.trim()) {
    throw new Error("Collection name must not start or end with whitespace.");
  }
  if (raw.startsWith("-")) {
    throw new Error("Collection name must not start with a hyphen.");
  }
  if (raw.length > MAX_COLLECTION_NAME_LENGTH) {
    throw new Error(`Collection name must be at most ${MAX_COLLECTION_NAME_LENGTH} characters.`);
  }
  return raw;
}

// Exact-match lookup (case-sensitive). On a miss, the error lists
// case-insensitive near-matches instead of fuzzy-matching.
export function getCollectionByName(doc: CoinControlDoc, rawName: string): CoinCollection {
  const name = validateCollectionName(rawName);
  const collection = doc.collections.find((c) => c.name === name);
  if (collection) return collection;
  const near = doc.collections.filter((c) => c.name.toLowerCase() === name.toLowerCase());
  const hint = near.length > 0 ? ` Did you mean ${near.map((c) => `"${c.name}"`).join(", ")}?` : "";
  throw new Error(`No collection "${name}".${hint} (Collection names are case-sensitive.)`);
}

export interface CollectionRules {
  addUntagged: boolean;
  autoLock: boolean;
  // Tag NAMES; resolved to ids (with near-miss errors) at write time.
  addTagNames: string[];
}

export function createCollection(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
  rules: CollectionRules,
): CoinCollection {
  const name = validateCollectionName(rawName);
  return mutateCoinControl(email, network, walletId, (doc) => {
    if (doc.collections.some((c) => c.name === name)) {
      throw new Error(`Collection "${name}" already exists.`);
    }
    const addTags: number[] = [];
    for (const tagName of rules.addTagNames) {
      const tag = getTagByName(doc, tagName);
      if (!addTags.includes(tag.id)) addTags.push(tag.id);
    }
    const collection: CoinCollection = {
      id: doc.nextCollectionId,
      name,
      addUntagged: rules.addUntagged,
      autoLock: rules.autoLock,
      addTags,
    };
    doc.nextCollectionId += 1;
    doc.collections.push(collection);
    return collection;
  });
}

export interface CollectionUpdate {
  name?: string;
  addUntagged?: boolean;
  autoLock?: boolean;
  // Appended to the rule's tag list (idempotent). Mutually exclusive with
  // clearAddTags at the command layer.
  addTagNames?: string[];
  clearAddTags?: boolean;
}

export function updateCollection(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
  update: CollectionUpdate,
): CoinCollection {
  const newName = update.name === undefined ? undefined : validateCollectionName(update.name);
  return mutateCoinControl(email, network, walletId, (doc) => {
    const collection = getCollectionByName(doc, rawName);
    if (newName !== undefined) {
      if (doc.collections.some((c) => c.name === newName && c.id !== collection.id)) {
        throw new Error(`Collection "${newName}" already exists.`);
      }
      collection.name = newName;
    }
    if (update.addUntagged !== undefined) collection.addUntagged = update.addUntagged;
    if (update.autoLock !== undefined) collection.autoLock = update.autoLock;
    if (update.clearAddTags) collection.addTags = [];
    if (update.addTagNames !== undefined) {
      for (const tagName of update.addTagNames) {
        const tag = getTagByName(doc, tagName);
        if (!collection.addTags.includes(tag.id)) collection.addTags.push(tag.id);
      }
    }
    return collection;
  });
}

export interface CollectionSummary {
  id: number;
  name: string;
  addUntagged: boolean;
  autoLock: boolean;
  addTagNames: string[];
  coinCount: number;
}

export function listCollections(
  email: string,
  network: Network,
  walletId: string,
): CollectionSummary[] {
  const doc = loadCoinControl(email, network, walletId);
  const counts = new Map<number, number>();
  for (const entry of Object.values(doc.coins)) {
    for (const id of entry.collections) counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  const tagNameById = new Map(doc.tags.map((t) => [t.id, t.name]));
  return doc.collections.map((c) => ({
    id: c.id,
    name: c.name,
    addUntagged: c.addUntagged,
    autoLock: c.autoLock,
    addTagNames: c.addTags
      .map((id) => tagNameById.get(id))
      .filter((n): n is string => n !== undefined),
    coinCount: counts.get(c.id) ?? 0,
  }));
}

// Deletes the collection and its memberships. Locks acquired via auto-lock are
// kept (matching the app: deleting a collection never unlocks coins).
export function deleteCollection(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
): void {
  mutateCoinControl(email, network, walletId, (doc) => {
    const collection = getCollectionByName(doc, rawName);
    doc.collections = doc.collections.filter((c) => c.id !== collection.id);
    for (const entry of Object.values(doc.coins)) {
      entry.collections = entry.collections.filter((id) => id !== collection.id);
    }
  });
}

// Idempotent membership insert. Auto-lock fires once, on insert — re-adding an
// existing member does not re-lock a coin the user has since unlocked.
export function addCoinToCollection(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
  rawName: string,
): CoinCollection {
  return mutateCoinControl(email, network, walletId, (doc) => {
    const collection = getCollectionByName(doc, rawName);
    joinCollection(ensureCoinEntry(doc, txid, vout), collection);
    return collection;
  });
}

// One-shot --apply-to-existing: run the collection's rules over every known
// coin. Returns the number of coins that newly joined.
export function applyCollectionToExisting(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
): { name: string; joined: number } {
  return mutateCoinControl(email, network, walletId, (doc) => {
    const collection = getCollectionByName(doc, rawName);
    return { name: collection.name, joined: applyRulesToExistingCoins(doc, collection) };
  });
}

// Removes membership only; an auto-locked coin stays locked.
export function removeCoinFromCollection(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
  rawName: string,
): CoinCollection {
  return mutateCoinControl(email, network, walletId, (doc) => {
    const collection = getCollectionByName(doc, rawName);
    const entry = doc.coins[outpointKey(txid, vout)];
    if (entry) {
      entry.collections = entry.collections.filter((id) => id !== collection.id);
    }
    return collection;
  });
}

export interface CollectionDetail {
  id: number;
  name: string;
  addUntagged: boolean;
  autoLock: boolean;
  addTagNames: string[];
  coins: TaggedCoinDetail[];
}

// Local-only detail view: the collection's rules plus every member coin (lock
// state + tags). Includes coins that have since been spent — the spendable
// view is `coin list --collection`.
export function getCollectionDetail(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
): CollectionDetail {
  const doc = loadCoinControl(email, network, walletId);
  const collection = getCollectionByName(doc, rawName);
  const tagNameById = new Map(doc.tags.map((t) => [t.id, t.name]));
  const coins: TaggedCoinDetail[] = [];
  for (const [key, entry] of Object.entries(doc.coins)) {
    if (!entry.collections.includes(collection.id)) continue;
    const sep = key.lastIndexOf(":");
    coins.push({
      txid: key.slice(0, sep),
      vout: Number(key.slice(sep + 1)),
      locked: entry.locked,
      tags: entry.tags.map((id) => tagNameById.get(id)).filter((n): n is string => n !== undefined),
    });
  }
  return {
    id: collection.id,
    name: collection.name,
    addUntagged: collection.addUntagged,
    autoLock: collection.autoLock,
    addTagNames: collection.addTags
      .map((id) => tagNameById.get(id))
      .filter((n): n is string => n !== undefined),
    coins,
  };
}

// Resolves a collection and returns the outpoint keys of its member coins.
export function getOutpointsByCollection(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
): { name: string; outpoints: Set<string> } {
  const doc = loadCoinControl(email, network, walletId);
  const collection = getCollectionByName(doc, rawName);
  const outpoints = new Set<string>();
  for (const [key, entry] of Object.entries(doc.coins)) {
    if (entry.collections.includes(collection.id)) outpoints.add(key);
  }
  return { name: collection.name, outpoints };
}

// Collection names per outpoint key, for display (the coin list collections line).
export function getCoinCollectionNames(
  email: string,
  network: Network,
  walletId: string,
): Map<string, string[]> {
  const doc = loadCoinControl(email, network, walletId);
  const nameById = new Map(doc.collections.map((c) => [c.id, c.name]));
  const result = new Map<string, string[]>();
  for (const [key, entry] of Object.entries(doc.coins)) {
    if (entry.collections.length === 0) continue;
    const names = entry.collections
      .map((id) => nameById.get(id))
      .filter((n): n is string => n !== undefined);
    if (names.length > 0) result.set(key, names);
  }
  return result;
}
