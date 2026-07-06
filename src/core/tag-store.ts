// Coin tags: reusable labels assigned to individual coins, stored in the
// wallet's encrypted coin-control document (coin-store.ts).
//
// Name semantics match the mobile app: case-SENSITIVE ("TAG" and "tag" are
// different tags), no whitespace, unique per wallet. Input accepts an optional
// leading "#" (the app displays tags as #name); the stored form has none.
// Commands address tags by name; the numeric id is internal and never reused.

import type { Network } from "./config.js";
import type { CoinControlDoc, CoinTag } from "./coin-store.js";
import { ensureCoinEntry, loadCoinControl, mutateCoinControl, outpointKey } from "./coin-store.js";
import { applyTagAddedRules } from "./coin-rules.js";

const MAX_TAG_NAME_LENGTH = 64;

// Returns the canonical tag name (leading "#" stripped) or throws.
export function validateTagName(raw: string): string {
  const name = raw.startsWith("#") ? raw.slice(1) : raw;
  if (name.length === 0) {
    throw new Error("Tag name must not be empty.");
  }
  if (/\s/.test(name)) {
    throw new Error("Tag name must not contain whitespace.");
  }
  if (name.startsWith("-")) {
    throw new Error("Tag name must not start with a hyphen.");
  }
  if (name.length > MAX_TAG_NAME_LENGTH) {
    throw new Error(`Tag name must be at most ${MAX_TAG_NAME_LENGTH} characters.`);
  }
  return name;
}

// Exact-match lookup (case-sensitive). On a miss, the error lists
// case-insensitive near-matches instead of fuzzy-matching.
export function getTagByName(doc: CoinControlDoc, rawName: string): CoinTag {
  const name = validateTagName(rawName);
  const tag = doc.tags.find((t) => t.name === name);
  if (tag) return tag;
  const near = doc.tags.filter((t) => t.name.toLowerCase() === name.toLowerCase());
  const hint = near.length > 0 ? ` Did you mean ${near.map((t) => `"${t.name}"`).join(", ")}?` : "";
  throw new Error(`No tag "${name}".${hint} (Tag names are case-sensitive.)`);
}

export function createTag(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
): CoinTag {
  const name = validateTagName(rawName);
  return mutateCoinControl(email, network, walletId, (doc) => {
    if (doc.tags.some((t) => t.name === name)) {
      throw new Error(`Tag "${name}" already exists.`);
    }
    const tag: CoinTag = { id: doc.nextTagId, name };
    doc.nextTagId += 1;
    doc.tags.push(tag);
    return tag;
  });
}

export interface TagSummary extends CoinTag {
  coinCount: number;
}

export function listTags(email: string, network: Network, walletId: string): TagSummary[] {
  const doc = loadCoinControl(email, network, walletId);
  const counts = new Map<number, number>();
  for (const entry of Object.values(doc.coins)) {
    for (const id of entry.tags) counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  return doc.tags.map((t) => ({ ...t, coinCount: counts.get(t.id) ?? 0 }));
}

export function renameTag(
  email: string,
  network: Network,
  walletId: string,
  rawOldName: string,
  rawNewName: string,
): CoinTag {
  const newName = validateTagName(rawNewName);
  return mutateCoinControl(email, network, walletId, (doc) => {
    const tag = getTagByName(doc, rawOldName);
    if (doc.tags.some((t) => t.name === newName && t.id !== tag.id)) {
      throw new Error(`Tag "${newName}" already exists.`);
    }
    tag.name = newName;
    return tag;
  });
}

// Deletes the tag and every reference to it: coin assignments, collection
// add-tag rules, and pending change-tag intents. The id is never reused.
export function deleteTag(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
): void {
  mutateCoinControl(email, network, walletId, (doc) => {
    const tag = getTagByName(doc, rawName);
    doc.tags = doc.tags.filter((t) => t.id !== tag.id);
    for (const entry of Object.values(doc.coins)) {
      entry.tags = entry.tags.filter((id) => id !== tag.id);
    }
    for (const collection of doc.collections) {
      collection.addTags = collection.addTags.filter((id) => id !== tag.id);
    }
    for (const intent of doc.changeTagIntents) {
      intent.tagIds = intent.tagIds.filter((id) => id !== tag.id);
    }
  });
}

export function addCoinTag(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
  rawName: string,
): CoinTag {
  return mutateCoinControl(email, network, walletId, (doc) => {
    const tag = getTagByName(doc, rawName);
    const entry = ensureCoinEntry(doc, txid, vout);
    if (!entry.tags.includes(tag.id)) {
      entry.tags.push(tag.id);
      // The coin joins collections whose rule list has this tag. Fires only on
      // a fresh insert, so re-tagging cannot re-lock an unlocked member.
      applyTagAddedRules(doc, entry, tag.id);
    }
    return tag;
  });
}

export function removeCoinTag(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
  rawName: string,
): CoinTag {
  return mutateCoinControl(email, network, walletId, (doc) => {
    const tag = getTagByName(doc, rawName);
    const entry = doc.coins[outpointKey(txid, vout)];
    if (entry) {
      entry.tags = entry.tags.filter((id) => id !== tag.id);
    }
    return tag;
  });
}

export interface TaggedCoinDetail {
  txid: string;
  vout: number;
  locked: boolean;
  tags: string[];
}

export interface TagDetail extends CoinTag {
  coins: TaggedCoinDetail[];
}

// Local-only detail view: the tag plus every member coin (lock state + tags).
// Includes coins that have since been spent — the spendable view is
// `coin list --tag`.
export function getTagDetail(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
): TagDetail {
  const doc = loadCoinControl(email, network, walletId);
  const tag = getTagByName(doc, rawName);
  const nameById = new Map(doc.tags.map((t) => [t.id, t.name]));
  const coins: TaggedCoinDetail[] = [];
  for (const [key, entry] of Object.entries(doc.coins)) {
    if (!entry.tags.includes(tag.id)) continue;
    const sep = key.lastIndexOf(":");
    coins.push({
      txid: key.slice(0, sep),
      vout: Number(key.slice(sep + 1)),
      locked: entry.locked,
      tags: entry.tags.map((id) => nameById.get(id)).filter((n): n is string => n !== undefined),
    });
  }
  return { ...tag, coins };
}

// Resolves a tag and returns the outpoint keys of the coins carrying it.
// Throws (with near-miss suggestions) when the tag does not exist.
export function getOutpointsByTag(
  email: string,
  network: Network,
  walletId: string,
  rawName: string,
): { name: string; outpoints: Set<string> } {
  const doc = loadCoinControl(email, network, walletId);
  const tag = getTagByName(doc, rawName);
  const outpoints = new Set<string>();
  for (const [key, entry] of Object.entries(doc.coins)) {
    if (entry.tags.includes(tag.id)) outpoints.add(key);
  }
  return { name: tag.name, outpoints };
}

// Tag names per outpoint key, for display (e.g. the coin list tag column).
export function getCoinTagNames(
  email: string,
  network: Network,
  walletId: string,
): Map<string, string[]> {
  const doc = loadCoinControl(email, network, walletId);
  const nameById = new Map(doc.tags.map((t) => [t.id, t.name]));
  const result = new Map<string, string[]>();
  for (const [key, entry] of Object.entries(doc.coins)) {
    if (entry.tags.length === 0) continue;
    const names = entry.tags
      .map((id) => nameById.get(id))
      .filter((n): n is string => n !== undefined);
    if (names.length > 0) result.set(key, names);
  }
  return result;
}
