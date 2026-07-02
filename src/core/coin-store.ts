// Coin-control state (lock, tags, collections, change-tag intents), stored as
// ONE encrypted JSON document per wallet in the coin_control table — the same
// AES-256-GCM format as the wallets and keys tables. Nothing about the wallet's
// coins (txids, addresses, names) is readable from the database file alone.
//
// A coin's entry is created the first time the CLI records anything about it
// and is kept afterward (locked = false means unlocked): entry presence doubles
// as the "seen before" marker for collection rules.
//
// Every mutation is a read-modify-write of the whole document and MUST run
// inside runInTransaction so racing CLI processes serialize instead of losing
// updates.

import type { Network } from "./config.js";
import {
  decrypt,
  encrypt,
  getDatabase,
  getOrCreateMasterKey,
  runInTransaction,
} from "./storage.js";

export interface CoinControlEntry {
  locked: boolean;
  tags: number[];
  collections: number[];
}

export interface CoinTag {
  id: number;
  name: string;
}

export interface CoinCollection {
  id: number;
  name: string;
  addUntagged: boolean;
  autoLock: boolean;
  addTags: number[];
}

export interface ChangeTagIntent {
  address: string;
  // Sats as a decimal string (JSON has no bigint).
  amount: string;
  tagIds: number[];
  createdAt: string;
}

export interface CoinControlDoc {
  version: 1;
  // Keyed by "<txid>:<vout>".
  coins: Record<string, CoinControlEntry>;
  tags: CoinTag[];
  collections: CoinCollection[];
  changeTagIntents: ChangeTagIntent[];
  // Monotonic counters — ids are never reused after deletion, so stale
  // references (collection rules, pending intents) can't point at a new object.
  nextTagId: number;
  nextCollectionId: number;
}

export interface CoinMeta {
  txid: string;
  vout: number;
  locked: boolean;
}

export function outpointKey(txid: string, vout: number): string {
  return `${txid}:${vout}`;
}

function emptyDoc(): CoinControlDoc {
  return {
    version: 1,
    coins: {},
    tags: [],
    collections: [],
    changeTagIntents: [],
    nextTagId: 1,
    nextCollectionId: 1,
  };
}

function decodeDoc(blob: Uint8Array): CoinControlDoc {
  const doc = JSON.parse(decrypt(Buffer.from(blob), getOrCreateMasterKey())) as CoinControlDoc;
  if (doc.version !== 1) {
    throw new Error(`Unsupported coin-control document version: ${String(doc.version)}`);
  }
  return doc;
}

// Read-only load. Returns an empty document when the wallet has none yet.
export function loadCoinControl(email: string, network: Network, walletId: string): CoinControlDoc {
  const db = getDatabase(email, network, { create: false });
  if (!db) return emptyDoc();
  const row = db.prepare("SELECT encrypted FROM coin_control WHERE wallet_id = ?").get(walletId) as
    | { encrypted: Uint8Array }
    | undefined;
  if (!row) return emptyDoc();
  return decodeDoc(row.encrypted);
}

// Read-modify-write inside a transaction. `fn` mutates the document (or returns
// a new one); the result is re-encrypted and written back atomically.
export function mutateCoinControl<T>(
  email: string,
  network: Network,
  walletId: string,
  fn: (doc: CoinControlDoc) => T,
): T {
  const db = getDatabase(email, network, { create: true });
  if (!db) throw new Error("Storage database unavailable");
  return runInTransaction(db, () => {
    const row = db
      .prepare("SELECT encrypted FROM coin_control WHERE wallet_id = ?")
      .get(walletId) as { encrypted: Uint8Array } | undefined;
    const doc = row ? decodeDoc(row.encrypted) : emptyDoc();
    const result = fn(doc);
    const blob = encrypt(JSON.stringify(doc), getOrCreateMasterKey());
    db.prepare(
      `INSERT INTO coin_control (wallet_id, encrypted) VALUES (?, ?)
       ON CONFLICT(wallet_id) DO UPDATE SET encrypted = excluded.encrypted`,
    ).run(walletId, blob);
    return result;
  });
}

// Returns the coin's entry, creating it (unlocked, untagged) if absent.
export function ensureCoinEntry(doc: CoinControlDoc, txid: string, vout: number): CoinControlEntry {
  const key = outpointKey(txid, vout);
  let entry = doc.coins[key];
  if (!entry) {
    entry = { locked: false, tags: [], collections: [] };
    doc.coins[key] = entry;
  }
  return entry;
}

// ── Lock state ───────────────────────────────────────────────────────

export function getCoinMeta(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
): CoinMeta | null {
  const entry = loadCoinControl(email, network, walletId).coins[outpointKey(txid, vout)];
  if (!entry) return null;
  return { txid, vout, locked: entry.locked };
}

export function listCoinMeta(email: string, network: Network, walletId: string): CoinMeta[] {
  const doc = loadCoinControl(email, network, walletId);
  return Object.entries(doc.coins).map(([key, entry]) => {
    const sep = key.lastIndexOf(":");
    return { txid: key.slice(0, sep), vout: Number(key.slice(sep + 1)), locked: entry.locked };
  });
}

// Convenience: returns "<txid>:<vout>" keys for all locked coins on the wallet.
// Used by createTransaction to filter locked UTXOs out of automatic selection.
export function getLockedOutpoints(email: string, network: Network, walletId: string): Set<string> {
  const doc = loadCoinControl(email, network, walletId);
  const set = new Set<string>();
  for (const [key, entry] of Object.entries(doc.coins)) {
    if (entry.locked) set.add(key);
  }
  return set;
}

export function setCoinLock(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
  locked: boolean,
): void {
  mutateCoinControl(email, network, walletId, (doc) => {
    ensureCoinEntry(doc, txid, vout).locked = locked;
  });
}

export function isCoinLocked(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
): boolean {
  return getCoinMeta(email, network, walletId, txid, vout)?.locked === true;
}
