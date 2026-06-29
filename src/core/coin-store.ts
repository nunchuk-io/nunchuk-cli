// Per-coin memo + lock state, stored in the per-account/network SQLite database.
// Not encrypted — these are user-controlled metadata, not secrets. The SQLite
// file itself is restricted via chmod 600 in storage.ts.
//
// Schema: coins(wallet_id, txid, vout, memo, locked) — see storage.ts.
// Reference (data model only, not on-chain): libnunchuk UnspentOutput::get_memo /
// is_locked (include/nunchuk.h).

import type { Network } from "./config.js";
import { getDatabase } from "./storage.js";

export interface CoinMeta {
  txid: string;
  vout: number;
  memo: string | null;
  locked: boolean;
}

interface CoinRow {
  txid: unknown;
  vout: unknown;
  memo: unknown;
  locked: unknown;
}

function rowToMeta(row: CoinRow): CoinMeta {
  return {
    txid: String(row.txid),
    vout: Number(row.vout),
    memo: typeof row.memo === "string" ? row.memo : null,
    locked: Number(row.locked) === 1,
  };
}

export function getCoinMeta(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
): CoinMeta | null {
  const db = getDatabase(email, network, { create: false });
  if (!db) return null;
  const row = db
    .prepare(
      "SELECT txid, vout, memo, locked FROM coins WHERE wallet_id = ? AND txid = ? AND vout = ?",
    )
    .get(walletId, txid, vout) as CoinRow | undefined;
  if (!row) return null;
  return rowToMeta(row);
}

export function listCoinMeta(email: string, network: Network, walletId: string): CoinMeta[] {
  const db = getDatabase(email, network, { create: false });
  if (!db) return [];
  const rows = db
    .prepare("SELECT txid, vout, memo, locked FROM coins WHERE wallet_id = ?")
    .all(walletId) as CoinRow[];
  return rows.map(rowToMeta);
}

// Convenience: returns "<txid>:<vout>" keys for all locked coins on the wallet.
// Used by createTransaction to filter locked UTXOs out of selection.
export function getLockedOutpoints(email: string, network: Network, walletId: string): Set<string> {
  const db = getDatabase(email, network, { create: false });
  if (!db) return new Set();
  const rows = db
    .prepare("SELECT txid, vout FROM coins WHERE wallet_id = ? AND locked = 1")
    .all(walletId) as { txid: unknown; vout: unknown }[];
  const set = new Set<string>();
  for (const row of rows) {
    set.add(`${String(row.txid)}:${Number(row.vout)}`);
  }
  return set;
}

export function setCoinMemo(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
  memo: string | null,
): void {
  const db = getDatabase(email, network, { create: true });
  if (!db) throw new Error("Storage database unavailable");
  upsertCoin(db, walletId, txid, vout, { memo });
}

export function setCoinLock(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
  locked: boolean,
): void {
  const db = getDatabase(email, network, { create: true });
  if (!db) throw new Error("Storage database unavailable");
  upsertCoin(db, walletId, txid, vout, { locked });
}

export function isCoinLocked(
  email: string,
  network: Network,
  walletId: string,
  txid: string,
  vout: number,
): boolean {
  const meta = getCoinMeta(email, network, walletId, txid, vout);
  return meta?.locked === true;
}

// Upserts a coin row, preserving fields not in `patch`. After the update, if
// the row would carry no information (memo=null AND locked=0), the row is
// deleted to keep the table tidy.
function upsertCoin(
  db: ReturnType<typeof getDatabase>,
  walletId: string,
  txid: string,
  vout: number,
  patch: { memo?: string | null; locked?: boolean },
): void {
  if (!db) return;
  const existing = db
    .prepare("SELECT memo, locked FROM coins WHERE wallet_id = ? AND txid = ? AND vout = ?")
    .get(walletId, txid, vout) as CoinRow | undefined;
  const memo: string | null =
    patch.memo !== undefined
      ? patch.memo
      : typeof existing?.memo === "string"
        ? existing.memo
        : null;
  const locked: number =
    patch.locked !== undefined
      ? patch.locked
        ? 1
        : 0
      : existing
        ? Number(existing.locked) === 1
          ? 1
          : 0
        : 0;

  if (memo === null && locked === 0) {
    db.prepare("DELETE FROM coins WHERE wallet_id = ? AND txid = ? AND vout = ?").run(
      walletId,
      txid,
      vout,
    );
    return;
  }

  db.prepare(
    `INSERT INTO coins (wallet_id, txid, vout, memo, locked)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(wallet_id, txid, vout)
     DO UPDATE SET memo = excluded.memo, locked = excluded.locked`,
  ).run(walletId, txid, vout, memo, locked);
}
