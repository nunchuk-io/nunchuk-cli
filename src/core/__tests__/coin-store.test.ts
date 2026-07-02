import { afterAll, beforeEach, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import {
  _clearMasterKeyCache,
  _closeDatabase,
  _deleteAccountData,
  emailHash,
  saveProfile,
} from "../storage.js";
import type { Profile } from "../storage.js";
import {
  getCoinMeta,
  getLockedOutpoints,
  isCoinLocked,
  listCoinMeta,
  setCoinLock,
} from "../coin-store.js";

const TEST_RUN_ID = crypto.randomBytes(4).toString("hex");
const TEST_HOME = path.join(os.tmpdir(), "nunchuk-cli-coin-store", TEST_RUN_ID);
process.env.NUNCHUK_CLI_HOME = TEST_HOME;

const createdEmails: string[] = [];
let counter = 0;
function uniqueEmail(): string {
  const email = `coin-store-${TEST_RUN_ID}-${++counter}@test.local`;
  createdEmails.push(email);
  return email;
}

const FAKE_PROFILE: Profile = {
  apiKey: "k",
  email: "x",
  userId: "u",
  name: "n",
  ephemeralPub: "p",
  ephemeralPriv: "v",
};

function bootstrap(email: string): void {
  // Initialise the per-account DB by writing a profile. The schema (incl. coins) is set up here.
  saveProfile(email, "testnet", { ...FAKE_PROFILE, email });
}

beforeEach(() => {
  _closeDatabase();
  _clearMasterKeyCache();
});

afterAll(() => {
  _closeDatabase();
  for (const email of createdEmails) _deleteAccountData(email);
  _closeDatabase();
  fs.rmSync(TEST_HOME, { recursive: true, force: true });
  delete process.env.NUNCHUK_CLI_HOME;
});

const TXID = "00".repeat(32);
const TXID_B = "11".repeat(32);
const WALLET_ID = "test-wallet";

describe("coin-store lock state", () => {
  it("returns null for an unknown coin", () => {
    const email = uniqueEmail();
    bootstrap(email);
    expect(getCoinMeta(email, "testnet", WALLET_ID, TXID, 0)).toBeNull();
    expect(isCoinLocked(email, "testnet", WALLET_ID, TXID, 0)).toBe(false);
  });

  it("locks and unlocks a coin", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 0, true);
    expect(isCoinLocked(email, "testnet", WALLET_ID, TXID, 0)).toBe(true);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 0, false);
    expect(isCoinLocked(email, "testnet", WALLET_ID, TXID, 0)).toBe(false);
  });

  it("keeps the row after unlock (row presence marks the coin as seen)", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 0, true);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 0, false);
    expect(getCoinMeta(email, "testnet", WALLET_ID, TXID, 0)).toEqual({
      txid: TXID,
      vout: 0,
      locked: false,
    });
  });

  it("tracks lock state per outpoint, not per transaction", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 1, true);
    expect(isCoinLocked(email, "testnet", WALLET_ID, TXID, 0)).toBe(false);
    expect(isCoinLocked(email, "testnet", WALLET_ID, TXID, 1)).toBe(true);
  });

  it("getLockedOutpoints returns only locked coins as txid:vout keys", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 0, true);
    setCoinLock(email, "testnet", WALLET_ID, TXID_B, 2, true);
    setCoinLock(email, "testnet", WALLET_ID, TXID_B, 3, false);
    expect(getLockedOutpoints(email, "testnet", WALLET_ID)).toEqual(
      new Set([`${TXID}:0`, `${TXID_B}:2`]),
    );
  });

  it("scopes coins to their wallet", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 0, true);
    expect(isCoinLocked(email, "testnet", "other-wallet", TXID, 0)).toBe(false);
    expect(getLockedOutpoints(email, "testnet", "other-wallet").size).toBe(0);
  });

  it("lists coin meta for a wallet", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 0, true);
    setCoinLock(email, "testnet", WALLET_ID, TXID_B, 1, false);
    const metas = listCoinMeta(email, "testnet", WALLET_ID).sort((a, b) =>
      a.txid.localeCompare(b.txid),
    );
    expect(metas).toEqual([
      { txid: TXID, vout: 0, locked: true },
      { txid: TXID_B, vout: 1, locked: false },
    ]);
  });

  it("returns empty results when the database does not exist", () => {
    const email = uniqueEmail(); // never bootstrapped
    expect(getCoinMeta(email, "testnet", WALLET_ID, TXID, 0)).toBeNull();
    expect(listCoinMeta(email, "testnet", WALLET_ID)).toEqual([]);
    expect(getLockedOutpoints(email, "testnet", WALLET_ID).size).toBe(0);
  });

  it("stores the coin-control document encrypted at rest", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 0, true);
    _closeDatabase();

    const dbFile = path.join(TEST_HOME, "data", emailHash(email), "testnet", "storage.sqlite");
    const db = new Database(dbFile, { readonly: true });
    const row = db
      .prepare("SELECT encrypted FROM coin_control WHERE wallet_id = ?")
      .get(WALLET_ID) as { encrypted: Uint8Array };
    db.close();

    // The raw blob reveals neither the outpoint nor the document structure.
    const raw = Buffer.from(row.encrypted).toString("latin1");
    expect(raw).not.toContain(TXID);
    expect(raw).not.toContain("locked");

    // And the store still reads it back fine.
    expect(isCoinLocked(email, "testnet", WALLET_ID, TXID, 0)).toBe(true);
  });
});
