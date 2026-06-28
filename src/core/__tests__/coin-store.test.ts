import { afterAll, beforeEach, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  _clearMasterKeyCache,
  _closeDatabase,
  _deleteAccountData,
  saveProfile,
} from "../storage.js";
import type { Profile } from "../storage.js";
import {
  getCoinMeta,
  getLockedOutpoints,
  isCoinLocked,
  listCoinMeta,
  setCoinLock,
  setCoinMemo,
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
const WALLET_ID = "test-wallet";

describe("coin-store CRUD", () => {
  it("returns null for an unknown coin", () => {
    const email = uniqueEmail();
    bootstrap(email);
    expect(getCoinMeta(email, "testnet", WALLET_ID, TXID, 0)).toBeNull();
    expect(isCoinLocked(email, "testnet", WALLET_ID, TXID, 0)).toBe(false);
  });

  it("setCoinMemo stores and retrieves a memo", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinMemo(email, "testnet", WALLET_ID, TXID, 0, "rent money");
    const meta = getCoinMeta(email, "testnet", WALLET_ID, TXID, 0);
    expect(meta).toEqual({ txid: TXID, vout: 0, memo: "rent money", locked: false });
  });

  it("setCoinLock toggles the lock flag", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 1, true);
    expect(isCoinLocked(email, "testnet", WALLET_ID, TXID, 1)).toBe(true);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 1, false);
    expect(isCoinLocked(email, "testnet", WALLET_ID, TXID, 1)).toBe(false);
  });

  it("memo and lock coexist on the same coin", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinMemo(email, "testnet", WALLET_ID, TXID, 2, "cold storage");
    setCoinLock(email, "testnet", WALLET_ID, TXID, 2, true);
    expect(getCoinMeta(email, "testnet", WALLET_ID, TXID, 2)).toEqual({
      txid: TXID,
      vout: 2,
      memo: "cold storage",
      locked: true,
    });
  });

  it("clearing both fields removes the row", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinMemo(email, "testnet", WALLET_ID, TXID, 3, "tmp");
    setCoinLock(email, "testnet", WALLET_ID, TXID, 3, true);

    setCoinLock(email, "testnet", WALLET_ID, TXID, 3, false);
    setCoinMemo(email, "testnet", WALLET_ID, TXID, 3, null);
    expect(getCoinMeta(email, "testnet", WALLET_ID, TXID, 3)).toBeNull();
  });

  it("listCoinMeta returns all rows for the wallet", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinMemo(email, "testnet", WALLET_ID, TXID, 0, "a");
    setCoinLock(email, "testnet", WALLET_ID, TXID, 1, true);
    setCoinMemo(email, "testnet", WALLET_ID, TXID, 2, "c");

    const metas = listCoinMeta(email, "testnet", WALLET_ID);
    expect(metas).toHaveLength(3);
    expect(metas.find((m) => m.vout === 1)?.locked).toBe(true);
  });

  it("getLockedOutpoints returns just the locked outpoints as txid:vout keys", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 0, true);
    setCoinLock(email, "testnet", WALLET_ID, TXID, 5, true);
    setCoinMemo(email, "testnet", WALLET_ID, TXID, 7, "not locked");

    const locked = getLockedOutpoints(email, "testnet", WALLET_ID);
    expect(locked.has(`${TXID}:0`)).toBe(true);
    expect(locked.has(`${TXID}:5`)).toBe(true);
    expect(locked.has(`${TXID}:7`)).toBe(false);
    expect(locked.size).toBe(2);
  });

  it("scopes locks per wallet_id", () => {
    const email = uniqueEmail();
    bootstrap(email);
    setCoinLock(email, "testnet", "wallet-a", TXID, 0, true);
    expect(isCoinLocked(email, "testnet", "wallet-a", TXID, 0)).toBe(true);
    expect(isCoinLocked(email, "testnet", "wallet-b", TXID, 0)).toBe(false);
  });
});
