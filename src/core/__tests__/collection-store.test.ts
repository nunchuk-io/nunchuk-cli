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
import { isCoinLocked, loadCoinControl, setCoinLock } from "../coin-store.js";
import { createTag } from "../tag-store.js";
import {
  addCoinToCollection,
  createCollection,
  deleteCollection,
  getCoinCollectionNames,
  getOutpointsByCollection,
  listCollections,
  removeCoinFromCollection,
  updateCollection,
  validateCollectionName,
} from "../collection-store.js";

const TEST_RUN_ID = crypto.randomBytes(4).toString("hex");
const TEST_HOME = path.join(os.tmpdir(), "nunchuk-cli-collection-store", TEST_RUN_ID);
process.env.NUNCHUK_CLI_HOME = TEST_HOME;

const createdEmails: string[] = [];
let counter = 0;
function uniqueEmail(): string {
  const email = `collection-store-${TEST_RUN_ID}-${++counter}@test.local`;
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
const NET = "testnet" as const;
const NO_RULES = { addUntagged: false, autoLock: false, addTagNames: [] };

describe("validateCollectionName", () => {
  it("allows interior whitespace (unlike tags)", () => {
    expect(validateCollectionName("auto lock")).toBe("auto lock");
  });

  it("rejects empty, padded, hyphen-leading, and overlong names", () => {
    expect(() => validateCollectionName("")).toThrow(/must not be empty/);
    expect(() => validateCollectionName(" padded ")).toThrow(/start or end with whitespace/);
    expect(() => validateCollectionName("-foo")).toThrow(/hyphen/);
    expect(() => validateCollectionName("a".repeat(65))).toThrow(/at most 64/);
  });
});

describe("collection CRUD", () => {
  it("creates collections with distinct, never-reused ids", () => {
    const email = uniqueEmail();
    bootstrap(email);
    const a = createCollection(email, NET, WALLET_ID, "alpha", NO_RULES);
    const b = createCollection(email, NET, WALLET_ID, "beta", NO_RULES);
    expect(a.id).not.toBe(b.id);

    deleteCollection(email, NET, WALLET_ID, "beta");
    const c = createCollection(email, NET, WALLET_ID, "gamma", NO_RULES);
    expect(c.id).not.toBe(b.id);
  });

  it("is case-sensitive and suggests near-matches on a miss", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createCollection(email, NET, WALLET_ID, "Savings", NO_RULES);
    expect(() => createCollection(email, NET, WALLET_ID, "Savings", NO_RULES)).toThrow(
      /already exists/,
    );
    expect(() => deleteCollection(email, NET, WALLET_ID, "savings")).toThrow(
      /No collection "savings"\. Did you mean "Savings"\?/,
    );
  });

  it("stores rule flags and resolves add-tag names to ids", () => {
    const email = uniqueEmail();
    bootstrap(email);
    const tag = createTag(email, NET, WALLET_ID, "kyc");
    createCollection(email, NET, WALLET_ID, "col", {
      addUntagged: true,
      autoLock: true,
      addTagNames: ["kyc", "#kyc"], // duplicate resolves once
    });
    const doc = loadCoinControl(email, NET, WALLET_ID);
    expect(doc.collections[0]).toMatchObject({
      addUntagged: true,
      autoLock: true,
      addTags: [tag.id],
    });
    expect(() =>
      createCollection(email, NET, WALLET_ID, "col2", { ...NO_RULES, addTagNames: ["nope"] }),
    ).toThrow(/No tag "nope"/);
  });

  it("update renames, toggles flags, appends and clears rule tags", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "a");
    createTag(email, NET, WALLET_ID, "b");
    createCollection(email, NET, WALLET_ID, "old", NO_RULES);

    updateCollection(email, NET, WALLET_ID, "old", {
      name: "new",
      addUntagged: true,
      autoLock: true,
      addTagNames: ["a"],
    });
    updateCollection(email, NET, WALLET_ID, "new", { addTagNames: ["a", "b"] }); // idempotent append
    let summary = listCollections(email, NET, WALLET_ID)[0];
    expect(summary).toMatchObject({
      name: "new",
      addUntagged: true,
      autoLock: true,
      addTagNames: ["a", "b"],
    });

    updateCollection(email, NET, WALLET_ID, "new", { autoLock: false, clearAddTags: true });
    summary = listCollections(email, NET, WALLET_ID)[0];
    expect(summary).toMatchObject({ addUntagged: true, autoLock: false, addTagNames: [] });
  });

  it("rejects renaming to an existing name", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createCollection(email, NET, WALLET_ID, "a", NO_RULES);
    createCollection(email, NET, WALLET_ID, "b", NO_RULES);
    expect(() => updateCollection(email, NET, WALLET_ID, "a", { name: "b" })).toThrow(
      /already exists/,
    );
  });
});

describe("collection membership", () => {
  it("adds and removes a coin (idempotent add); listCollections counts members", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createCollection(email, NET, WALLET_ID, "col", NO_RULES);
    addCoinToCollection(email, NET, WALLET_ID, TXID, 0, "col");
    addCoinToCollection(email, NET, WALLET_ID, TXID, 0, "col");
    addCoinToCollection(email, NET, WALLET_ID, TXID, 1, "col");
    expect(listCollections(email, NET, WALLET_ID)[0].coinCount).toBe(2);
    expect(getCoinCollectionNames(email, NET, WALLET_ID).get(`${TXID}:0`)).toEqual(["col"]);

    removeCoinFromCollection(email, NET, WALLET_ID, TXID, 0, "col");
    const { outpoints } = getOutpointsByCollection(email, NET, WALLET_ID, "col");
    expect(outpoints).toEqual(new Set([`${TXID}:1`]));
    // The coin entry survives removal (seen marker).
    expect(loadCoinControl(email, NET, WALLET_ID).coins[`${TXID}:0`].collections).toEqual([]);
  });

  it("auto-lock fires once on insert; re-add does not re-lock", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createCollection(email, NET, WALLET_ID, "vault", {
      addUntagged: false,
      autoLock: true,
      addTagNames: [],
    });
    addCoinToCollection(email, NET, WALLET_ID, TXID, 0, "vault");
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(true);

    setCoinLock(email, NET, WALLET_ID, TXID, 0, false);
    addCoinToCollection(email, NET, WALLET_ID, TXID, 0, "vault"); // already a member
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(false);
  });

  it("removal and collection delete keep the lock", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createCollection(email, NET, WALLET_ID, "vault", {
      addUntagged: false,
      autoLock: true,
      addTagNames: [],
    });
    addCoinToCollection(email, NET, WALLET_ID, TXID, 0, "vault");
    removeCoinFromCollection(email, NET, WALLET_ID, TXID, 0, "vault");
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(true);

    addCoinToCollection(email, NET, WALLET_ID, TXID, 1, "vault");
    deleteCollection(email, NET, WALLET_ID, "vault");
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 1)).toBe(true);
    const doc = loadCoinControl(email, NET, WALLET_ID);
    expect(doc.collections).toEqual([]);
    expect(doc.coins[`${TXID}:1`].collections).toEqual([]);
  });
});
