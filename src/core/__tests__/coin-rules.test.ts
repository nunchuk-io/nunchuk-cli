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
import { addCoinTag, createTag, removeCoinTag } from "../tag-store.js";
import {
  applyCollectionToExisting,
  createCollection,
  getOutpointsByCollection,
} from "../collection-store.js";
import { applyFirstSeenRules, reconcileNewCoins } from "../coin-rules.js";

const TEST_RUN_ID = crypto.randomBytes(4).toString("hex");
const TEST_HOME = path.join(os.tmpdir(), "nunchuk-cli-coin-rules", TEST_RUN_ID);
process.env.NUNCHUK_CLI_HOME = TEST_HOME;

const createdEmails: string[] = [];
let counter = 0;
function uniqueEmail(): string {
  const email = `coin-rules-${TEST_RUN_ID}-${++counter}@test.local`;
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

describe("first-seen rules (reconcileNewCoins)", () => {
  it("a new untagged coin joins add-untagged collections and is auto-locked", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createCollection(email, NET, WALLET_ID, "quarantine", {
      addUntagged: true,
      autoLock: true,
      addTagNames: [],
    });
    reconcileNewCoins(email, NET, WALLET_ID, [
      { txid: TXID, vout: 0 },
      { txid: TXID, vout: 1 },
    ]);
    const { outpoints } = getOutpointsByCollection(email, NET, WALLET_ID, "quarantine");
    expect(outpoints).toEqual(new Set([`${TXID}:0`, `${TXID}:1`]));
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(true);
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 1)).toBe(true);
  });

  it("a second scan is a no-op: no re-join, no re-lock", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createCollection(email, NET, WALLET_ID, "quarantine", {
      addUntagged: true,
      autoLock: true,
      addTagNames: [],
    });
    const scanned = [{ txid: TXID, vout: 0 }];
    reconcileNewCoins(email, NET, WALLET_ID, scanned);
    setCoinLock(email, NET, WALLET_ID, TXID, 0, false);

    reconcileNewCoins(email, NET, WALLET_ID, scanned);
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(false);
    const entry = loadCoinControl(email, NET, WALLET_ID).coins[`${TXID}:0`];
    expect(entry.collections).toHaveLength(1);
  });

  it("rules are apply-on-arrival: coins seen before the rule existed do not join on rescan", () => {
    const email = uniqueEmail();
    bootstrap(email);
    reconcileNewCoins(email, NET, WALLET_ID, [{ txid: TXID, vout: 0 }]); // seen, no collections yet
    createCollection(email, NET, WALLET_ID, "late", {
      addUntagged: true,
      autoLock: false,
      addTagNames: [],
    });
    reconcileNewCoins(email, NET, WALLET_ID, [{ txid: TXID, vout: 0 }]);
    expect(getOutpointsByCollection(email, NET, WALLET_ID, "late").outpoints.size).toBe(0);

    // --apply-to-existing is the explicit way to pick them up.
    const { joined } = applyCollectionToExisting(email, NET, WALLET_ID, "late");
    expect(joined).toBe(1);
    expect(getOutpointsByCollection(email, NET, WALLET_ID, "late").outpoints).toEqual(
      new Set([`${TXID}:0`]),
    );
  });

  it("a tag-carrying entry never joins add-untagged collections (pure rule)", () => {
    const doc = {
      version: 1 as const,
      coins: {},
      tags: [{ id: 1, name: "kyc" }],
      collections: [
        { id: 1, name: "untagged only", addUntagged: true, autoLock: true, addTags: [] },
      ],
      changeTagIntents: [],
      nextTagId: 2,
      nextCollectionId: 2,
    };
    const entry = { locked: false, tags: [1], collections: [] };
    applyFirstSeenRules(doc, entry);
    expect(entry.collections).toEqual([]);
    expect(entry.locked).toBe(false);
  });
});

describe("tag-added hook (coin tag add)", () => {
  it("tagging a coin inserts it into rule-matching collections and auto-locks", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "kyc");
    createCollection(email, NET, WALLET_ID, "verified", {
      addUntagged: false,
      autoLock: true,
      addTagNames: ["kyc"],
    });
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "kyc");
    expect(getOutpointsByCollection(email, NET, WALLET_ID, "verified").outpoints).toEqual(
      new Set([`${TXID}:0`]),
    );
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(true);
  });

  it("re-tagging is idempotent and never re-locks; tag removal keeps membership", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "kyc");
    createCollection(email, NET, WALLET_ID, "verified", {
      addUntagged: false,
      autoLock: true,
      addTagNames: ["kyc"],
    });
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "kyc");
    setCoinLock(email, NET, WALLET_ID, TXID, 0, false);

    addCoinTag(email, NET, WALLET_ID, TXID, 0, "kyc"); // tag already present
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(false);

    removeCoinTag(email, NET, WALLET_ID, TXID, 0, "kyc");
    expect(getOutpointsByCollection(email, NET, WALLET_ID, "verified").outpoints).toEqual(
      new Set([`${TXID}:0`]),
    );
  });
});

describe("--apply-to-existing (applyCollectionToExisting)", () => {
  it("joins untagged and tag-matching coins, counts new joins only", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "kyc");
    reconcileNewCoins(email, NET, WALLET_ID, [
      { txid: TXID, vout: 0 }, // will carry kyc
      { txid: TXID, vout: 1 }, // stays untagged
    ]);
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "kyc");

    createCollection(email, NET, WALLET_ID, "both", {
      addUntagged: true,
      autoLock: true,
      addTagNames: ["kyc"],
    });
    const first = applyCollectionToExisting(email, NET, WALLET_ID, "both");
    expect(first.joined).toBe(2);
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(true);
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 1)).toBe(true);

    // Second run: everyone is already a member.
    setCoinLock(email, NET, WALLET_ID, TXID, 0, false);
    const second = applyCollectionToExisting(email, NET, WALLET_ID, "both");
    expect(second.joined).toBe(0);
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(false);
  });
});
