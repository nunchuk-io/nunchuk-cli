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
import { isCoinLocked, loadCoinControl, mutateCoinControl, setCoinLock } from "../coin-store.js";
import { addCoinTag, createTag, getCoinTagNames, removeCoinTag } from "../tag-store.js";
import {
  applyCollectionToExisting,
  createCollection,
  getOutpointsByCollection,
} from "../collection-store.js";
import { applyFirstSeenRules, reconcileNewCoins } from "../coin-rules.js";
import { storeChangeTagIntent } from "../change-intents.js";

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

function coin(
  vout: number,
  address = `tb1qcoin${vout}`,
  amountSats = 10_000n,
): { txid: string; vout: number; address: string; amountSats: bigint } {
  return { txid: TXID, vout, address, amountSats };
}

describe("first-seen rules (reconcileNewCoins)", () => {
  it("a new untagged coin joins add-untagged collections and is auto-locked", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createCollection(email, NET, WALLET_ID, "quarantine", {
      addUntagged: true,
      autoLock: true,
      addTagNames: [],
    });
    reconcileNewCoins(email, NET, WALLET_ID, [coin(0), coin(1)]);
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
    const scanned = [coin(0)];
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
    reconcileNewCoins(email, NET, WALLET_ID, [coin(0)]); // seen, no collections yet
    createCollection(email, NET, WALLET_ID, "late", {
      addUntagged: true,
      autoLock: false,
      addTagNames: [],
    });
    reconcileNewCoins(email, NET, WALLET_ID, [coin(0)]);
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
    reconcileNewCoins(email, NET, WALLET_ID, [coin(0), coin(1)]);
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

describe("change-tag intent reconciliation (scan time)", () => {
  const CHANGE_ADDR = "tb1qchange";

  function intentFor(email: string, tagName: string, amountSats: bigint): void {
    const doc = loadCoinControl(email, NET, WALLET_ID);
    const tag = doc.tags.find((t) => t.name === tagName)!;
    storeChangeTagIntent(email, NET, WALLET_ID, {
      address: CHANGE_ADDR,
      amountSats,
      tagIds: [tag.id],
    });
  }

  it("a matching new coin inherits the tags, fires tag rules, and skips untagged rules", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "kyc");
    createCollection(email, NET, WALLET_ID, "quarantine", {
      addUntagged: true,
      autoLock: true,
      addTagNames: [],
    });
    createCollection(email, NET, WALLET_ID, "verified", {
      addUntagged: false,
      autoLock: true,
      addTagNames: ["kyc"],
    });
    intentFor(email, "kyc", 5_000n);

    // The change coin appears in a scan — txid is irrelevant, address matches.
    reconcileNewCoins(email, NET, WALLET_ID, [coin(0, CHANGE_ADDR, 5_000n)]);

    expect(getCoinTagNames(email, NET, WALLET_ID).get(`${TXID}:0`)).toEqual(["kyc"]);
    // Tagged change joins the tag-rule collection (auto-locked) but NOT the
    // untagged-coins collection — intents apply before first-seen rules.
    expect(getOutpointsByCollection(email, NET, WALLET_ID, "verified").outpoints).toEqual(
      new Set([`${TXID}:0`]),
    );
    expect(getOutpointsByCollection(email, NET, WALLET_ID, "quarantine").outpoints.size).toBe(0);
    expect(isCoinLocked(email, NET, WALLET_ID, TXID, 0)).toBe(true);
    // The intent is consumed.
    expect(loadCoinControl(email, NET, WALLET_ID).changeTagIntents).toEqual([]);
  });

  it("a consumed intent does not apply to later coins on the same address", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "kyc");
    intentFor(email, "kyc", 5_000n);

    reconcileNewCoins(email, NET, WALLET_ID, [coin(0, CHANGE_ADDR, 5_000n)]);
    reconcileNewCoins(email, NET, WALLET_ID, [coin(1, CHANGE_ADDR, 5_000n)]);

    const tags = getCoinTagNames(email, NET, WALLET_ID);
    expect(tags.get(`${TXID}:0`)).toEqual(["kyc"]);
    expect(tags.has(`${TXID}:1`)).toBe(false);
  });

  it("prefers the exact-amount intent when drafts share a change address", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "a");
    createTag(email, NET, WALLET_ID, "b");
    intentFor(email, "a", 1_000n);
    intentFor(email, "b", 2_000n);

    reconcileNewCoins(email, NET, WALLET_ID, [coin(0, CHANGE_ADDR, 2_000n)]);

    expect(getCoinTagNames(email, NET, WALLET_ID).get(`${TXID}:0`)).toEqual(["b"]);
    // The non-matching intent survives for its own coin.
    const remaining = loadCoinControl(email, NET, WALLET_ID).changeTagIntents;
    expect(remaining).toHaveLength(1);
    expect(remaining[0].amount).toBe("1000");
  });

  it("falls back to the newest intent when no amount matches", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "old");
    createTag(email, NET, WALLET_ID, "new");
    mutateCoinControl(email, NET, WALLET_ID, (doc) => {
      const idOf = (name: string): number => doc.tags.find((t) => t.name === name)!.id;
      doc.changeTagIntents.push(
        {
          address: CHANGE_ADDR,
          amount: "1000",
          tagIds: [idOf("old")],
          createdAt: "2026-07-01T00:00:00.000Z",
        },
        {
          address: CHANGE_ADDR,
          amount: "2000",
          tagIds: [idOf("new")],
          createdAt: "2026-07-02T00:00:00.000Z",
        },
      );
    });

    // The coin's value (fee-adjusted replacement) matches neither intent.
    reconcileNewCoins(email, NET, WALLET_ID, [coin(0, CHANGE_ADDR, 3_000n)]);
    expect(getCoinTagNames(email, NET, WALLET_ID).get(`${TXID}:0`)).toEqual(["new"]);
  });

  it("drops stale intents during a scan and keeps fresh ones", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "kyc");
    const staleDate = new Date(Date.now() - 91 * 24 * 60 * 60 * 1000).toISOString();
    mutateCoinControl(email, NET, WALLET_ID, (doc) => {
      doc.changeTagIntents.push({
        address: "tb1qstale",
        amount: "1000",
        tagIds: [doc.tags[0].id],
        createdAt: staleDate,
      });
    });
    intentFor(email, "kyc", 5_000n); // fresh

    // Even a scan of already-seen coins prunes stale intents.
    reconcileNewCoins(email, NET, WALLET_ID, [coin(9, "tb1qunrelated")]);
    reconcileNewCoins(email, NET, WALLET_ID, [coin(9, "tb1qunrelated")]);

    const intents = loadCoinControl(email, NET, WALLET_ID).changeTagIntents;
    expect(intents).toHaveLength(1);
    expect(intents[0].address).toBe(CHANGE_ADDR);
  });
});
