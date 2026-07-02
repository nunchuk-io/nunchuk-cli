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
import { loadCoinControl, mutateCoinControl } from "../coin-store.js";
import {
  addCoinTag,
  createTag,
  deleteTag,
  getCoinTagNames,
  getOutpointsByTag,
  listTags,
  removeCoinTag,
  renameTag,
  validateTagName,
} from "../tag-store.js";

const TEST_RUN_ID = crypto.randomBytes(4).toString("hex");
const TEST_HOME = path.join(os.tmpdir(), "nunchuk-cli-tag-store", TEST_RUN_ID);
process.env.NUNCHUK_CLI_HOME = TEST_HOME;

const createdEmails: string[] = [];
let counter = 0;
function uniqueEmail(): string {
  const email = `tag-store-${TEST_RUN_ID}-${++counter}@test.local`;
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

describe("validateTagName", () => {
  it("strips a single leading #", () => {
    expect(validateTagName("#kyc")).toBe("kyc");
    expect(validateTagName("kyc")).toBe("kyc");
  });

  it("rejects empty and whitespace names", () => {
    expect(() => validateTagName("")).toThrow(/must not be empty/);
    expect(() => validateTagName("#")).toThrow(/must not be empty/);
    expect(() => validateTagName("two words")).toThrow(/whitespace/);
    expect(() => validateTagName("tab\tname")).toThrow(/whitespace/);
  });

  it("rejects names above the length cap", () => {
    expect(() => validateTagName("a".repeat(65))).toThrow(/at most 64/);
  });

  it("rejects names starting with a hyphen", () => {
    expect(() => validateTagName("-foo")).toThrow(/hyphen/);
    expect(() => validateTagName("#-foo")).toThrow(/hyphen/);
  });
});

describe("tag CRUD", () => {
  it("creates tags with distinct, never-reused ids", () => {
    const email = uniqueEmail();
    bootstrap(email);
    const a = createTag(email, NET, WALLET_ID, "alpha");
    const b = createTag(email, NET, WALLET_ID, "beta");
    expect(a.id).not.toBe(b.id);

    deleteTag(email, NET, WALLET_ID, "beta");
    const c = createTag(email, NET, WALLET_ID, "gamma");
    expect(c.id).not.toBe(b.id); // deleted id is not reused
  });

  it("is case-sensitive: TAG and tag coexist; exact duplicates are rejected", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "tag");
    createTag(email, NET, WALLET_ID, "TAG");
    expect(
      listTags(email, NET, WALLET_ID)
        .map((t) => t.name)
        .sort(),
    ).toEqual(["TAG", "tag"]);
    expect(() => createTag(email, NET, WALLET_ID, "tag")).toThrow(/already exists/);
    expect(() => createTag(email, NET, WALLET_ID, "#tag")).toThrow(/already exists/);
  });

  it("lookup misses suggest case-insensitive near-matches", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "kyc");
    expect(() => addCoinTag(email, NET, WALLET_ID, TXID, 0, "KYC")).toThrow(
      /No tag "KYC"\. Did you mean "kyc"\?/,
    );
  });

  it("renames a tag; assigned coins keep it", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "old");
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "old");
    renameTag(email, NET, WALLET_ID, "old", "new");
    expect(getCoinTagNames(email, NET, WALLET_ID).get(`${TXID}:0`)).toEqual(["new"]);
    expect(() => renameTag(email, NET, WALLET_ID, "new", "new2")).not.toThrow();
  });

  it("rejects renaming to an existing name", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "a");
    createTag(email, NET, WALLET_ID, "b");
    expect(() => renameTag(email, NET, WALLET_ID, "a", "b")).toThrow(/already exists/);
  });

  it("delete removes the tag from coins, collection rules, and intents", () => {
    const email = uniqueEmail();
    bootstrap(email);
    const tag = createTag(email, NET, WALLET_ID, "doomed");
    const keep = createTag(email, NET, WALLET_ID, "keep");
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "doomed");
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "keep");
    mutateCoinControl(email, NET, WALLET_ID, (doc) => {
      doc.collections.push({
        id: doc.nextCollectionId++,
        name: "col",
        addUntagged: false,
        autoLock: false,
        addTags: [tag.id, keep.id],
      });
      doc.changeTagIntents.push({
        address: "tb1qexample",
        amount: "1000",
        tagIds: [tag.id, keep.id],
        createdAt: "2026-07-02T00:00:00Z",
      });
    });

    deleteTag(email, NET, WALLET_ID, "doomed");

    const doc = loadCoinControl(email, NET, WALLET_ID);
    expect(doc.tags.map((t) => t.name)).toEqual(["keep"]);
    expect(doc.coins[`${TXID}:0`].tags).toEqual([keep.id]);
    expect(doc.collections[0].addTags).toEqual([keep.id]);
    expect(doc.changeTagIntents[0].tagIds).toEqual([keep.id]);
  });
});

describe("coin tag assignment", () => {
  it("adds and removes a tag on a coin (idempotent add)", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "kyc");
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "kyc");
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "#kyc"); // idempotent, # stripped
    expect(getCoinTagNames(email, NET, WALLET_ID).get(`${TXID}:0`)).toEqual(["kyc"]);

    removeCoinTag(email, NET, WALLET_ID, TXID, 0, "kyc");
    expect(getCoinTagNames(email, NET, WALLET_ID).size).toBe(0);
    // The coin entry survives (seen marker), just untagged.
    expect(loadCoinControl(email, NET, WALLET_ID).coins[`${TXID}:0`].tags).toEqual([]);
  });

  it("getOutpointsByTag returns the coins carrying the tag", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "kyc");
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "kyc");
    addCoinTag(email, NET, WALLET_ID, TXID, 2, "kyc");
    const { name, outpoints } = getOutpointsByTag(email, NET, WALLET_ID, "#kyc");
    expect(name).toBe("kyc");
    expect(outpoints).toEqual(new Set([`${TXID}:0`, `${TXID}:2`]));
    expect(() => getOutpointsByTag(email, NET, WALLET_ID, "nope")).toThrow(/No tag "nope"/);
  });

  it("listTags reports per-tag coin counts", () => {
    const email = uniqueEmail();
    bootstrap(email);
    createTag(email, NET, WALLET_ID, "a");
    createTag(email, NET, WALLET_ID, "b");
    addCoinTag(email, NET, WALLET_ID, TXID, 0, "a");
    addCoinTag(email, NET, WALLET_ID, TXID, 1, "a");
    const tags = listTags(email, NET, WALLET_ID);
    expect(tags.find((t) => t.name === "a")?.coinCount).toBe(2);
    expect(tags.find((t) => t.name === "b")?.coinCount).toBe(0);
  });
});
