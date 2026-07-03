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
import { loadCoinControl } from "../coin-store.js";
import { addCoinTag, createTag } from "../tag-store.js";
import {
  getPendingIntentAddresses,
  planChangeTags,
  storeChangeTagIntent,
} from "../change-intents.js";

const TEST_RUN_ID = crypto.randomBytes(4).toString("hex");
const TEST_HOME = path.join(os.tmpdir(), "nunchuk-cli-change-intents", TEST_RUN_ID);
process.env.NUNCHUK_CLI_HOME = TEST_HOME;

const createdEmails: string[] = [];
let counter = 0;
function uniqueEmail(): string {
  const email = `change-intents-${TEST_RUN_ID}-${++counter}@test.local`;
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
const INPUTS = [
  { txid: TXID, vout: 0 },
  { txid: TXID, vout: 1 },
];

// Coins: vout 0 carries {kyc, cold}; vout 1 carries {cold, exchange}.
function seedTaggedInputs(email: string): void {
  bootstrap(email);
  createTag(email, NET, WALLET_ID, "kyc");
  createTag(email, NET, WALLET_ID, "cold");
  createTag(email, NET, WALLET_ID, "exchange");
  addCoinTag(email, NET, WALLET_ID, TXID, 0, "kyc");
  addCoinTag(email, NET, WALLET_ID, TXID, 0, "cold");
  addCoinTag(email, NET, WALLET_ID, TXID, 1, "cold");
  addCoinTag(email, NET, WALLET_ID, TXID, 1, "exchange");
}

describe("planChangeTags", () => {
  it("defaults to the union of the input coins' tags", () => {
    const email = uniqueEmail();
    seedTaggedInputs(email);
    const plan = planChangeTags(email, NET, WALLET_ID, INPUTS);
    expect(plan.tagNames.sort()).toEqual(["cold", "exchange", "kyc"]);
  });

  it('"none" yields an empty plan', () => {
    const email = uniqueEmail();
    seedTaggedInputs(email);
    const plan = planChangeTags(email, NET, WALLET_ID, INPUTS, "none");
    expect(plan).toEqual({ tagIds: [], tagNames: [] });
  });

  it("accepts a subset (with # prefixes and duplicates) of the input tags", () => {
    const email = uniqueEmail();
    seedTaggedInputs(email);
    const plan = planChangeTags(email, NET, WALLET_ID, INPUTS, "#kyc, cold,kyc");
    expect(plan.tagNames).toEqual(["kyc", "cold"]);
  });

  it("rejects unknown tags and tags not on the inputs", () => {
    const email = uniqueEmail();
    seedTaggedInputs(email);
    expect(() => planChangeTags(email, NET, WALLET_ID, INPUTS, "nope")).toThrow(/No tag "nope"/);
    // "exchange" exists but only on vout 1; select just vout 0 as input.
    expect(() =>
      planChangeTags(email, NET, WALLET_ID, [{ txid: TXID, vout: 0 }], "exchange"),
    ).toThrow(/Tag "#exchange" is not on any selected input coin\./);
  });

  it("untagged inputs default to an empty plan", () => {
    const email = uniqueEmail();
    bootstrap(email);
    const plan = planChangeTags(email, NET, WALLET_ID, INPUTS);
    expect(plan).toEqual({ tagIds: [], tagNames: [] });
  });
});

describe("storeChangeTagIntent", () => {
  it("stores the intent keyed by address with a decimal-string amount", () => {
    const email = uniqueEmail();
    seedTaggedInputs(email);
    storeChangeTagIntent(email, NET, WALLET_ID, {
      address: "tb1qchange",
      amountSats: 12_345n,
      tagIds: [1, 2],
    });
    const intents = loadCoinControl(email, NET, WALLET_ID).changeTagIntents;
    expect(intents).toHaveLength(1);
    expect(intents[0]).toMatchObject({ address: "tb1qchange", amount: "12345", tagIds: [1, 2] });
    expect(new Date(intents[0].createdAt).getTime()).not.toBeNaN();
  });

  it("replaces an identical (address, amount) intent but keeps distinct amounts", () => {
    const email = uniqueEmail();
    seedTaggedInputs(email);
    storeChangeTagIntent(email, NET, WALLET_ID, {
      address: "tb1qchange",
      amountSats: 1_000n,
      tagIds: [1],
    });
    storeChangeTagIntent(email, NET, WALLET_ID, {
      address: "tb1qchange",
      amountSats: 1_000n,
      tagIds: [2], // re-created transaction with a different tag choice
    });
    storeChangeTagIntent(email, NET, WALLET_ID, {
      address: "tb1qchange",
      amountSats: 2_000n, // concurrent draft on the same address
      tagIds: [1],
    });
    const intents = loadCoinControl(email, NET, WALLET_ID).changeTagIntents;
    expect(intents).toHaveLength(2);
    expect(intents.find((i) => i.amount === "1000")?.tagIds).toEqual([2]);
    expect(intents.find((i) => i.amount === "2000")?.tagIds).toEqual([1]);
  });

  it("getPendingIntentAddresses lists the addresses awaiting reconciliation", () => {
    const email = uniqueEmail();
    seedTaggedInputs(email);
    expect(getPendingIntentAddresses(email, NET, WALLET_ID)).toEqual(new Set());
    storeChangeTagIntent(email, NET, WALLET_ID, {
      address: "tb1qchange",
      amountSats: 1_000n,
      tagIds: [1],
    });
    expect(getPendingIntentAddresses(email, NET, WALLET_ID)).toEqual(new Set(["tb1qchange"]));
  });
});
