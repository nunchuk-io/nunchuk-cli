import { describe, it, expect } from "vitest";
import { HDKey } from "@scure/bip32";
import {
  validatePolicies,
  buildGlobalPolicyFromFlags,
  buildSignerPolicyFromFlags,
  mergePolicies,
  parseSigningDelayInput,
  parsePolicyJson,
  formatPoliciesText,
  validateWalletPolicies,
  createDummyPsbt,
  extractPartialSignature,
  type PlatformKeyPolicies,
} from "../platform-key.js";
import { TESTNET_VERSIONS } from "../address.js";
import { buildWalletDescriptor } from "../descriptor.js";
import { buildMiniscriptDescriptor, MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT } from "../miniscript.js";
import { signWalletPsbtWithKey } from "../psbt-sign.js";
import { encryptWalletPayload, decryptWalletPayload } from "../wallet-keys.js";
import type { WalletData } from "../storage.js";

describe("validatePolicies", () => {
  it("accepts valid global policy", () => {
    expect(() =>
      validatePolicies({
        global: {
          autoBroadcastTransaction: true,
          signingDelaySeconds: 3600,
          spendingLimit: { interval: "DAILY", amount: "1000", currency: "USD" },
        },
      }),
    ).not.toThrow();
  });

  it("accepts valid per-signer policy", () => {
    expect(() =>
      validatePolicies({
        signers: [
          {
            masterFingerprint: "534a4a82",
            autoBroadcastTransaction: false,
            signingDelaySeconds: 0,
          },
        ],
      }),
    ).not.toThrow();
  });

  it("accepts empty policies", () => {
    expect(() => validatePolicies({})).not.toThrow();
  });

  it("rejects global + signers coexisting", () => {
    expect(() =>
      validatePolicies({
        global: { autoBroadcastTransaction: true, signingDelaySeconds: 0 },
        signers: [
          {
            masterFingerprint: "534a4a82",
            autoBroadcastTransaction: false,
            signingDelaySeconds: 0,
          },
        ],
      }),
    ).toThrow("must not coexist");
  });

  it("rejects invalid master fingerprint", () => {
    expect(() =>
      validatePolicies({
        signers: [
          {
            masterFingerprint: "invalid",
            autoBroadcastTransaction: false,
            signingDelaySeconds: 0,
          },
        ],
      }),
    ).toThrow("Invalid master fingerprint");
  });

  it("rejects negative signing delay", () => {
    expect(() =>
      validatePolicies({
        global: { autoBroadcastTransaction: true, signingDelaySeconds: -1 },
      }),
    ).toThrow("signingDelaySeconds must be a non-negative number");
  });

  it("rejects invalid spending limit interval", () => {
    expect(() =>
      validatePolicies({
        global: {
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
          spendingLimit: {
            interval: "HOURLY" as "DAILY",
            amount: "100",
            currency: "USD",
          },
        },
      }),
    ).toThrow("Invalid spending limit interval");
  });

  it("rejects spending limit with missing amount", () => {
    expect(() =>
      validatePolicies({
        global: {
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
          spendingLimit: { interval: "DAILY", amount: "", currency: "USD" },
        },
      }),
    ).toThrow("amount is required");
  });

  it("allows null spendingLimit", () => {
    expect(() =>
      validatePolicies({
        global: {
          autoBroadcastTransaction: false,
          signingDelaySeconds: 0,
          spendingLimit: null,
        },
      }),
    ).not.toThrow();
  });

  it("rejects invalid currency", () => {
    expect(() =>
      validatePolicies({
        global: {
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
          spendingLimit: { interval: "DAILY", amount: "100", currency: "EUR" },
        },
      }),
    ).toThrow("Invalid currency");
  });

  it("accepts BTC and sat currencies", () => {
    expect(() =>
      validatePolicies({
        global: {
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
          spendingLimit: { interval: "DAILY", amount: "0.5", currency: "BTC" },
        },
      }),
    ).not.toThrow();
    expect(() =>
      validatePolicies({
        global: {
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
          spendingLimit: { interval: "DAILY", amount: "50000", currency: "sat" },
        },
      }),
    ).not.toThrow();
  });
});

describe("parseSigningDelayInput", () => {
  it.each([
    ["0", 0],
    ["30", 30],
    ["30s", 30],
    ["15m", 900],
    ["24h", 86400],
    ["7d", 604800],
    ["1H", 3600],
  ])("parses %s as %i seconds", (input, expected) => {
    expect(parseSigningDelayInput(input)).toBe(expected);
  });

  it.each(["1w", "1.5h", "-1", "abc", "1 hour"])("rejects invalid input %s", (input) => {
    expect(() => parseSigningDelayInput(input)).toThrow("Invalid signing delay");
  });
});

describe("buildGlobalPolicyFromFlags", () => {
  it("builds global policy with defaults", () => {
    const result = buildGlobalPolicyFromFlags({});
    expect(result).toEqual({
      global: {
        autoBroadcastTransaction: false,
        signingDelaySeconds: 0,
      },
    });
  });

  it("builds global policy with all flags", () => {
    const result = buildGlobalPolicyFromFlags({
      autoBroadcast: true,
      signingDelay: 3600,
      limitAmount: "1000",
      limitCurrency: "usd",
      limitInterval: "daily",
    });
    expect(result).toEqual({
      global: {
        autoBroadcastTransaction: true,
        signingDelaySeconds: 3600,
        spendingLimit: { interval: "DAILY", amount: "1000", currency: "USD" },
      },
    });
  });

  it("normalizes currency to canonical form", () => {
    const result = buildGlobalPolicyFromFlags({
      limitAmount: "50000",
      limitCurrency: "SAT",
      limitInterval: "weekly",
    });
    expect(result.global!.spendingLimit!.currency).toBe("sat");
  });

  it("rejects invalid currency in flags", () => {
    expect(() =>
      buildGlobalPolicyFromFlags({
        limitAmount: "100",
        limitCurrency: "EUR",
        limitInterval: "daily",
      }),
    ).toThrow("Invalid currency");
  });

  it("throws when spending limit is incomplete", () => {
    expect(() =>
      buildGlobalPolicyFromFlags({
        limitAmount: "1000",
      }),
    ).toThrow("All spending limit fields are required");
  });
});

describe("buildSignerPolicyFromFlags", () => {
  it("builds per-signer policy", () => {
    const result = buildSignerPolicyFromFlags("534A4A82", {
      autoBroadcast: true,
      signingDelay: 60,
    });
    expect(result).toEqual({
      signers: [
        {
          masterFingerprint: "534a4a82",
          autoBroadcastTransaction: true,
          signingDelaySeconds: 60,
        },
      ],
    });
  });

  it("lowercases fingerprint", () => {
    const result = buildSignerPolicyFromFlags("AABB1122", {});
    expect(result.signers![0].masterFingerprint).toBe("aabb1122");
  });
});

describe("mergePolicies", () => {
  it("replaces when no --signer (global mode)", () => {
    const existing: PlatformKeyPolicies = {
      signers: [
        {
          masterFingerprint: "aaaaaaaa",
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
        },
      ],
    };
    const incoming: PlatformKeyPolicies = {
      global: { autoBroadcastTransaction: false, signingDelaySeconds: 100 },
    };

    const result = mergePolicies(existing, incoming);
    expect(result).toEqual(incoming);
  });

  it("merges per-signer: updates existing signer, keeps others", () => {
    const existing: PlatformKeyPolicies = {
      signers: [
        {
          masterFingerprint: "aaaaaaaa",
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
        },
        {
          masterFingerprint: "bbbbbbbb",
          autoBroadcastTransaction: false,
          signingDelaySeconds: 100,
        },
      ],
    };
    const incoming: PlatformKeyPolicies = {
      signers: [
        {
          masterFingerprint: "aaaaaaaa",
          autoBroadcastTransaction: false,
          signingDelaySeconds: 3600,
        },
      ],
    };

    const result = mergePolicies(existing, incoming, "aaaaaaaa");
    expect(result.signers).toHaveLength(2);
    expect(result.signers![0].masterFingerprint).toBe("bbbbbbbb");
    expect(result.signers![1].masterFingerprint).toBe("aaaaaaaa");
    expect(result.signers![1].signingDelaySeconds).toBe(3600);
  });

  it("merges per-signer: adds new signer, keeps existing", () => {
    const existing: PlatformKeyPolicies = {
      signers: [
        {
          masterFingerprint: "aaaaaaaa",
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
        },
      ],
    };
    const incoming: PlatformKeyPolicies = {
      signers: [
        {
          masterFingerprint: "cccccccc",
          autoBroadcastTransaction: false,
          signingDelaySeconds: 60,
        },
      ],
    };

    const result = mergePolicies(existing, incoming, "cccccccc");
    expect(result.signers).toHaveLength(2);
    expect(result.signers![0].masterFingerprint).toBe("aaaaaaaa");
    expect(result.signers![1].masterFingerprint).toBe("cccccccc");
  });

  it("switches from global to per-signer when --signer used", () => {
    const existing: PlatformKeyPolicies = {
      global: { autoBroadcastTransaction: true, signingDelaySeconds: 0 },
    };
    const incoming: PlatformKeyPolicies = {
      signers: [
        {
          masterFingerprint: "aaaaaaaa",
          autoBroadcastTransaction: false,
          signingDelaySeconds: 0,
        },
      ],
    };

    const result = mergePolicies(existing, incoming, "aaaaaaaa");
    expect(result).toEqual(incoming);
    expect(result.global).toBeUndefined();
  });

  it("creates new per-signer from empty existing", () => {
    const incoming: PlatformKeyPolicies = {
      signers: [
        {
          masterFingerprint: "aaaaaaaa",
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
        },
      ],
    };

    const result = mergePolicies(undefined, incoming, "aaaaaaaa");
    expect(result).toEqual(incoming);
  });

  it("merge is case-insensitive for fingerprint", () => {
    const existing: PlatformKeyPolicies = {
      signers: [
        {
          masterFingerprint: "aabbccdd",
          autoBroadcastTransaction: true,
          signingDelaySeconds: 0,
        },
      ],
    };
    const incoming: PlatformKeyPolicies = {
      signers: [
        {
          masterFingerprint: "aabbccdd",
          autoBroadcastTransaction: false,
          signingDelaySeconds: 100,
        },
      ],
    };

    const result = mergePolicies(existing, incoming, "AABBCCDD");
    expect(result.signers).toHaveLength(1);
    expect(result.signers![0].signingDelaySeconds).toBe(100);
  });
});

describe("validateWalletPolicies", () => {
  const signerDescriptors = [
    "[aaaaaaaa/48h/1h/0h/2h]tpubD6NzVbkrYhZ4WgYk9X4g1Wv1mZ8m7fQk7uF6YvH8JQnC1vVZ6X9m3FvD7a9wY7NwB8uQ6K5pL4mN3oP2qR1sT6uV7wX8yZ9aBcDeFg",
    "[bbbbbbbb/48h/1h/0h/2h]tpubD6NzVbkrYhZ4Wj2h4X4g1Wv1mZ8m7fQk7uF6YvH8JQnC1vVZ6X9m3FvD7a9wY7NwB8uQ6K5pL4mN3oP2qR1sT6uV7wX8yZ9aBcDeFg",
    "[cccccccc/48h/1h/56h/2h]tpubD6NzVbkrYhZ4Wh3h4X4g1Wv1mZ8m7fQk7uF6YvH8JQnC1vVZ6X9m3FvD7a9wY7NwB8uQ6K5pL4mN3oP2qR1sT6uV7wX8yZ9aBcDeFg",
  ];

  it("accepts complete per-key policies for all non-platform signers", () => {
    expect(() =>
      validateWalletPolicies(
        {
          signers: [
            {
              masterFingerprint: "aaaaaaaa",
              autoBroadcastTransaction: true,
              signingDelaySeconds: 0,
            },
            {
              masterFingerprint: "bbbbbbbb",
              autoBroadcastTransaction: false,
              signingDelaySeconds: 3600,
            },
          ],
        },
        signerDescriptors,
        "cccccccc",
      ),
    ).not.toThrow();
  });

  it("rejects per-key policies missing a wallet signer", () => {
    expect(() =>
      validateWalletPolicies(
        {
          signers: [
            {
              masterFingerprint: "aaaaaaaa",
              autoBroadcastTransaction: true,
              signingDelaySeconds: 0,
            },
          ],
        },
        signerDescriptors,
        "cccccccc",
      ),
    ).toThrow("Missing signer policy");
  });

  it("rejects per-key policies for a fingerprint not in the wallet", () => {
    expect(() =>
      validateWalletPolicies(
        {
          signers: [
            {
              masterFingerprint: "dddddddd",
              autoBroadcastTransaction: true,
              signingDelaySeconds: 0,
            },
          ],
        },
        signerDescriptors,
        "cccccccc",
      ),
    ).toThrow("Master fingerprint not found in wallet");
  });
});

describe("parsePolicyJson", () => {
  it("parses valid global policy JSON", () => {
    const json = JSON.stringify({
      global: { autoBroadcastTransaction: true, signingDelaySeconds: 0 },
    });
    const result = parsePolicyJson(json);
    expect(result.global?.autoBroadcastTransaction).toBe(true);
  });

  it("parses valid per-signer policy JSON", () => {
    const json = JSON.stringify({
      signers: [
        {
          masterFingerprint: "12345678",
          autoBroadcastTransaction: false,
          signingDelaySeconds: 60,
        },
      ],
    });
    const result = parsePolicyJson(json);
    expect(result.signers).toHaveLength(1);
  });

  it("throws on invalid JSON", () => {
    expect(() => parsePolicyJson("not json")).toThrow("Invalid policy JSON");
  });

  it("throws on mutually exclusive policies", () => {
    const json = JSON.stringify({
      global: { autoBroadcastTransaction: true, signingDelaySeconds: 0 },
      signers: [
        {
          masterFingerprint: "12345678",
          autoBroadcastTransaction: false,
          signingDelaySeconds: 0,
        },
      ],
    });
    expect(() => parsePolicyJson(json)).toThrow("must not coexist");
  });
});

// -- Phase 2a tests --

describe("formatPoliciesText", () => {
  it.each([
    [0, "0s"],
    [1, "1s"],
    [59, "59s"],
    [60, "1m"],
    [61, "1m 1s"],
    [120, "2m"],
    [121, "2m 1s"],
    [3600, "1h"],
    [3601, "1h 1s"],
    [3660, "1h 1m"],
    [3661, "1h 1m 1s"],
    [7322, "2h 2m 2s"],
  ])("formats signing delay %i seconds as %s", (seconds, expected) => {
    const lines = formatPoliciesText({
      global: {
        autoBroadcastTransaction: true,
        signingDelaySeconds: seconds,
      },
    });

    expect(lines).toContain(`Signing Delay:   ${expected}`);
  });

  it("formats global policy", () => {
    const lines = formatPoliciesText({
      global: {
        autoBroadcastTransaction: true,
        signingDelaySeconds: 3600,
        spendingLimit: { interval: "DAILY", amount: "1000", currency: "USD" },
      },
    });
    expect(lines).toEqual([
      "Policy Type:     Global",
      "Auto Broadcast:  true",
      "Signing Delay:   1h",
      "Spending Limit:  1000 USD / DAILY",
    ]);
  });

  it("formats global policy with no spending limit as Unlimited", () => {
    const lines = formatPoliciesText({
      global: {
        autoBroadcastTransaction: false,
        signingDelaySeconds: 0,
        spendingLimit: null,
      },
    });
    expect(lines).toContain("Spending Limit:  Unlimited");
  });

  it("formats per-signer policies", () => {
    const lines = formatPoliciesText({
      signers: [
        {
          masterFingerprint: "aabbccdd",
          autoBroadcastTransaction: true,
          signingDelaySeconds: 60,
          spendingLimit: { interval: "WEEKLY", amount: "500", currency: "BTC" },
        },
        {
          masterFingerprint: "11223344",
          autoBroadcastTransaction: false,
          signingDelaySeconds: 0,
        },
      ],
    });
    expect(lines[0]).toBe("Policy Type:     Per-signer");
    expect(lines).toContain("Signer aabbccdd:");
    expect(lines).toContain("  Signing Delay:   1m");
    expect(lines).toContain("  Spending Limit:  500 BTC / WEEKLY");
    expect(lines).toContain("Signer 11223344:");
    expect(lines).toContain("  Spending Limit:  Unlimited");
  });

  it("formats empty policies as None", () => {
    const lines = formatPoliciesText({});
    expect(lines).toEqual(["Policy Type:     None"]);
  });
});

// Test wallet data matching the real 207u9ts4 wallet
const TEST_WALLET: WalletData = {
  walletId: "207u9ts4",
  groupId: "883409fe-511d-4ae7-92bf-250b5bd6ce45",
  gid: "mrQ3kuD4AUt1S2H5HFhGk6LbpRGLDQkzLg",
  name: "Wallet 1",
  m: 2,
  n: 3,
  addressType: 3,
  descriptor: buildWalletDescriptor(
    [
      "[b9a14f1a/48'/1'/0'/2']tpubDDuXvjq5jan2EVqnJpQjUcUAhYWVf4rrfuAgPp2oLqeGE6eZXvci5dbzuwpHdHrmGVzeBVZSCLavn4Fr5sYAd5PtzcufWwNH78KpUm37RRs",
      "[8317a853/48'/1'/0'/2']tpubDFUfs6uQ1PdCjjEasu5jAVjN32hhiSfFzS4cmgtkAK83WwWVSm26aoGeRBqKry51WmZkUgewhRaJzGGb3YLdxCFyKL8f7zC9tsF7KhQ9RxZ",
      "[ecfed4c1/48'/1'/45'/2']tpubDEeLpUMN5J595ocbHwWGyX39k7X8Jae5DqyQe5csXgJAnUZsAKrP6dhy2WDtxXvMmYCGTXo5eUuMAKV9dQryVyx3kW1EZnLXtcTTxsBvrnD",
    ],
    2,
    3,
  ),
  signers: [
    "[b9a14f1a/48'/1'/0'/2']tpubDDuXvjq5jan2EVqnJpQjUcUAhYWVf4rrfuAgPp2oLqeGE6eZXvci5dbzuwpHdHrmGVzeBVZSCLavn4Fr5sYAd5PtzcufWwNH78KpUm37RRs",
    "[8317a853/48'/1'/0'/2']tpubDFUfs6uQ1PdCjjEasu5jAVjN32hhiSfFzS4cmgtkAK83WwWVSm26aoGeRBqKry51WmZkUgewhRaJzGGb3YLdxCFyKL8f7zC9tsF7KhQ9RxZ",
    "[ecfed4c1/48'/1'/45'/2']tpubDEeLpUMN5J595ocbHwWGyX39k7X8Jae5DqyQe5csXgJAnUZsAKrP6dhy2WDtxXvMmYCGTXo5eUuMAKV9dQryVyx3kW1EZnLXtcTTxsBvrnD",
  ],
  secretboxKey: "jnQRPI4//QSN8ti/4KUkcE0dt99/hDXIxwxCcDtKCiU=",
  createdAt: "2026-03-31T02:02:07.273Z",
};

const TEST_XPRV =
  "tprv8indigs9s1wXrGCnzFR8m65FU1BmZ7UMR8TqVArSk3KegTFipNCWQJenF45BjmrcPXXfNjyx5NrsU1gEd5BKYog9dEHuu7YqWB7HUt7AuzM";

const TEST_REQUEST_BODY =
  '{"dummyTransactionId":"694364702230188032","walletId":"mrQ3kuD4AUt1S2H5HFhGk6LbpRGLDQkzLg","nonce":"d5c974eb-4b5d-43ae-8524-89d2a58c0c8a","type":"UPDATE_PLATFORM_KEY_POLICIES"}';

describe("createDummyPsbt", () => {
  it("creates a PSBT with correct structure", () => {
    const psbt = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");

    expect(psbt.inputsLength).toBe(1);
    expect(psbt.outputsLength).toBe(1);
  });

  it("supports miniscript wallets", () => {
    const miniscriptWallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor: buildMiniscriptDescriptor(
        `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),pk(${TEST_WALLET.signers[1]}/<0;1>/*))`,
        MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
      ),
    };

    const psbt = createDummyPsbt(miniscriptWallet, TEST_REQUEST_BODY, "testnet");
    expect(psbt.inputsLength).toBe(1);
    expect(psbt.outputsLength).toBe(1);
  });

  it("signs miniscript dummy PSBTs with the fallback signer", () => {
    const miniscriptWallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor: buildMiniscriptDescriptor(
        `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),pk(${TEST_WALLET.signers[1]}/<0;1>/*))`,
        MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
      ),
    };
    const psbt = createDummyPsbt(miniscriptWallet, TEST_REQUEST_BODY, "testnet");
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);

    const signed = signWalletPsbtWithKey(psbt, signerKey, TEST_XFP, miniscriptWallet.descriptor);

    expect(signed).toBe(1);
    expect(extractPartialSignature(psbt, TEST_XFP)).toMatch(/^30[0-9a-f]+01$/);
  });

  it("uses miniscript relative timelocks as input sequence", () => {
    const miniscriptWallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor: buildMiniscriptDescriptor(
        `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),older(10))`,
        MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
      ),
    };

    const psbt = createDummyPsbt(miniscriptWallet, TEST_REQUEST_BODY, "testnet");
    expect(psbt.getInput(0).sequence).toBe(10);
  });

  it("uses miniscript absolute timelocks as transaction locktime", () => {
    const miniscriptWallet: WalletData = {
      ...TEST_WALLET,
      m: 0,
      descriptor: buildMiniscriptDescriptor(
        `and_v(v:pk(${TEST_WALLET.signers[0]}/<0;1>/*),after(144))`,
        MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
      ),
    };

    const psbt = createDummyPsbt(miniscriptWallet, TEST_REQUEST_BODY, "testnet");
    expect(psbt.lockTime).toBe(144);
  });

  it("uses RBF sequence (0xfffffffd)", () => {
    const psbt = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");

    const input = psbt.getInput(0);
    expect(input.sequence).toBe(0xfffffffd);
  });

  it("has correct output amount (10000 sats)", () => {
    const psbt = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");

    const output = psbt.getOutput(0);
    expect(output.amount).toBe(10000n);
  });

  it("has witnessUtxo with 10150 sats", () => {
    const psbt = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");

    const input = psbt.getInput(0);
    expect(input.witnessUtxo?.amount).toBe(10150n);
  });

  it("has bip32Derivation for all 3 signers", () => {
    const psbt = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");

    const input = psbt.getInput(0);
    const bip32 = input.bip32Derivation as Array<
      [Uint8Array, { fingerprint: number; path: number[] }]
    >;
    expect(bip32).toHaveLength(3);
  });

  it("is deterministic (same inputs produce same PSBT)", () => {
    const psbt1 = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");
    const psbt2 = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");

    const hex1 = Buffer.from(psbt1.toPSBT()).toString("hex");
    const hex2 = Buffer.from(psbt2.toPSBT()).toString("hex");
    expect(hex1).toBe(hex2);
  });

  it("produces different PSBT for different requestBody", () => {
    const psbt1 = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");
    const psbt2 = createDummyPsbt(TEST_WALLET, "different body", "testnet");

    const hex1 = Buffer.from(psbt1.toPSBT()).toString("hex");
    const hex2 = Buffer.from(psbt2.toPSBT()).toString("hex");
    expect(hex1).not.toBe(hex2);
  });
});

// TEST_XPRV matches signer [8317a853/48'/1'/0'/2']
const TEST_XFP = 0x8317a853;

describe("extractPartialSignature", () => {
  it("extracts DER signature after signing", () => {
    const psbt = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");
    const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);

    // Sign
    const input = psbt.getInput(0);
    const bip32 = input.bip32Derivation as Array<
      [Uint8Array, { fingerprint: number; path: number[] }]
    >;
    for (const [, { fingerprint, path }] of bip32) {
      if (fingerprint === TEST_XFP) {
        const chain = path[path.length - 2];
        const index = path[path.length - 1];
        const childKey = signerKey.deriveChild(chain).deriveChild(index);
        if (childKey.privateKey) psbt.signIdx(childKey.privateKey, 0);
        break;
      }
    }

    const sig = extractPartialSignature(psbt, TEST_XFP);

    // DER signature: starts with 30, ends with sighash byte 01
    expect(sig).toMatch(/^30[0-9a-f]+01$/);
    // Typical DER length: 140-146 hex chars
    expect(sig.length).toBeGreaterThanOrEqual(140);
    expect(sig.length).toBeLessThanOrEqual(146);
  });

  it("throws when xfp has no signature", () => {
    const psbt = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");

    // No signing done — should throw
    expect(() => extractPartialSignature(psbt, TEST_XFP)).toThrow("No partial signature found");
  });

  it("produces deterministic signature", () => {
    const sign = () => {
      const psbt = createDummyPsbt(TEST_WALLET, TEST_REQUEST_BODY, "testnet");
      const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
      const input = psbt.getInput(0);
      const bip32 = input.bip32Derivation as Array<
        [Uint8Array, { fingerprint: number; path: number[] }]
      >;
      for (const [, { fingerprint, path }] of bip32) {
        if (fingerprint === TEST_XFP) {
          const chain = path[path.length - 2];
          const index = path[path.length - 1];
          const childKey = signerKey.deriveChild(chain).deriveChild(index);
          if (childKey.privateKey) psbt.signIdx(childKey.privateKey, 0);
          break;
        }
      }
      return extractPartialSignature(psbt, TEST_XFP);
    };

    expect(sign()).toBe(sign());
  });
});

describe("encryptWalletPayload / decryptWalletPayload", () => {
  it("roundtrips encrypt → decrypt", async () => {
    const plaintext = { signatures: ["b9a14f1a.3044abcd01"] };
    const encrypted = await encryptWalletPayload(TEST_WALLET, plaintext);
    const decrypted = decryptWalletPayload<typeof plaintext>(TEST_WALLET, encrypted);

    expect(decrypted).toEqual(plaintext);
  });

  it("returns version 1 with msg and sig", async () => {
    const encrypted = await encryptWalletPayload(TEST_WALLET, { test: true });

    expect(encrypted.version).toBe(1);
    expect(typeof encrypted.msg).toBe("string");
    expect(typeof encrypted.sig).toBe("string");
    expect(encrypted.msg.length).toBeGreaterThan(0);
    expect(encrypted.sig.length).toBeGreaterThan(0);
  });

  it("decrypts from nested data field", async () => {
    const plaintext = { key: "value" };
    const encrypted = await encryptWalletPayload(TEST_WALLET, plaintext);
    // Server response wraps in { data: ... }
    const wrapped = { data: encrypted };
    const decrypted = decryptWalletPayload<typeof plaintext>(TEST_WALLET, wrapped);

    expect(decrypted).toEqual(plaintext);
  });

  it("throws on missing msg field", () => {
    expect(() => decryptWalletPayload(TEST_WALLET, { version: 1, sig: "abc" })).toThrow(
      "missing msg",
    );
  });
});
