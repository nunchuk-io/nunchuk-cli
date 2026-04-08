import { describe, expect, it } from "vitest";
import { HDKey } from "@scure/bip32";
import { combinePendingPsbt, decodePsbtDetail } from "../transaction.js";
import { createDummyPsbt } from "../platform-key.js";
import { TESTNET_VERSIONS } from "../address.js";
import type { WalletData } from "../storage.js";

const TEST_WALLET: WalletData = {
  walletId: "207u9ts4",
  groupId: "883409fe-511d-4ae7-92bf-250b5bd6ce45",
  gid: "mrQ3kuD4AUt1S2H5HFhGk6LbpRGLDQkzLg",
  name: "Wallet 1",
  m: 2,
  n: 3,
  addressType: 3,
  descriptor: "",
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

const TEST_XFP = 0x8317a853;

function createPsbtB64(requestBody = "testing"): string {
  return Buffer.from(createDummyPsbt(TEST_WALLET, requestBody, "testnet").toPSBT()).toString(
    "base64",
  );
}

function createSignedPsbtB64(requestBody = "testing"): string {
  const psbt = createDummyPsbt(TEST_WALLET, requestBody, "testnet");
  const signerKey = HDKey.fromExtendedKey(TEST_XPRV, TESTNET_VERSIONS);
  const input = psbt.getInput(0);
  const bip32 = input.bip32Derivation as Array<
    [Uint8Array, { fingerprint: number; path: number[] }]
  >;

  for (const [, { fingerprint, path }] of bip32) {
    if (fingerprint !== TEST_XFP) continue;

    const chain = path[path.length - 2];
    const index = path[path.length - 1];
    const childKey = signerKey.deriveChild(chain).deriveChild(index);
    if (childKey.privateKey) {
      psbt.signIdx(childKey.privateKey, 0);
    }
    break;
  }

  return Buffer.from(psbt.toPSBT()).toString("base64");
}

describe("combinePendingPsbt", () => {
  it("marks changed when the provided PSBT adds a new signature", () => {
    const currentPsbtB64 = createPsbtB64();
    const nextPsbtB64 = createSignedPsbtB64();

    const result = combinePendingPsbt(currentPsbtB64, nextPsbtB64);
    const detail = decodePsbtDetail(result.psbtB64, "testnet", TEST_WALLET.m, TEST_WALLET.signers);

    expect(result.changed).toBe(true);
    expect(detail?.signedCount).toBe(1);
    expect(detail?.signers["8317a853"]).toBe(true);
  });

  it("marks unchanged when the provided PSBT adds no new data", () => {
    const currentPsbtB64 = createSignedPsbtB64();

    const result = combinePendingPsbt(currentPsbtB64, currentPsbtB64);
    const detail = decodePsbtDetail(result.psbtB64, "testnet", TEST_WALLET.m, TEST_WALLET.signers);

    expect(result.changed).toBe(false);
    expect(detail?.signedCount).toBe(1);
    expect(detail?.signers["8317a853"]).toBe(true);
  });

  it("rejects a provided PSBT for a different unsigned transaction", () => {
    const currentPsbtB64 = createPsbtB64();
    const nextPsbtB64 = createSignedPsbtB64("different testing body");

    expect(() => combinePendingPsbt(currentPsbtB64, nextPsbtB64)).toThrow(
      "Provided PSBT does not match the current pending transaction",
    );
  });
});
