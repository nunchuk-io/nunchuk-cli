import { describe, expect, it } from "vitest";
import { generateKeypair } from "../crypto.js";
import { buildWalletDescriptor } from "../descriptor.js";
import { withDescriptorChecksum } from "../miniscript.js";
import {
  buildCreateReplaceGroupBody,
  getGroupDisplayState,
  getGroupPlatformKeyState,
} from "../sandbox.js";
import type { WalletData } from "../storage.js";
import {
  getDeprecatedWalletName,
  getGroupReplaceWalletId,
  getReplacementAcceptSigners,
  getReplacementGroupDetails,
} from "../wallet-replacement.js";

const SIGNERS = [
  "[aaaa0000/48'/1'/0'/2']tpubD1111111111111111111111111111111111111111111111111111111111111111111",
  "[bbbb0000/48'/1'/0'/2']tpubD2222222222222222222222222222222222222222222222222222222222222222222",
  "[cccc0000/48'/1'/0'/2']tpubD3333333333333333333333333333333333333333333333333333333333333333333",
];

function makeWallet(overrides: Partial<WalletData> = {}): WalletData {
  return {
    walletId: "wallet-1",
    groupId: "group-1",
    gid: "gid-1",
    name: "Vault",
    m: 2,
    n: 3,
    addressType: "NATIVE_SEGWIT",
    descriptor: buildWalletDescriptor(SIGNERS, 2, "NATIVE_SEGWIT"),
    signers: SIGNERS,
    secretboxKey: Buffer.from("a".repeat(32)).toString("base64"),
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

function makeMiniscriptWallet(miniscript: string): WalletData {
  return makeWallet({
    m: 0,
    n: 0,
    descriptor: withDescriptorChecksum(`wsh(${miniscript})`),
    signers: [],
  });
}

describe("wallet replacement helpers", () => {
  it("reads replacement wallet ids from group metadata", () => {
    expect(getGroupReplaceWalletId({ replace_wallet_id: "gid-1" })).toBe("gid-1");
    expect(
      getGroupReplaceWalletId({
        init: { extra: { replace_wallet_id: "gid-2" } },
      }),
    ).toBe("gid-2");
    expect(
      getGroupReplaceWalletId({
        finalize: { extra: { replaceWalletId: "gid-3" } },
      }),
    ).toBe("gid-3");
  });

  it("prefixes deprecated wallet names idempotently", () => {
    expect(getDeprecatedWalletName("Vault")).toBe("[DEPRECATED] Vault");
    expect(getDeprecatedWalletName("[DEPRECATED] Vault")).toBe("[DEPRECATED] Vault");
  });

  it("builds multisig replacement details from the wallet descriptor", () => {
    const details = getReplacementGroupDetails(makeWallet());

    expect(details).toMatchObject({
      name: "Vault",
      m: 2,
      n: 3,
      addressType: "NATIVE_SEGWIT",
      miniscriptTemplate: "",
      platformKeySlots: [],
    });
    expect(details.signers).toEqual(SIGNERS);
    expect(getReplacementAcceptSigners(makeWallet())).toEqual(SIGNERS);
  });

  it("derives multisig signers from the descriptor instead of stale wallet metadata", () => {
    const details = getReplacementGroupDetails(makeWallet({ signers: ["[dddd0000/48']stale"] }));

    expect(details.signers).toEqual(SIGNERS);
  });

  it("derives Taproot multisig replacement details", () => {
    const wallet = makeWallet({
      addressType: "TAPROOT",
      descriptor: buildWalletDescriptor(SIGNERS, 2, "TAPROOT", "DEFAULT"),
    });

    const details = getReplacementGroupDetails(wallet);

    expect(details.addressType).toBe("TAPROOT");
    expect(details.signers).toEqual(SIGNERS);
  });

  it("clears the last multisig signer when replacing a platform-key wallet", () => {
    const details = getReplacementGroupDetails(makeWallet(), {
      platformKey: { policies: {} },
      platformKeyFingerprint: "cccc0000",
    });

    expect(details.signers).toEqual([SIGNERS[0], SIGNERS[1], "[]"]);
    expect(getReplacementAcceptSigners(makeWallet(), { platformKey: { policies: {} } })).toEqual([
      SIGNERS[0],
      SIGNERS[1],
      "[]",
    ]);
  });

  it("clears the last multisig signer even when the platform key fingerprint points elsewhere", () => {
    const details = getReplacementGroupDetails(makeWallet(), {
      platformKey: { policies: {} },
      platformKeyFingerprint: "bbbb0000",
    });

    expect(details.signers).toEqual([SIGNERS[0], SIGNERS[1], "[]"]);
    expect(details.platformKeySlots).toEqual([]);
  });

  it("does not clear multisig signers when only a platform key fingerprint is present", () => {
    const details = getReplacementGroupDetails(makeWallet(), {
      platformKey: null,
      platformKeyFingerprint: "cccc0000",
    });

    expect(details.signers).toEqual(SIGNERS);
  });

  it("rebuilds native-segwit miniscript replacement template", () => {
    const miniscript = `and_v(v:pk(${SIGNERS[0]}/<0;1>/*),pk(${SIGNERS[1]}/<0;1>/*))`;
    const wallet = makeMiniscriptWallet(miniscript);

    const details = getReplacementGroupDetails(wallet);

    expect(details.m).toBe(0);
    expect(details.n).toBe(2);
    expect(details.miniscriptTemplate).toBe("and_v(v:pk(key_0),pk(key_1))");
    expect(details.signers).toEqual(SIGNERS.slice(0, 2));
    expect(getReplacementAcceptSigners(wallet)).toEqual(SIGNERS.slice(0, 2));
  });

  it("rebuilds complex miniscript templates and preserves signer order", () => {
    const miniscript = `or_d(multi(2,${SIGNERS[0]}/<0;1>/*,${SIGNERS[1]}/<0;1>/*),and_v(v:pk(${SIGNERS[2]}/<0;1>/*),older(144)))`;
    const wallet = makeMiniscriptWallet(miniscript);

    const details = getReplacementGroupDetails(wallet);

    expect(details.m).toBe(0);
    expect(details.n).toBe(3);
    expect(details.miniscriptTemplate).toBe(
      "or_d(multi(2,key_0,key_1),and_v(v:pk(key_2),older(144)))",
    );
    expect(details.signers).toEqual(SIGNERS);
  });

  it("normalizes miniscript descriptors that use external-only child paths", () => {
    const miniscript = `and_v(v:pk(${SIGNERS[0]}/0/*),pk(${SIGNERS[1]}/0/*))`;
    const wallet = makeMiniscriptWallet(miniscript);

    const details = getReplacementGroupDetails(wallet);

    expect(details.miniscriptTemplate).toBe("and_v(v:pk(key_0),pk(key_1))");
    expect(details.signers).toEqual(SIGNERS.slice(0, 2));
  });

  it("clears miniscript platform-key signer slots for replacement", () => {
    const miniscript = `and_v(v:pk(${SIGNERS[0]}/<0;1>/*),pk(${SIGNERS[1]}/<0;1>/*))`;
    const wallet = makeMiniscriptWallet(miniscript);

    const details = getReplacementGroupDetails(wallet, {
      platformKey: { policies: {} },
      platformKeyFingerprint: "bbbb0000",
    });

    expect(details.platformKeySlots).toEqual(["key_1"]);
    expect(details.signers).toEqual([SIGNERS[0], "[]"]);
    expect(
      getReplacementAcceptSigners(wallet, {
        platformKey: { policies: {} },
        platformKeyFingerprint: "bbbb0000",
      }),
    ).toEqual([SIGNERS[0], "[]"]);
  });

  it("clears multiple miniscript platform-key signer slots with the same fingerprint", () => {
    const platformSigner =
      "[bbbb0000/48'/1'/1'/2']tpubD4444444444444444444444444444444444444444444444444444444444444444444";
    const signers = [SIGNERS[0], SIGNERS[1], platformSigner];
    const miniscript = `thresh(2,pk(${signers[0]}/<0;1>/*),s:pk(${signers[1]}/<0;1>/*),s:pk(${signers[2]}/<0;1>/*))`;
    const wallet = makeMiniscriptWallet(miniscript);

    const details = getReplacementGroupDetails(wallet, {
      platformKey: { policies: {} },
      platformKeyFingerprint: "bbbb0000",
    });

    expect(details.platformKeySlots).toEqual(["key_1", "key_2"]);
    expect(details.signers).toEqual([SIGNERS[0], "[]", "[]"]);
  });

  it("does not guess miniscript platform-key slots when fingerprint is missing", () => {
    const miniscript = `and_v(v:pk(${SIGNERS[0]}/<0;1>/*),pk(${SIGNERS[1]}/<0;1>/*))`;
    const wallet = makeMiniscriptWallet(miniscript);

    const details = getReplacementGroupDetails(wallet, { platformKey: { policies: {} } });

    expect(details.platformKeySlots).toEqual([]);
    expect(details.signers).toEqual(SIGNERS.slice(0, 2));
  });

  it("does not clear miniscript signers when platform key fingerprint is unknown", () => {
    const miniscript = `and_v(v:pk(${SIGNERS[0]}/<0;1>/*),pk(${SIGNERS[1]}/<0;1>/*))`;
    const wallet = makeMiniscriptWallet(miniscript);

    const details = getReplacementGroupDetails(wallet, {
      platformKey: { policies: {} },
      platformKeyFingerprint: "dddd0000",
    });

    expect(details.platformKeySlots).toEqual([]);
    expect(details.signers).toEqual(SIGNERS.slice(0, 2));
  });

  it("builds a replacement create event from multisig details", () => {
    const creator = generateKeypair();
    const details = getReplacementGroupDetails(makeWallet());
    const body = buildCreateReplaceGroupBody({
      ...details,
      ephemeralPub: creator.pub,
      ephemeralPriv: creator.priv,
    });
    const parsed = JSON.parse(body);
    const group = { init: parsed.data, status: "PENDING" };

    expect(parsed.data.pubstate.added).toEqual([0, 1, 2]);
    expect(getGroupDisplayState(group, creator.pub, creator.priv).signers).toEqual(SIGNERS);
    expect(getGroupPlatformKeyState(group, creator.pub, creator.priv)).toBeNull();
  });

  it("builds a replacement create event with miniscript platform key metadata", () => {
    const creator = generateKeypair();
    const backend = generateKeypair();
    const miniscript = `and_v(v:pk(${SIGNERS[0]}/<0;1>/*),pk(${SIGNERS[1]}/<0;1>/*))`;
    const wallet = makeMiniscriptWallet(miniscript);
    const platformKey = {
      policies: { global: { autoBroadcastTransaction: true, signingDelaySeconds: 60 } },
    };
    const details = getReplacementGroupDetails(wallet, {
      platformKey,
      platformKeyFingerprint: "bbbb0000",
    });

    const body = buildCreateReplaceGroupBody({
      ...details,
      ephemeralPub: creator.pub,
      ephemeralPriv: creator.priv,
      platformKey,
      backendPubkey: backend.pub,
    });
    const parsed = JSON.parse(body);
    const group = { init: parsed.data, status: "PENDING" };

    expect(parsed.data.state[backend.pub]).toBeDefined();
    expect(parsed.data.pubstate.added).toEqual([0]);
    expect(getGroupDisplayState(group, creator.pub, creator.priv).signers).toEqual([
      SIGNERS[0],
      "[]",
    ]);
    expect(getGroupPlatformKeyState(group, creator.pub, creator.priv)).toEqual({
      ...platformKey,
      slots: ["key_1"],
    });
  });
});
