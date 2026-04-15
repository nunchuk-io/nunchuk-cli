import { describe, it, expect, beforeAll } from "vitest";
import { generateKeypair } from "../crypto.js";
import { buildMiniscriptDescriptor, miniscriptTemplateToMiniscript } from "../miniscript.js";
import {
  buildCreateGroupBody,
  buildJoinGroupEvent,
  buildAddKeyBody,
  buildSignerDescriptor,
  getGroupDisplayState,
  isGroupFinalized,
  decryptSigners,
  buildFinalizeBody,
  buildEnablePlatformKeyBody,
  buildDisablePlatformKeyBody,
  buildSetPlatformKeyPolicyBody,
  getGroupPlatformKeyState,
} from "../sandbox.js";

// Keypairs generated once per test suite
let creator: { pub: string; priv: string };
let joiner: { pub: string; priv: string };
let backend: { pub: string; priv: string };

beforeAll(() => {
  creator = generateKeypair();
  joiner = generateKeypair();
  backend = generateKeypair();
});

/** Deep-clone to avoid in-place mutation between tests */
function clone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj)) as T;
}

/** Create a fresh group and wrap it as server would return */
function createGroup(
  m = 2,
  n = 3,
  addressType: "NATIVE_SEGWIT" | "TAPROOT" = "NATIVE_SEGWIT",
  miniscriptTemplate = "",
): Record<string, unknown> {
  const body = buildCreateGroupBody(
    "Test Wallet",
    m,
    n,
    addressType,
    creator.pub,
    creator.priv,
    miniscriptTemplate,
  );
  const parsed = JSON.parse(body);
  return { init: parsed.data, status: "PENDING" };
}

/** Create a group and add keys to the first slots (leaving last slot empty) */
function createGroupWithKeys(m = 2, n = 3): Record<string, unknown> {
  let group = createGroup(m, n);
  for (let i = 0; i < n - 1; i++) {
    const desc = `[${String(i).repeat(8)}/48'/0'/0'/2']xpub${i}`;
    const body = buildAddKeyBody(`g1`, clone(group), i, desc, creator.pub, creator.priv);
    group = { init: JSON.parse(body).data, status: "PENDING" };
  }
  return group;
}

// ─── buildCreateGroupBody ───────────────────────────────────────────

describe("buildCreateGroupBody", () => {
  it("creates valid event body structure", () => {
    const body = buildCreateGroupBody(
      "My Wallet",
      2,
      3,
      "NATIVE_SEGWIT",
      creator.pub,
      creator.priv,
    );
    const parsed = JSON.parse(body);

    expect(parsed.group_id).toBe("");
    expect(parsed.type).toBe("init");
    expect(parsed.data.version).toBe(1);
    expect(parsed.data.stateId).toBe(1);
    expect(parsed.data.modified).toEqual({});
  });

  it("sets correct pubstate for 2-of-3 NATIVE_SEGWIT", () => {
    const body = buildCreateGroupBody(
      "My Wallet",
      2,
      3,
      "NATIVE_SEGWIT",
      creator.pub,
      creator.priv,
    );
    const { pubstate } = JSON.parse(body).data;

    expect(pubstate.m).toBe(2);
    expect(pubstate.n).toBe(3);
    expect(pubstate.addressType).toBe(3);
    expect(pubstate.name).toBe("My Wallet");
    expect(pubstate.occupied).toEqual([]);
    expect(pubstate.added).toEqual([]);
  });

  it("maps address type numbers correctly", () => {
    const types = { LEGACY: 1, NESTED_SEGWIT: 2, NATIVE_SEGWIT: 3, TAPROOT: 4 } as const;
    for (const [name, expected] of Object.entries(types)) {
      const body = buildCreateGroupBody(
        "W",
        2,
        3,
        name as "LEGACY" | "NESTED_SEGWIT" | "NATIVE_SEGWIT" | "TAPROOT",
        creator.pub,
        creator.priv,
      );
      expect(JSON.parse(body).data.pubstate.addressType).toBe(expected);
    }
  });

  it("encrypts state for creator's ephemeral key only", () => {
    const body = buildCreateGroupBody("W", 2, 3, "NATIVE_SEGWIT", creator.pub, creator.priv);
    const state = JSON.parse(body).data.state;

    expect(Object.keys(state)).toHaveLength(1);
    expect(state[creator.pub]).toBeDefined();
    expect(typeof state[creator.pub]).toBe("string");
  });

  it("encrypted state decrypts to n empty signers", () => {
    const group = createGroup(2, 4);
    const display = getGroupDisplayState(group, creator.pub, creator.priv);

    expect(display.signers).toEqual(["[]", "[]", "[]", "[]"]);
  });

  it("derives miniscript slot count and stores template metadata", () => {
    const template = "and_v(v:pk(key_0_0),pk(key_1_0))";
    const body = buildCreateGroupBody(
      "Policy Wallet",
      0,
      0,
      "NATIVE_SEGWIT",
      creator.pub,
      creator.priv,
      template,
    );
    const parsed = JSON.parse(body);

    expect(parsed.data.pubstate.m).toBe(0);
    expect(parsed.data.pubstate.n).toBe(2);
    expect(parsed.data.pubstate.miniscriptTemplate).toBe(template);
  });
});

// ─── buildSignerDescriptor ──────────────────────────────────────────

describe("buildSignerDescriptor", () => {
  it("normalizes h to apostrophe", () => {
    expect(buildSignerDescriptor("aabbccdd", "m/48h/0h/0h/2h", "xpub123")).toBe(
      "[aabbccdd/48'/0'/0'/2']xpub123",
    );
  });

  it("handles path already in apostrophe format", () => {
    expect(buildSignerDescriptor("aabbccdd", "/48'/0'/0'/2'", "xpub123")).toBe(
      "[aabbccdd/48'/0'/0'/2']xpub123",
    );
  });

  it("handles path without leading slash", () => {
    expect(buildSignerDescriptor("aabbccdd", "48h/0h", "xpub123")).toBe("[aabbccdd/48'/0']xpub123");
  });
});

// ─── buildJoinGroupEvent ────────────────────────────────────────────

describe("buildJoinGroupEvent", () => {
  it("adds joiner ephemeral key to state with empty string", () => {
    const group = createGroup();
    const body = buildJoinGroupEvent("g1", clone(group), joiner.pub);
    const parsed = JSON.parse(body);

    expect(parsed.data.state[joiner.pub]).toBe("");
    // Creator key should still be present
    expect(parsed.data.state[creator.pub]).toBeDefined();
  });

  it("increments stateId by 1", () => {
    const group = createGroup();
    const originalStateId = (group.init as Record<string, unknown>).stateId as number;
    const body = buildJoinGroupEvent("g1", clone(group), joiner.pub);
    const parsed = JSON.parse(body);

    expect(parsed.data.stateId).toBe(originalStateId + 1);
  });

  it("uses correct event structure { group_id, type: init, data }", () => {
    const group = createGroup();
    const body = buildJoinGroupEvent("g1", clone(group), joiner.pub);
    const parsed = JSON.parse(body);

    expect(parsed.group_id).toBe("g1");
    expect(parsed.type).toBe("init");
    expect(parsed.data).toBeDefined();
    expect(parsed.data.state).toBeDefined();
    expect(parsed.data.pubstate).toBeDefined();
  });

  it("throws if group is already finalized", () => {
    // Simulate a finalized group
    const group = { finalize: { state: {}, pubstate: {} }, status: "ACTIVE" };
    expect(() => buildJoinGroupEvent("g1", group, joiner.pub)).toThrow("already finalized");
  });

  it("throws if user already joined", () => {
    const group = createGroup();
    // Creator's pub is already in state
    expect(() => buildJoinGroupEvent("g1", clone(group), creator.pub)).toThrow("Already joined");
  });
});

// ─── buildAddKeyBody ────────────────────────────────────────────────

describe("buildAddKeyBody", () => {
  it("adds a key to the specified slot (Path A — creator)", () => {
    const group = createGroup();
    const descriptor = "[aabbccdd/48'/0'/0'/2']xpub123";

    const body = buildAddKeyBody("g1", clone(group), 0, descriptor, creator.pub, creator.priv);
    const updated = { init: JSON.parse(body).data, status: "PENDING" };
    const display = getGroupDisplayState(updated, creator.pub, creator.priv);

    expect(display.signers[0]).toBe(descriptor);
    expect(display.signers[1]).toBe("[]");
    expect(display.signers[2]).toBe("[]");
  });

  it("adds key via modified path (Path B — joiner without state entry)", () => {
    const group = createGroup();

    // Joiner has no state entry — uses Path B (modified)
    const body = buildAddKeyBody(
      "g1",
      clone(group),
      1,
      "[cccccccc/48']xpub_joiner",
      joiner.pub,
      joiner.priv,
    );
    const updated = { init: JSON.parse(body).data, status: "PENDING" };

    // Creator can see the joiner's key through modified merge
    const display = getGroupDisplayState(updated, creator.pub, creator.priv);
    expect(display.signers[1]).toBe("[cccccccc/48']xpub_joiner");
  });

  it("increments stateId after adding key", () => {
    const group = createGroup();
    const body = buildAddKeyBody(
      "g1",
      clone(group),
      0,
      "[aaaa0000/48']xpub1",
      creator.pub,
      creator.priv,
    );
    expect(JSON.parse(body).data.stateId).toBe(2);
  });

  it("updates added array correctly", () => {
    let group = createGroup(2, 3);

    // Add key at slot 1
    let body = buildAddKeyBody(
      "g1",
      clone(group),
      1,
      "[aaaa0000/48']xpub1",
      creator.pub,
      creator.priv,
    );
    expect(JSON.parse(body).data.pubstate.added).toEqual([1]);

    // Add another key at slot 0
    group = { init: JSON.parse(body).data, status: "PENDING" };
    body = buildAddKeyBody("g1", clone(group), 0, "[bbbb0000/48']xpub2", creator.pub, creator.priv);
    expect(JSON.parse(body).data.pubstate.added).toEqual([0, 1]);
  });

  it("rejects duplicate signer descriptor", () => {
    const group = createGroup();
    const descriptor = "[aabbccdd/48'/0'/0'/2']xpub123";

    const body = buildAddKeyBody("g1", clone(group), 0, descriptor, creator.pub, creator.priv);
    const updated = { init: JSON.parse(body).data, status: "PENDING" };

    expect(() =>
      buildAddKeyBody("g1", clone(updated), 1, descriptor, creator.pub, creator.priv),
    ).toThrow("already exists");
  });

  it("rejects adding to finalized group", () => {
    const group = {
      finalize: { pubstate: { n: 3, m: 2 }, state: {}, modified: {}, stateId: 1 },
      status: "ACTIVE",
    };

    expect(() =>
      buildAddKeyBody("g1", group, 0, "[aaaa/48']xpub1", creator.pub, creator.priv),
    ).toThrow("already finalized");
  });

  it("removes slot from occupied list", () => {
    const group = createGroup();
    // Manually add an occupied entry
    const init = group.init as Record<string, unknown>;
    const pubstate = init.pubstate as Record<string, unknown>;
    pubstate.occupied = [
      { i: 0, ts: 1000, uid: "user1" },
      { i: 1, ts: 2000, uid: "user2" },
    ];

    const body = buildAddKeyBody(
      "g1",
      clone(group),
      0,
      "[aaaa0000/48']xpub1",
      creator.pub,
      creator.priv,
    );
    const occupied = JSON.parse(body).data.pubstate.occupied;
    expect(occupied).toEqual([{ i: 1, ts: 2000, uid: "user2" }]);
  });
});

// ─── isGroupFinalized ───────────────────────────────────────────────

describe("isGroupFinalized", () => {
  it("returns false for pending group with init data", () => {
    const group = createGroup();
    expect(isGroupFinalized(group)).toBe(false);
  });

  it("returns true for active group with finalize data", () => {
    const group = {
      finalize: { pubstate: {}, state: {}, modified: {}, stateId: 1 },
      status: "ACTIVE",
    };
    expect(isGroupFinalized(group)).toBe(true);
  });

  it("throws for group with no init or finalize data", () => {
    expect(() => isGroupFinalized({ status: "PENDING" })).toThrow("missing group state");
  });
});

// ─── getGroupDisplayState ───────────────────────────────────────────

describe("getGroupDisplayState", () => {
  it("returns correct fields for empty group", () => {
    const group = createGroup(2, 3);
    const display = getGroupDisplayState(group, creator.pub, creator.priv);

    expect(display.name).toBe("Test Wallet");
    expect(display.m).toBe(2);
    expect(display.n).toBe(3);
    expect(display.addressType).toBe(3);
    expect(display.signers).toEqual(["[]", "[]", "[]"]);
    expect(display.added).toEqual([]);
    expect(display.participants).toBe(1);
    expect(display.status).toBe("PENDING");
  });

  it("shows added signers after add-key", () => {
    let group = createGroup(2, 2);
    const body = buildAddKeyBody(
      "g1",
      clone(group),
      0,
      "[aaaa0000/48']xpub1",
      creator.pub,
      creator.priv,
    );
    group = { init: JSON.parse(body).data, status: "PENDING" };

    const display = getGroupDisplayState(group, creator.pub, creator.priv);
    expect(display.signers[0]).toBe("[aaaa0000/48']xpub1");
    expect(display.signers[1]).toBe("[]");
    expect(display.added).toEqual([0]);
  });

  it("merges modified signers from multiple participants", () => {
    let group = createGroup(2, 3);

    // Creator adds key at slot 0
    let body = buildAddKeyBody(
      "g1",
      clone(group),
      0,
      "[aaaa0000/48']xpub1",
      creator.pub,
      creator.priv,
    );
    group = { init: JSON.parse(body).data, status: "PENDING" };

    // Joiner adds key at slot 1 via Path B
    body = buildAddKeyBody("g1", clone(group), 1, "[bbbb0000/48']xpub2", joiner.pub, joiner.priv);
    group = { init: JSON.parse(body).data, status: "PENDING" };

    // Creator sees both keys
    const display = getGroupDisplayState(group, creator.pub, creator.priv);
    expect(display.signers[0]).toBe("[aaaa0000/48']xpub1");
    expect(display.signers[1]).toBe("[bbbb0000/48']xpub2");
    expect(display.signers[2]).toBe("[]");
  });

  it("parses occupied items with correct shape", () => {
    const group = createGroup();
    const init = group.init as Record<string, unknown>;
    const pubstate = init.pubstate as Record<string, unknown>;
    pubstate.occupied = [{ i: 0, ts: 12345, uid: "user-1" }];

    const display = getGroupDisplayState(group, creator.pub, creator.priv);
    expect(display.occupied).toEqual([{ slot: 0, ts: 12345, uid: "user-1" }]);
  });

  it("handles missing state entry gracefully (falls back to empty)", () => {
    const group = createGroup();
    // Use a different key that has no state entry
    const other = generateKeypair();
    const display = getGroupDisplayState(group, other.pub, other.priv);

    expect(display.signers).toEqual(["[]", "[]", "[]"]);
  });

  it("includes miniscript slot names and type label", () => {
    const template = "and_v(v:pk(key_0_0),pk(key_1_0))";
    const group = createGroup(0, 0, "NATIVE_SEGWIT", template);
    const display = getGroupDisplayState(group, creator.pub, creator.priv);

    expect(display.kind).toBe("miniscript");
    expect(display.typeLabel).toBe("MINISCRIPT");
    expect(display.slotNames).toEqual(["key_0_0", "key_1_0"]);
    expect(display.miniscriptTemplate).toBe(template);
  });
});

// ─── decryptSigners ─────────────────────────────────────────────────

describe("decryptSigners", () => {
  it("decrypts all signers when all slots are filled", () => {
    let group = createGroup(2, 2);
    let body = buildAddKeyBody(
      "g1",
      clone(group),
      0,
      "[aaaa0000/48']xpub1",
      creator.pub,
      creator.priv,
    );
    group = { init: JSON.parse(body).data, status: "PENDING" };

    body = buildAddKeyBody("g1", clone(group), 1, "[bbbb0000/48']xpub2", creator.pub, creator.priv);
    group = { init: JSON.parse(body).data, status: "PENDING" };

    const { signers } = decryptSigners(group, creator.pub, creator.priv);
    expect(signers).toEqual(["[aaaa0000/48']xpub1", "[bbbb0000/48']xpub2"]);
  });

  it("throws when a slot is empty", () => {
    const group = createGroup(2, 2);
    // Only add one key, leaving slot 1 empty
    const body = buildAddKeyBody(
      "g1",
      clone(group),
      0,
      "[aaaa0000/48']xpub1",
      creator.pub,
      creator.priv,
    );
    const updated = { init: JSON.parse(body).data, status: "PENDING" };

    expect(() => decryptSigners(updated, creator.pub, creator.priv)).toThrow("slot 1 is empty");
  });

  it("throws for finalized group", () => {
    const group = {
      finalize: { pubstate: { n: 2, m: 2 }, state: {}, modified: {}, stateId: 1 },
      status: "ACTIVE",
    };
    expect(() => decryptSigners(group, creator.pub, creator.priv)).toThrow("already active");
  });

  it("throws when no state entry for ephemeral key", () => {
    const group = createGroup();
    const other = generateKeypair();
    expect(() => decryptSigners(group, other.pub, other.priv)).toThrow("no state entry");
  });
});

describe("buildFinalizeBody", () => {
  it("builds miniscript descriptors from the sandbox template", async () => {
    const template = "and_v(v:pk(key_0_0),pk(key_1_0))";
    let group = createGroup(0, 0, "NATIVE_SEGWIT", template);
    const signerA = "[aaaa0000/48'/1'/0'/2']tpubA";
    const signerB = "[bbbb0000/48'/1'/0'/2']tpubB";

    let body = buildAddKeyBody("g1", clone(group), 0, signerA, creator.pub, creator.priv);
    group = { init: JSON.parse(body).data, status: "PENDING" };

    body = buildAddKeyBody("g1", clone(group), 1, signerB, creator.pub, creator.priv);
    group = { init: JSON.parse(body).data, status: "PENDING" };

    const result = await buildFinalizeBody("g1", group, creator.pub, creator.priv, "testnet");

    const miniscript = miniscriptTemplateToMiniscript(
      template,
      { key_0_0: signerA, key_1_0: signerB },
      "/<0;1>/*",
      "NATIVE_SEGWIT",
    );
    expect(result.descriptor).toBe(buildMiniscriptDescriptor(miniscript, "NATIVE_SEGWIT"));
    expect(result.m).toBe(0);
    expect(result.n).toBe(2);
    expect(result.signers).toEqual([signerA, signerB]);
  });
});

// ─── Platform Key: enable ───────────────────────────────────────────

describe("buildEnablePlatformKeyBody", () => {
  it("enables platform key and adds backend to state", () => {
    const group = createGroupWithKeys();

    const body = buildEnablePlatformKeyBody(
      "g1",
      clone(group),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    const parsed = JSON.parse(body);
    const updated = { init: parsed.data, status: "PENDING" };

    // Platform key should be enabled
    const config = getGroupPlatformKeyState(updated, creator.pub, creator.priv);
    expect(config).not.toBeNull();
    expect(config!.policies).toEqual({});

    // Backend key should be in state
    expect(parsed.data.state[backend.pub]).toBeDefined();

    // Last slot should be cleared
    const display = getGroupDisplayState(updated, creator.pub, creator.priv);
    expect(display.signers[2]).toBe("[]");
    // First two keys remain
    expect(display.signers[0]).not.toBe("[]");
    expect(display.signers[1]).not.toBe("[]");
  });

  it("increments stateId after enabling platform key", () => {
    const group = createGroupWithKeys();
    const prevStateId = (group.init as Record<string, unknown>).stateId as number;

    const body = buildEnablePlatformKeyBody(
      "g1",
      clone(group),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    expect(JSON.parse(body).data.stateId).toBe(prevStateId + 1);
  });

  it("throws when platform key is already enabled", () => {
    const group = createGroupWithKeys();
    const body = buildEnablePlatformKeyBody(
      "g1",
      clone(group),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    const enabled = { init: JSON.parse(body).data, status: "PENDING" };

    expect(() =>
      buildEnablePlatformKeyBody("g1", clone(enabled), backend.pub, creator.pub, creator.priv),
    ).toThrow("already enabled");
  });

  it("throws for finalized group", () => {
    const group = {
      finalize: { pubstate: { n: 3, m: 2 }, state: {}, modified: {}, stateId: 1 },
      status: "ACTIVE",
    };
    expect(() =>
      buildEnablePlatformKeyBody("g1", group, backend.pub, creator.pub, creator.priv),
    ).toThrow("already finalized");
  });

  it("enables platform key for miniscript sandboxes with named slots", () => {
    const template = "and_v(v:pk(key_0_0),pk(key_1_0))";
    let group = createGroup(0, 0, "NATIVE_SEGWIT", template);
    let body = buildAddKeyBody(
      "g1",
      clone(group),
      0,
      "[aaaa0000/48']xpub1",
      creator.pub,
      creator.priv,
    );
    group = { init: JSON.parse(body).data, status: "PENDING" };
    body = buildAddKeyBody("g1", clone(group), 1, "[bbbb0000/48']xpub2", creator.pub, creator.priv);
    group = { init: JSON.parse(body).data, status: "PENDING" };

    body = buildEnablePlatformKeyBody("g1", clone(group), backend.pub, creator.pub, creator.priv, [
      "key_1_0",
    ]);
    const parsed = JSON.parse(body);
    const updated = { init: parsed.data, status: "PENDING" };

    expect(parsed.data.state[backend.pub]).toBeDefined();
    expect(getGroupPlatformKeyState(updated, creator.pub, creator.priv)?.slots).toEqual([
      "key_1_0",
    ]);
    expect(getGroupDisplayState(updated, creator.pub, creator.priv).signers).toEqual([
      "[aaaa0000/48']xpub1",
      "[bbbb0000/48']xpub2",
    ]);
  });

  it("requires miniscript slot names when enabling platform key", () => {
    const template = "and_v(v:pk(key_0_0),pk(key_1_0))";
    const group = createGroup(0, 0, "NATIVE_SEGWIT", template);
    expect(() =>
      buildEnablePlatformKeyBody("g1", clone(group), backend.pub, creator.pub, creator.priv),
    ).toThrow("required for miniscript");
  });
});

// ─── Platform Key: disable ──────────────────────────────────────────

describe("buildDisablePlatformKeyBody", () => {
  function enablePlatformKey(): Record<string, unknown> {
    const group = createGroupWithKeys();
    const body = buildEnablePlatformKeyBody(
      "g1",
      clone(group),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    return { init: JSON.parse(body).data, status: "PENDING" };
  }

  it("disables platform key and removes backend from state", () => {
    const enabled = enablePlatformKey();

    const body = buildDisablePlatformKeyBody(
      "g1",
      clone(enabled),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    const parsed = JSON.parse(body);
    const updated = { init: parsed.data, status: "PENDING" };

    // Platform key should be gone
    const config = getGroupPlatformKeyState(updated, creator.pub, creator.priv);
    expect(config).toBeNull();

    // Backend key should be removed from state
    expect(parsed.data.state[backend.pub]).toBeUndefined();
  });

  it("throws when platform key is not enabled", () => {
    const group = createGroupWithKeys();
    expect(() =>
      buildDisablePlatformKeyBody("g1", clone(group), backend.pub, creator.pub, creator.priv),
    ).toThrow("not enabled");
  });

  it("clears configured miniscript platform key slots on disable", () => {
    const template = "and_v(v:pk(key_0_0),pk(key_1_0))";
    let group = createGroup(0, 0, "NATIVE_SEGWIT", template);
    let body = buildAddKeyBody(
      "g1",
      clone(group),
      0,
      "[aaaa0000/48']xpub1",
      creator.pub,
      creator.priv,
    );
    group = { init: JSON.parse(body).data, status: "PENDING" };
    body = buildAddKeyBody("g1", clone(group), 1, "[bbbb0000/48']xpub2", creator.pub, creator.priv);
    group = { init: JSON.parse(body).data, status: "PENDING" };
    body = buildEnablePlatformKeyBody("g1", clone(group), backend.pub, creator.pub, creator.priv, [
      "key_1_0",
    ]);
    const enabled = { init: JSON.parse(body).data, status: "PENDING" };

    body = buildDisablePlatformKeyBody(
      "g1",
      clone(enabled),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    const updated = { init: JSON.parse(body).data, status: "PENDING" };

    expect(getGroupDisplayState(updated, creator.pub, creator.priv).signers).toEqual([
      "[aaaa0000/48']xpub1",
      "[]",
    ]);
  });
});

// ─── Platform Key: set-policy ───────────────────────────────────────

describe("buildSetPlatformKeyPolicyBody", () => {
  function enablePlatformKey(): Record<string, unknown> {
    const group = createGroupWithKeys();
    const body = buildEnablePlatformKeyBody(
      "g1",
      clone(group),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    return { init: JSON.parse(body).data, status: "PENDING" };
  }

  it("sets global policy", () => {
    const enabled = enablePlatformKey();
    const policies = {
      global: { autoBroadcastTransaction: true, signingDelaySeconds: 3600 },
    };

    const body = buildSetPlatformKeyPolicyBody(
      "g1",
      clone(enabled),
      policies,
      creator.pub,
      creator.priv,
    );
    const updated = { init: JSON.parse(body).data, status: "PENDING" };

    const config = getGroupPlatformKeyState(updated, creator.pub, creator.priv);
    expect(config!.policies.global).toEqual({
      autoBroadcastTransaction: true,
      signingDelaySeconds: 3600,
    });
  });

  it("sets per-signer policy", () => {
    const enabled = enablePlatformKey();
    const policies = {
      signers: [
        {
          masterFingerprint: "aaaa0000",
          autoBroadcastTransaction: false,
          signingDelaySeconds: 60,
        },
      ],
    };

    const body = buildSetPlatformKeyPolicyBody(
      "g1",
      clone(enabled),
      policies,
      creator.pub,
      creator.priv,
    );
    const updated = { init: JSON.parse(body).data, status: "PENDING" };

    const config = getGroupPlatformKeyState(updated, creator.pub, creator.priv);
    expect(config!.policies.signers).toHaveLength(1);
    expect(config!.policies.signers![0].masterFingerprint).toBe("aaaa0000");
  });

  it("replaces existing policy", () => {
    const enabled = enablePlatformKey();

    // Set initial policy
    let body = buildSetPlatformKeyPolicyBody(
      "g1",
      clone(enabled),
      { global: { autoBroadcastTransaction: true, signingDelaySeconds: 0 } },
      creator.pub,
      creator.priv,
    );
    let updated = { init: JSON.parse(body).data, status: "PENDING" };

    // Replace with different policy
    body = buildSetPlatformKeyPolicyBody(
      "g1",
      clone(updated),
      { global: { autoBroadcastTransaction: false, signingDelaySeconds: 7200 } },
      creator.pub,
      creator.priv,
    );
    updated = { init: JSON.parse(body).data, status: "PENDING" };

    const config = getGroupPlatformKeyState(updated, creator.pub, creator.priv);
    expect(config!.policies.global!.autoBroadcastTransaction).toBe(false);
    expect(config!.policies.global!.signingDelaySeconds).toBe(7200);
  });

  it("throws when platform key is not enabled", () => {
    const group = createGroupWithKeys();
    expect(() =>
      buildSetPlatformKeyPolicyBody(
        "g1",
        clone(group),
        { global: { autoBroadcastTransaction: true, signingDelaySeconds: 0 } },
        creator.pub,
        creator.priv,
      ),
    ).toThrow("not enabled");
  });

  it("preserves existing signers in state", () => {
    const enabled = enablePlatformKey();

    const body = buildSetPlatformKeyPolicyBody(
      "g1",
      clone(enabled),
      { global: { autoBroadcastTransaction: true, signingDelaySeconds: 0 } },
      creator.pub,
      creator.priv,
    );
    const updated = { init: JSON.parse(body).data, status: "PENDING" };

    const display = getGroupDisplayState(updated, creator.pub, creator.priv);
    // First two signers should still be there
    expect(display.signers[0]).not.toBe("[]");
    expect(display.signers[1]).not.toBe("[]");
  });
});

// ─── Platform Key: getGroupPlatformKeyState ─────────────────────────

describe("getGroupPlatformKeyState", () => {
  it("returns null when platform key is not enabled", () => {
    const group = createGroup();
    expect(getGroupPlatformKeyState(group, creator.pub, creator.priv)).toBeNull();
  });

  it("returns config when enabled", () => {
    const group = createGroupWithKeys();
    const body = buildEnablePlatformKeyBody(
      "g1",
      clone(group),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    const enabled = { init: JSON.parse(body).data, status: "PENDING" };

    const config = getGroupPlatformKeyState(enabled, creator.pub, creator.priv);
    expect(config).not.toBeNull();
    expect(config!.policies).toEqual({});
  });

  it("returns null when no state entry for key", () => {
    const group = createGroup();
    const other = generateKeypair();
    expect(getGroupPlatformKeyState(group, other.pub, other.priv)).toBeNull();
  });

  it("returns policies after set-policy", () => {
    const group = createGroupWithKeys();
    let body = buildEnablePlatformKeyBody(
      "g1",
      clone(group),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    let updated = { init: JSON.parse(body).data, status: "PENDING" };

    body = buildSetPlatformKeyPolicyBody(
      "g1",
      clone(updated),
      {
        global: {
          autoBroadcastTransaction: true,
          signingDelaySeconds: 600,
          spendingLimit: { interval: "DAILY", amount: "500", currency: "USD" },
        },
      },
      creator.pub,
      creator.priv,
    );
    updated = { init: JSON.parse(body).data, status: "PENDING" };

    const config = getGroupPlatformKeyState(updated, creator.pub, creator.priv);
    expect(config!.policies.global!.autoBroadcastTransaction).toBe(true);
    expect(config!.policies.global!.signingDelaySeconds).toBe(600);
    expect(config!.policies.global!.spendingLimit).toEqual({
      interval: "DAILY",
      amount: "500",
      currency: "USD",
    });
  });
});

// ─── Full lifecycle: enable → set-policy → disable ──────────────────

describe("platform key lifecycle", () => {
  it("enable → set global policy → disable", () => {
    const group = createGroupWithKeys();

    // Enable
    let body = buildEnablePlatformKeyBody(
      "g1",
      clone(group),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    let current = { init: JSON.parse(body).data, status: "PENDING" } as Record<string, unknown>;
    expect(getGroupPlatformKeyState(current, creator.pub, creator.priv)).not.toBeNull();

    // Set policy
    body = buildSetPlatformKeyPolicyBody(
      "g1",
      clone(current),
      { global: { autoBroadcastTransaction: true, signingDelaySeconds: 3600 } },
      creator.pub,
      creator.priv,
    );
    current = { init: JSON.parse(body).data, status: "PENDING" };
    const config = getGroupPlatformKeyState(current, creator.pub, creator.priv);
    expect(config!.policies.global!.signingDelaySeconds).toBe(3600);

    // Disable
    body = buildDisablePlatformKeyBody(
      "g1",
      clone(current),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    current = { init: JSON.parse(body).data, status: "PENDING" };
    expect(getGroupPlatformKeyState(current, creator.pub, creator.priv)).toBeNull();

    // Signers still intact
    const display = getGroupDisplayState(current, creator.pub, creator.priv);
    expect(display.signers[0]).not.toBe("[]");
    expect(display.signers[1]).not.toBe("[]");
  });

  it("enable → set per-signer → update single signer → verify merge preserved", () => {
    const group = createGroupWithKeys();

    // Enable
    let body = buildEnablePlatformKeyBody(
      "g1",
      clone(group),
      backend.pub,
      creator.pub,
      creator.priv,
    );
    let current = { init: JSON.parse(body).data, status: "PENDING" } as Record<string, unknown>;

    // Set policy for two signers
    body = buildSetPlatformKeyPolicyBody(
      "g1",
      clone(current),
      {
        signers: [
          {
            masterFingerprint: "aaaa0000",
            autoBroadcastTransaction: true,
            signingDelaySeconds: 0,
          },
          {
            masterFingerprint: "bbbb0000",
            autoBroadcastTransaction: false,
            signingDelaySeconds: 300,
          },
        ],
      },
      creator.pub,
      creator.priv,
    );
    current = { init: JSON.parse(body).data, status: "PENDING" };

    let config = getGroupPlatformKeyState(current, creator.pub, creator.priv);
    expect(config!.policies.signers).toHaveLength(2);

    // Replace with global policy (full replacement at API level)
    body = buildSetPlatformKeyPolicyBody(
      "g1",
      clone(current),
      { global: { autoBroadcastTransaction: false, signingDelaySeconds: 60 } },
      creator.pub,
      creator.priv,
    );
    current = { init: JSON.parse(body).data, status: "PENDING" };

    config = getGroupPlatformKeyState(current, creator.pub, creator.priv);
    expect(config!.policies.global).toBeDefined();
    expect(config!.policies.signers).toBeUndefined();
  });
});
