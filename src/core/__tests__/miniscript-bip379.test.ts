import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hex } from "@scure/base";
import { Script, type ScriptOP } from "@scure/btc-signer/script.js";
import { describe, expect, it } from "vitest";
import { deriveDescriptorPayment } from "../address.js";
import { buildMiniscriptDescriptor, isValidMiniscriptTemplate } from "../miniscript.js";

const KEY_0 = "03841ad0999320d435ce8e1e7dc8b2fb7abaa4bd2e5b8599bf2c02eba66b12b869";
const KEY_1 = "030bab88fd386b5da3091705821dc25982f9ee1826027965361c9ac21017d2606b";
const KEY_2 = "02ccbd907b579569072e7ef555cf5a11c3dda49d248c80a0b4e568b4372739e4c1";

const KEY_0_BYTES = hex.decode(KEY_0);
const KEY_1_BYTES = hex.decode(KEY_1);
const KEY_2_BYTES = hex.decode(KEY_2);
const HASH20 = "11".repeat(20);
const HASH32 = "22".repeat(32);
const RELATIVE_TIME_LOCK = 0x400001;

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function scriptHex(ops: ScriptOP[]): string {
  return hex.encode(Script.encode(ops));
}

function witnessScriptHex(miniscript: string): string {
  const descriptor = buildMiniscriptDescriptor(miniscript, "NATIVE_SEGWIT");
  const payment = deriveDescriptorPayment(descriptor, "testnet", 0, 0);
  if (!payment.witnessScript) {
    throw new Error("Expected miniscript witness script");
  }
  return hex.encode(payment.witnessScript);
}

describe("BIP-0379 miniscript script translation", () => {
  it.each([
    ["0", "0", [0]],
    ["1", "1", [1]],
    ["c:pk_k", `c:pk_k(${KEY_0})`, [KEY_0_BYTES, "CHECKSIG"]],
    [
      "c:pk_h",
      `c:pk_h(${KEY_0})`,
      ["DUP", "HASH160", hash160(KEY_0_BYTES), "EQUALVERIFY", "CHECKSIG"],
    ],
    ["pk", `pk(${KEY_0})`, [KEY_0_BYTES, "CHECKSIG"]],
    ["pkh", `pkh(${KEY_0})`, ["DUP", "HASH160", hash160(KEY_0_BYTES), "EQUALVERIFY", "CHECKSIG"]],
    ["older", "older(10)", [10, "CHECKSEQUENCEVERIFY"]],
    ["after", "after(500000001)", [500000001, "CHECKLOCKTIMEVERIFY"]],
    [
      "sha256",
      `sha256(${HASH32})`,
      ["SIZE", 32, "EQUALVERIFY", "SHA256", hex.decode(HASH32), "EQUAL"],
    ],
    [
      "hash256",
      `hash256(${HASH32})`,
      ["SIZE", 32, "EQUALVERIFY", "HASH256", hex.decode(HASH32), "EQUAL"],
    ],
    [
      "ripemd160",
      `ripemd160(${HASH20})`,
      ["SIZE", 32, "EQUALVERIFY", "RIPEMD160", hex.decode(HASH20), "EQUAL"],
    ],
    [
      "hash160",
      `hash160(${HASH20})`,
      ["SIZE", 32, "EQUALVERIFY", "HASH160", hex.decode(HASH20), "EQUAL"],
    ],
    [
      "andor",
      `andor(pk(${KEY_0}),pk(${KEY_1}),pk(${KEY_2}))`,
      [
        KEY_0_BYTES,
        "CHECKSIG",
        "NOTIF",
        KEY_2_BYTES,
        "CHECKSIG",
        "ELSE",
        KEY_1_BYTES,
        "CHECKSIG",
        "ENDIF",
      ],
    ],
    [
      "and_v",
      `and_v(v:pk(${KEY_0}),pk(${KEY_1}))`,
      [KEY_0_BYTES, "CHECKSIGVERIFY", KEY_1_BYTES, "CHECKSIG"],
    ],
    [
      "and_b",
      `and_b(pk(${KEY_0}),s:pk(${KEY_1}))`,
      [KEY_0_BYTES, "CHECKSIG", "SWAP", KEY_1_BYTES, "CHECKSIG", "BOOLAND"],
    ],
    [
      "and_n",
      `and_n(pk(${KEY_0}),pk(${KEY_1}))`,
      [KEY_0_BYTES, "CHECKSIG", "NOTIF", 0, "ELSE", KEY_1_BYTES, "CHECKSIG", "ENDIF"],
    ],
    [
      "or_b",
      `or_b(pk(${KEY_0}),s:pk(${KEY_1}))`,
      [KEY_0_BYTES, "CHECKSIG", "SWAP", KEY_1_BYTES, "CHECKSIG", "BOOLOR"],
    ],
    [
      "or_c",
      `t:or_c(pk(${KEY_0}),v:pk(${KEY_1}))`,
      [KEY_0_BYTES, "CHECKSIG", "NOTIF", KEY_1_BYTES, "CHECKSIGVERIFY", "ENDIF", 1],
    ],
    [
      "or_d",
      `or_d(pk(${KEY_0}),pk(${KEY_1}))`,
      [KEY_0_BYTES, "CHECKSIG", "IFDUP", "NOTIF", KEY_1_BYTES, "CHECKSIG", "ENDIF"],
    ],
    [
      "or_i",
      `or_i(pk(${KEY_0}),pk(${KEY_1}))`,
      ["IF", KEY_0_BYTES, "CHECKSIG", "ELSE", KEY_1_BYTES, "CHECKSIG", "ENDIF"],
    ],
    [
      "thresh",
      `thresh(2,pk(${KEY_0}),s:pk(${KEY_1}),s:pk(${KEY_2}))`,
      [
        KEY_0_BYTES,
        "CHECKSIG",
        "SWAP",
        KEY_1_BYTES,
        "CHECKSIG",
        "ADD",
        "SWAP",
        KEY_2_BYTES,
        "CHECKSIG",
        "ADD",
        2,
        "EQUAL",
      ],
    ],
    [
      "multi",
      `multi(2,${KEY_0},${KEY_1},${KEY_2})`,
      [2, KEY_0_BYTES, KEY_1_BYTES, KEY_2_BYTES, 3, "CHECKMULTISIG"],
    ],
    [
      "a wrapper",
      `and_b(pk(${KEY_1}),a:pk(${KEY_0}))`,
      [KEY_1_BYTES, "CHECKSIG", "TOALTSTACK", KEY_0_BYTES, "CHECKSIG", "FROMALTSTACK", "BOOLAND"],
    ],
    [
      "s wrapper",
      `and_b(pk(${KEY_1}),s:pk(${KEY_0}))`,
      [KEY_1_BYTES, "CHECKSIG", "SWAP", KEY_0_BYTES, "CHECKSIG", "BOOLAND"],
    ],
    ["c wrapper", `c:pk_k(${KEY_0})`, [KEY_0_BYTES, "CHECKSIG"]],
    ["t wrapper", `tv:pk(${KEY_0})`, [KEY_0_BYTES, "CHECKSIGVERIFY", 1]],
    ["d wrapper", "dv:after(10)", ["DUP", "IF", 10, "CHECKLOCKTIMEVERIFY", "VERIFY", "ENDIF"]],
    [
      "v wrapper",
      `and_v(v:after(10),pk(${KEY_0}))`,
      [10, "CHECKLOCKTIMEVERIFY", "VERIFY", KEY_0_BYTES, "CHECKSIG"],
    ],
    ["j wrapper", `j:pk(${KEY_0})`, ["SIZE", "0NOTEQUAL", "IF", KEY_0_BYTES, "CHECKSIG", "ENDIF"]],
    ["n wrapper", `n:pk(${KEY_0})`, [KEY_0_BYTES, "CHECKSIG", "0NOTEQUAL"]],
    ["l wrapper", `l:pk(${KEY_0})`, ["IF", 0, "ELSE", KEY_0_BYTES, "CHECKSIG", "ENDIF"]],
    ["u wrapper", `u:pk(${KEY_0})`, ["IF", KEY_0_BYTES, "CHECKSIG", "ELSE", 0, "ENDIF"]],
  ] satisfies Array<[string, string, ScriptOP[]]>)(
    "%s matches the BIP-0379 script",
    (_, miniscript, expectedOps) => {
      expect(witnessScriptHex(miniscript)).toBe(scriptHex(expectedOps));
    },
  );
});

describe("BIP-0379 miniscript validation constraints", () => {
  it("rejects fragments that are invalid as top-level miniscript descriptors", () => {
    for (const miniscript of [
      `pk_k(${KEY_0})`,
      `pk_h(${KEY_0})`,
      `a:pk(${KEY_0})`,
      `s:pk(${KEY_0})`,
      `t:pk(${KEY_0})`,
      `d:pk(${KEY_0})`,
      `v:pk(${KEY_0})`,
      `and_b(pk(${KEY_0}),pk(${KEY_1}))`,
      `or_b(pk(${KEY_0}),pk(${KEY_1}))`,
      `or_c(pk(${KEY_0}),v:pk(${KEY_1}))`,
      `thresh(2,pk(${KEY_0}),pk(${KEY_1}),pk(${KEY_2}))`,
    ]) {
      expect(isValidMiniscriptTemplate(miniscript, "NATIVE_SEGWIT")).toBe(false);
    }
  });

  it("enforces timelock and multi constraints", () => {
    const twentyOneKeys = Array.from({ length: 21 }, (_, index) => `key_${index}`);

    expect(isValidMiniscriptTemplate("older(0)", "NATIVE_SEGWIT")).toBe(false);
    expect(isValidMiniscriptTemplate("after(0)", "NATIVE_SEGWIT")).toBe(false);
    expect(isValidMiniscriptTemplate("older(2147483648)", "NATIVE_SEGWIT")).toBe(false);
    expect(isValidMiniscriptTemplate(`multi(1,${twentyOneKeys.join(",")})`, "NATIVE_SEGWIT")).toBe(
      false,
    );
  });

  it("matches BIP-0379 timelock mixing rules", () => {
    expect(isValidMiniscriptTemplate("and_v(v:after(1),after(500000000))", "NATIVE_SEGWIT")).toBe(
      false,
    );
    expect(
      isValidMiniscriptTemplate(`and_v(v:older(1),older(${RELATIVE_TIME_LOCK}))`, "NATIVE_SEGWIT"),
    ).toBe(false);
    expect(
      isValidMiniscriptTemplate(
        `or_i(and_v(v:pk(${KEY_0}),after(1)),and_v(v:pk(${KEY_1}),after(144)))`,
        "NATIVE_SEGWIT",
      ),
    ).toBe(true);
    expect(
      isValidMiniscriptTemplate(
        `andor(pk(${KEY_0}),and_v(v:pk(${KEY_1}),after(1)),and_v(v:pk(${KEY_2}),after(144)))`,
        "NATIVE_SEGWIT",
      ),
    ).toBe(true);
    expect(
      isValidMiniscriptTemplate(
        `and_v(v:after(500000000),and_v(v:older(${RELATIVE_TIME_LOCK}),pk(${KEY_0})))`,
        "NATIVE_SEGWIT",
      ),
    ).toBe(true);
  });

  it("keeps multi and multi_a in their BIP-0379 address contexts", () => {
    expect(isValidMiniscriptTemplate(`multi_a(2,${KEY_0},${KEY_1})`, "NATIVE_SEGWIT")).toBe(false);
    expect(isValidMiniscriptTemplate(`multi(2,${KEY_0},${KEY_1})`, "TAPROOT")).toBe(false);
    expect(isValidMiniscriptTemplate(`multi_a(2,${KEY_0},${KEY_1})`, "TAPROOT")).toBe(true);
  });
});
