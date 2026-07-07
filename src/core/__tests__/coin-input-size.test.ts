import { describe, expect, it } from "vitest";
import {
  buildMiniscriptDummyWitness,
  estimateMiniscriptInputVBytes,
  estimateMultisigInputVBytes,
  estimateTaprootKeyPathInputVBytes,
  getChangeOutputSize,
  getChangeScriptLen,
  isWalletWitnessOutput,
} from "../coin-input-size.js";
import { CFeeRate } from "../coin-selection.js";
import { getDustThreshold } from "../coin-selection-params.js";
import { buildWalletDescriptor } from "../descriptor.js";
import { buildMiniscriptDescriptor } from "../miniscript.js";
import { getMiniscriptSpendingPlans } from "../miniscript-spend.js";
import { parseDescriptor } from "../descriptor.js";
import type { WalletData } from "../storage.js";

const SIGNERS = [
  "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
];

const MULTISIG_P2WSH: WalletData = {
  walletId: "ms-wsh",
  groupId: "g1",
  gid: "gid1",
  name: "Multisig P2WSH",
  m: 2,
  n: 2,
  addressType: "NATIVE_SEGWIT",
  descriptor: buildWalletDescriptor(SIGNERS, 2, "NATIVE_SEGWIT"),
  signers: SIGNERS,
  secretboxKey: "",
  createdAt: "2025-01-01T00:00:00.000Z",
};

const MINISCRIPT_DESCRIPTOR = buildMiniscriptDescriptor(
  `and_v(v:pk(${SIGNERS[0]}/<0;1>/*),pk(${SIGNERS[1]}/<0;1>/*))`,
  "NATIVE_SEGWIT",
);

const MINISCRIPT_WALLET: WalletData = {
  ...MULTISIG_P2WSH,
  walletId: "ms-script",
  m: 0,
  descriptor: MINISCRIPT_DESCRIPTOR,
};

describe("estimateMultisigInputVBytes", () => {
  it("matches the Bitcoin Core formula for 2-of-3 P2WSH", () => {
    // witness: count(1) + empty(1) + 2 sigs(146) + script(106) = 254
    // non-witness: 32 + 4 + 1 + 0 + 4 = 41
    // weight = 41*4 + 254 = 418 → vbytes = ceil(418/4) = 105
    expect(estimateMultisigInputVBytes(2, 3, "NATIVE_SEGWIT")).toBe(105);
  });

  it("matches the Bitcoin Core formula for 2-of-3 P2SH-P2WSH (nested)", () => {
    // witness: same as P2WSH = 254
    // non-witness: 32 + 4 + compactSize(35) + 35 + 4 = 32 + 4 + 1 + 35 + 4 = 76
    // weight = 76*4 + 254 = 558 → vbytes = ceil(558/4) = 140
    expect(estimateMultisigInputVBytes(2, 3, "NESTED_SEGWIT")).toBe(140);
  });

  it("matches the Bitcoin Core formula for 2-of-3 P2SH (LEGACY)", () => {
    // scriptSig = 1 (OP_0) + 2*73 (sigs) + 2 + 105 (PUSHDATA1 + redeemScript) = 254
    // non-witness: 32 + 4 + compactSize(254)=3 + 254 + 4 = 297
    // weight = 297*4 = 1188 → vbytes = 297
    expect(estimateMultisigInputVBytes(2, 3, "LEGACY")).toBe(297);
  });

  it("throws for unsupported address types", () => {
    expect(() => estimateMultisigInputVBytes(2, 3, "TAPROOT")).toThrow(/Unsupported/);
  });
});

describe("estimateMiniscriptInputVBytes", () => {
  it("returns a positive vbytes for a 2-key and_v miniscript wallet", () => {
    const parsed = parseDescriptor(MINISCRIPT_WALLET.descriptor);
    const plans = getMiniscriptSpendingPlans(parsed.miniscript!).filter((p) => p.supported);
    expect(plans.length).toBeGreaterThan(0);
    const v = estimateMiniscriptInputVBytes(MINISCRIPT_WALLET, "testnet", plans[0]);
    // Sanity: should be in the same ballpark as a 2-of-2 P2WSH multisig (~ 100 vbytes).
    expect(v).toBeGreaterThan(60);
    expect(v).toBeLessThan(200);
  });
});

describe("estimateTaprootKeyPathInputVBytes", () => {
  it("sizes a single 64-byte Schnorr key-path spend at 58 vbytes", () => {
    // non-witness 41 * 4 + witness (1 + 1 + 64) = 164 + 66 = 230 → ceil(230/4) = 58
    expect(estimateTaprootKeyPathInputVBytes()).toBe(58);
  });
});

describe("buildMiniscriptDummyWitness", () => {
  it("pushes one 72-byte signature placeholder per required signature (v0)", () => {
    const parsed = parseDescriptor(MINISCRIPT_WALLET.descriptor);
    const plans = getMiniscriptSpendingPlans(parsed.miniscript!).filter((p) => p.supported);
    const plan = plans[0];
    const witnessScript = new Uint8Array([0xab, 0xcd]); // doesn't matter for size
    const stack = buildMiniscriptDummyWitness(plan, witnessScript);
    const sigCount = stack.filter((item) => item.length === 72).length;
    expect(sigCount).toBe(plan.requiredSignatures);
    // last item is always the witness script
    expect(stack[stack.length - 1]).toBe(witnessScript);
  });

  it("uses 64-byte Schnorr sigs and appends the control block for taproot script-path", () => {
    const parsed = parseDescriptor(MINISCRIPT_WALLET.descriptor);
    const plan = getMiniscriptSpendingPlans(parsed.miniscript!).filter((p) => p.supported)[0];
    const leafScript = new Uint8Array([0xab, 0xcd]);
    const controlBlock = new Uint8Array(33); // minimal control block (parity+x-only)
    const stack = buildMiniscriptDummyWitness(plan, leafScript, controlBlock);
    expect(stack.filter((item) => item.length === 64).length).toBe(plan.requiredSignatures);
    expect(stack.filter((item) => item.length === 72).length).toBe(0);
    // control block is last, leaf script second-to-last
    expect(stack[stack.length - 1]).toBe(controlBlock);
    expect(stack[stack.length - 2]).toBe(leafScript);
  });
});

describe("change output helpers", () => {
  it("isWalletWitnessOutput is true for NATIVE_SEGWIT and TAPROOT", () => {
    expect(isWalletWitnessOutput("NATIVE_SEGWIT")).toBe(true);
    expect(isWalletWitnessOutput("TAPROOT")).toBe(true);
    expect(isWalletWitnessOutput("NESTED_SEGWIT")).toBe(false);
    expect(isWalletWitnessOutput("LEGACY")).toBe(false);
  });

  it("getChangeOutputSize encodes value(8) + compactSize(scriptLen) + scriptLen", () => {
    expect(getChangeOutputSize(34)).toBe(43); // P2WSH
    expect(getChangeOutputSize(22)).toBe(31); // P2WPKH
    expect(getChangeOutputSize(23)).toBe(32); // P2SH
  });

  it("getChangeScriptLen returns 34 for a P2WSH multisig wallet", () => {
    const len = getChangeScriptLen(MULTISIG_P2WSH, "testnet", 0);
    // P2WSH scriptPubKey: OP_0 (0x00) + OP_PUSHBYTES_32 (0x20) + <32 bytes> = 34 bytes
    expect(len).toBe(34);
  });

  it("dust threshold for a P2WSH change at 3000 sat/kvB matches Core (330 sat)", () => {
    const len = getChangeScriptLen(MULTISIG_P2WSH, "testnet", 0);
    const dust = getDustThreshold(
      getChangeOutputSize(len),
      isWalletWitnessOutput("NATIVE_SEGWIT"),
      new CFeeRate(3_000n),
    );
    expect(dust).toBe(330n);
  });
});
