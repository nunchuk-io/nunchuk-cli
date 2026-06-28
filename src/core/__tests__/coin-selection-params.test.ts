import { describe, expect, it } from "vitest";
import { CFeeRate, CHANGE_LOWER } from "../coin-selection.js";
import {
  CryptoRng,
  DEFAULT_DISCARD_FEERATE_SAT_PER_KVB,
  DEFAULT_LONG_TERM_FEERATE_SAT_PER_KVB,
  DUMMY_NESTED_P2WPKH_INPUT_SIZE,
  SeededRng,
  buildCoinSelectionParams,
  compactSizeBytes,
  computeTxNoinputsSize,
  getDustThreshold,
} from "../coin-selection-params.js";

// -- compactSize / tx_noinputs_size --

describe("compactSizeBytes", () => {
  it("uses 1 byte under 253", () => {
    expect(compactSizeBytes(0)).toBe(1);
    expect(compactSizeBytes(252)).toBe(1);
  });

  it("uses 3 bytes between 253 and 0xFFFF", () => {
    expect(compactSizeBytes(253)).toBe(3);
    expect(compactSizeBytes(0xffff)).toBe(3);
  });

  it("uses 5 bytes between 0x10000 and 0xFFFFFFFF", () => {
    expect(compactSizeBytes(0x10000)).toBe(5);
  });
});

describe("computeTxNoinputsSize", () => {
  it("matches Core's outpoint-free serialization for a single P2WPKH recipient", () => {
    // P2WPKH scriptPubKey = OP_0 OP_PUSHBYTES_20 <20 bytes> = 22 bytes
    // Per-output = 8 (value) + 1 (compactSize for 22) + 22 = 31
    // Header = 10 + 1 (compactSize for 1 output) = 11
    // Total = 11 + 31 = 42
    expect(computeTxNoinputsSize([22])).toBe(42);
  });

  it("adds per-recipient overhead correctly for multiple outputs", () => {
    // Two P2WSH recipients (script len 34 each)
    // Per-output = 8 + 1 + 34 = 43
    // Header = 10 + 1 = 11
    // Total = 11 + 2 * 43 = 97
    expect(computeTxNoinputsSize([34, 34])).toBe(97);
  });
});

// -- getDustThreshold --

describe("getDustThreshold", () => {
  it("matches Bitcoin Core for a witness output (P2WPKH at 3000 sat/kvB)", () => {
    // P2WPKH: serialized output size = 8 + 1 + 22 = 31
    // Witness overhead = 32 + 4 + 1 + floor(107/4) + 4 = 67
    // nSize = 31 + 67 = 98 → dust = 3000 * 98 / 1000 = 294 sat
    expect(getDustThreshold(31, true, new CFeeRate(3_000n))).toBe(294n);
  });

  it("matches Bitcoin Core for a witness output (P2WSH)", () => {
    // P2WSH: serialized output size = 8 + 1 + 34 = 43
    // Witness overhead = 67
    // nSize = 43 + 67 = 110 → dust = 3000 * 110 / 1000 = 330 sat
    expect(getDustThreshold(43, true, new CFeeRate(3_000n))).toBe(330n);
  });

  it("uses larger non-witness overhead when isWitness is false", () => {
    // P2PKH: serialized = 8 + 1 + 25 = 34
    // Non-witness overhead = 32 + 4 + 1 + 107 + 4 = 148
    // nSize = 34 + 148 = 182 → dust = 3000 * 182 / 1000 = 546 sat
    expect(getDustThreshold(34, false, new CFeeRate(3_000n))).toBe(546n);
  });
});

// -- buildCoinSelectionParams --

describe("buildCoinSelectionParams", () => {
  const baseArgs = () => ({
    feeRate: 5n, // sat/vB → 5000 sat/kvB
    changeOutputSize: 43, // P2WSH change
    changeOutputDust: 330n,
    txNoinputsSize: 42,
    paymentValue: 200_000n,
    rng: new SeededRng(7),
  });

  it("pins libnunchuk's feerates by default", () => {
    const p = buildCoinSelectionParams(baseArgs());
    expect(p.effectiveFeerate.satPerKvB).toBe(5_000n);
    expect(p.longTermFeerate.satPerKvB).toBe(DEFAULT_LONG_TERM_FEERATE_SAT_PER_KVB);
    expect(p.discardFeerate.satPerKvB).toBe(DEFAULT_DISCARD_FEERATE_SAT_PER_KVB);
  });

  it("uses DUMMY_NESTED_P2WPKH_INPUT_SIZE for change_spend_size by default", () => {
    const p = buildCoinSelectionParams(baseArgs());
    expect(p.changeSpendSize).toBe(DUMMY_NESTED_P2WPKH_INPUT_SIZE);
  });

  it("computes change_fee, cost_of_change, and min_viable_change per spender.cpp", () => {
    const p = buildCoinSelectionParams(baseArgs());
    // change_fee   = 5000 sat/kvB × 43 / 1000 = 215
    // change_spend = 3000 sat/kvB × 91 / 1000 = 273
    // cost_of_chg  = 273 + 215 = 488
    // dust         = 330
    // min_viable   = max(273 + 1, 330) = 330
    expect(p.changeFee).toBe(215n);
    expect(p.costOfChange).toBe(488n);
    expect(p.minViableChange).toBe(330n);
  });

  it("uses change_spend_fee + 1 when it exceeds the dust threshold", () => {
    const p = buildCoinSelectionParams({
      ...baseArgs(),
      changeOutputDust: 100n, // below change_spend_fee + 1 = 274
    });
    expect(p.minViableChange).toBe(274n);
  });

  it("min_change_target is randomized via the provided RNG", () => {
    const a = buildCoinSelectionParams({ ...baseArgs(), rng: new SeededRng(1) });
    const b = buildCoinSelectionParams({ ...baseArgs(), rng: new SeededRng(2) });
    expect(a.minChangeTarget).not.toBe(b.minChangeTarget);
    // Bounded below by change_fee + CHANGE_LOWER
    expect(a.minChangeTarget).toBeGreaterThanOrEqual(a.changeFee + CHANGE_LOWER);
  });

  it("min_change_target is fixed (change_fee + CHANGE_LOWER) for tiny payments", () => {
    const p = buildCoinSelectionParams({
      ...baseArgs(),
      paymentValue: CHANGE_LOWER / 2n,
    });
    expect(p.minChangeTarget).toBe(p.changeFee + CHANGE_LOWER);
  });

  it("flips selection-relevant defaults: avoidPartialSpends=false, includeUnsafeInputs=true", () => {
    const p = buildCoinSelectionParams(baseArgs());
    expect(p.avoidPartialSpends).toBe(false);
    expect(p.includeUnsafeInputs).toBe(true);
    expect(p.subtractFeeOutputs).toBe(false);
  });

  it("threads subtractFeeOutputs through when set", () => {
    const p = buildCoinSelectionParams({ ...baseArgs(), subtractFeeOutputs: true });
    expect(p.subtractFeeOutputs).toBe(true);
  });
});

// -- RNG implementations --

describe("SeededRng", () => {
  it("produces the same stream for the same seed", () => {
    const a = new SeededRng(42);
    const b = new SeededRng(42);
    for (let i = 0; i < 100; i++) {
      expect(a.randrange(1000n)).toBe(b.randrange(1000n));
    }
  });

  it("randrange returns values in [0, n)", () => {
    const r = new SeededRng(7);
    for (let i = 0; i < 1000; i++) {
      const v = r.randrange(13n);
      expect(v).toBeGreaterThanOrEqual(0n);
      expect(v).toBeLessThan(13n);
    }
  });

  it("shuffle is deterministic for a given seed", () => {
    const a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const b = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    new SeededRng(99).shuffle(a);
    new SeededRng(99).shuffle(b);
    expect(a).toEqual(b);
  });

  it("randbool returns both true and false over many calls", () => {
    const r = new SeededRng(1);
    const counts = { true: 0, false: 0 };
    for (let i = 0; i < 1000; i++) counts[r.randbool() ? "true" : "false"]++;
    expect(counts.true).toBeGreaterThan(100);
    expect(counts.false).toBeGreaterThan(100);
  });
});

describe("CryptoRng", () => {
  it("randrange returns values in [0, n)", () => {
    const r = new CryptoRng();
    for (let i = 0; i < 100; i++) {
      const v = r.randrange(17n);
      expect(v).toBeGreaterThanOrEqual(0n);
      expect(v).toBeLessThan(17n);
    }
  });

  it("randrange handles bigint ranges larger than 2^32", () => {
    const r = new CryptoRng();
    const big = 1n << 40n;
    const v = r.randrange(big);
    expect(v).toBeGreaterThanOrEqual(0n);
    expect(v).toBeLessThan(big);
  });

  it("shuffle preserves all elements", () => {
    const arr = [1, 2, 3, 4, 5];
    new CryptoRng().shuffle(arr);
    expect(arr.sort()).toEqual([1, 2, 3, 4, 5]);
  });
});
