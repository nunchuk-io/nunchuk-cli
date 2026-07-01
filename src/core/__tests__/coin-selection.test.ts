import { describe, expect, it } from "vitest";
import {
  CFeeRate,
  CHANGE_LOWER,
  CHANGE_UPPER,
  MAX_STANDARD_TX_WEIGHT,
  SelectionAlgorithm,
  SelectionResult,
  WITNESS_SCALE_FACTOR,
  approximateBestSubset,
  attemptSelection,
  automaticCoinSelection,
  chooseSelectionResult,
  eligibleForSpending,
  generateChangeTarget,
  getSelectionAmount,
  groupOutputs,
  insertIntoGroup,
  knapsackSolver,
  makeCOutput,
  makeOutputGroup,
  selectCoins,
  selectCoinsBnB,
  selectCoinsSRD,
  type CoinInput,
  type CoinSelectionParams,
  type Groups,
  type SelectionRng,
} from "../coin-selection.js";
import { SeededRng } from "../coin-selection-params.js";

// -- Test helpers --

function coin(opts: {
  txid?: string;
  vout?: number;
  value: bigint;
  inputVBytes?: number;
  height?: number;
  isChange?: boolean;
}): CoinInput {
  return {
    txid: opts.txid ?? `tx${opts.value}`,
    vout: opts.vout ?? 0,
    value: opts.value,
    inputVBytes: opts.inputVBytes ?? 100,
    height: opts.height ?? 100,
    isChange: opts.isChange ?? false,
  };
}

// Builds a COutput from a CoinInput at the given feerates.
function out(
  c: CoinInput,
  args: {
    effectiveFeerate?: CFeeRate;
    longTermFeerate?: CFeeRate;
    currentHeight?: number;
  } = {},
) {
  return makeCOutput(c, {
    effectiveFeerate: args.effectiveFeerate ?? new CFeeRate(0n),
    longTermFeerate: args.longTermFeerate ?? new CFeeRate(0n),
    currentHeight: args.currentHeight ?? 200,
  });
}

// A single-coin OutputGroup with explicit selection amount + fees (skips
// effective-value math when we want to drive the algorithms directly).
function group(opts: {
  value: bigint;
  fee?: bigint;
  longTermFee?: bigint;
  effectiveValue?: bigint;
  weight?: number;
  depth?: number;
  subtractFeeOutputs?: boolean;
  txid?: string;
  vout?: number;
}) {
  const g = makeOutputGroup(opts.subtractFeeOutputs ?? false);
  const c: CoinInput = {
    txid: opts.txid ?? `tx${opts.value}`,
    vout: opts.vout ?? 0,
    value: opts.value,
    inputVBytes: opts.weight ? Math.floor(opts.weight / WITNESS_SCALE_FACTOR) : 0,
    height: 100,
    isChange: false,
  };
  const co = {
    coin: c,
    depth: opts.depth ?? 6,
    fee: opts.fee ?? 0n,
    longTermFee: opts.longTermFee ?? 0n,
    effectiveValue: opts.effectiveValue ?? opts.value - (opts.fee ?? 0n),
    ancestorBumpFees: 0n,
    weight: opts.weight ?? 0,
  };
  insertIntoGroup(g, co, 0, 0);
  return g;
}

// Stable RNG that mostly returns false/0; useful when we don't want
// ApproximateBestSubset to wander.
const STABLE_RNG: SelectionRng = {
  randbool: () => false,
  randrange: () => 0n,
  shuffle: () => undefined,
};

// -- CFeeRate --

describe("CFeeRate.getFee", () => {
  it("truncates feerate × vbytes / 1000", () => {
    expect(new CFeeRate(1_000n).getFee(141)).toBe(141n); // exact
    expect(new CFeeRate(2_500n).getFee(150)).toBe(375n);
    expect(new CFeeRate(3_001n).getFee(33)).toBe(99n); // (3001*33)/1000 = 99033/1000 = 99
  });

  it("bumps to 1 sat when positive feerate would truncate to 0", () => {
    // Bitcoin Core policy/feerate.cpp: if nFee == 0 && size != 0 && rate > 0 → 1.
    expect(new CFeeRate(1n).getFee(1)).toBe(1n); // 1 / 1000 = 0 → 1
    expect(new CFeeRate(999n).getFee(1)).toBe(1n);
  });

  it("returns 0 when feerate or size is 0", () => {
    expect(new CFeeRate(0n).getFee(141)).toBe(0n);
    expect(new CFeeRate(1_000n).getFee(0)).toBe(0n);
    expect(new CFeeRate(1_000n).getFee(-1)).toBe(0n);
  });
});

// -- generateChangeTarget --

describe("generateChangeTarget", () => {
  it("returns change_fee + CHANGE_LOWER for tiny payments", () => {
    const result = generateChangeTarget(CHANGE_LOWER / 2n, 100n, STABLE_RNG);
    expect(result).toBe(100n + CHANGE_LOWER);
  });

  it("randomizes within [CHANGE_LOWER, min(2 * payment, CHANGE_UPPER)) + change_fee", () => {
    const rng = new SeededRng(42);
    const payment = 200_000n; // 2× = 400k < CHANGE_UPPER (1M)
    const result = generateChangeTarget(payment, 100n, rng);
    const upper = payment * 2n;
    expect(result).toBeGreaterThanOrEqual(100n + CHANGE_LOWER);
    expect(result).toBeLessThan(100n + upper);
  });

  it("caps upper bound at CHANGE_UPPER for large payments", () => {
    const rng = new SeededRng(1);
    const result = generateChangeTarget(10_000_000n, 0n, rng);
    expect(result).toBeGreaterThanOrEqual(CHANGE_LOWER);
    expect(result).toBeLessThan(CHANGE_UPPER);
  });
});

// -- BnB --

describe("selectCoinsBnB", () => {
  it("finds an exact match within cost-of-change window", () => {
    // pool 10/5/3, target 8, cost_of_change 1 → matches {5,3}=8
    const pool = [
      group({ value: 10n, txid: "a" }),
      group({ value: 5n, txid: "b" }),
      group({ value: 3n, txid: "c" }),
    ];
    const res = selectCoinsBnB(pool, 8n, 1n, MAX_STANDARD_TX_WEIGHT);
    expect("result" in res).toBe(true);
    if ("result" in res) {
      const txids = res.result.inputs.map((i) => i.coin.txid).sort();
      expect(txids).toEqual(["b", "c"]);
    }
  });

  it("returns no_solution when total < target", () => {
    const pool = [group({ value: 5n }), group({ value: 3n })];
    const res = selectCoinsBnB(pool, 100n, 0n, MAX_STANDARD_TX_WEIGHT);
    expect("error" in res && res.error).toBe("no_solution");
  });

  it("returns no_solution when no exact match exists in the window", () => {
    // pool 7/4, target 8, cost_of_change 1 → window [8, 9]; subsets: 7 (too low),
    // 4 (too low), 11 (too high), 7+4=11 (too high). No solution.
    const pool = [group({ value: 7n }), group({ value: 4n })];
    const res = selectCoinsBnB(pool, 8n, 1n, MAX_STANDARD_TX_WEIGHT);
    expect("error" in res && res.error).toBe("no_solution");
  });

  it("skips selection-amount duplicates to avoid equivalent branches", () => {
    // {5, 5, 3}: BnB still finds {5,3} (or one of the two 5s), without
    // enumerating both duplicate branches.
    const pool = [
      group({ value: 5n, txid: "a" }),
      group({ value: 5n, txid: "b" }),
      group({ value: 3n, txid: "c" }),
    ];
    const res = selectCoinsBnB(pool, 8n, 1n, MAX_STANDARD_TX_WEIGHT);
    expect("result" in res).toBe(true);
    if ("result" in res) {
      expect(res.result.inputs.length).toBe(2);
      const total = res.result.inputs.reduce((s, i) => s + i.coin.value, 0n);
      expect(total).toBe(8n);
    }
  });

  it("returns max_weight when only candidates blow the weight cap", () => {
    const pool = [group({ value: 100n, weight: 1_000_000 })];
    const res = selectCoinsBnB(pool, 100n, 0n, 4_000);
    expect("error" in res && res.error).toBe("max_weight");
  });

  it("reports waste of 0 when the selection is an exact match (no excess, no timing cost)", () => {
    const pool = [group({ value: 10n }), group({ value: 5n }), group({ value: 3n })];
    const res = selectCoinsBnB(pool, 8n, 1n, MAX_STANDARD_TX_WEIGHT);
    expect("result" in res).toBe(true);
    if ("result" in res) expect(res.result.getWaste()).toBe(0n);
  });
});

// -- Knapsack --

describe("knapsackSolver", () => {
  it("returns immediately on an exact single-group match", () => {
    const pool = [
      group({ value: 10n, txid: "a" }),
      group({ value: 8n, txid: "b" }),
      group({ value: 3n, txid: "c" }),
    ];
    const res = knapsackSolver(pool, 8n, 100n, new SeededRng(1), MAX_STANDARD_TX_WEIGHT);
    expect("result" in res).toBe(true);
    if ("result" in res) {
      expect(res.result.inputs.length).toBe(1);
      expect(res.result.inputs[0].coin.value).toBe(8n);
    }
  });

  it("uses lowest_larger when applicable sum < target", () => {
    // target = 8, change_target = 0; applicable groups (< 8) sum to 1+2 = 3 < 8.
    // lowest_larger = 10. Returns just {10}.
    const pool = [
      group({ value: 10n, txid: "big" }),
      group({ value: 1n, txid: "a" }),
      group({ value: 2n, txid: "b" }),
    ];
    const res = knapsackSolver(pool, 8n, 0n, new SeededRng(7), MAX_STANDARD_TX_WEIGHT);
    expect("result" in res).toBe(true);
    if ("result" in res) {
      expect(res.result.inputs.length).toBe(1);
      expect(res.result.inputs[0].coin.txid).toBe("big");
    }
  });

  it("returns the exact subset when applicable groups sum exactly to target", () => {
    // target = 8, applicable {5,3} sum exactly to 8 → returns both.
    const pool = [group({ value: 5n, txid: "a" }), group({ value: 3n, txid: "b" })];
    const res = knapsackSolver(pool, 8n, 100n, new SeededRng(1), MAX_STANDARD_TX_WEIGHT);
    expect("result" in res).toBe(true);
    if ("result" in res) {
      expect(res.result.inputs.length).toBe(2);
      const sum = res.result.inputs.reduce((s, i) => s + i.coin.value, 0n);
      expect(sum).toBe(8n);
    }
  });

  it("falls back to stochastic best-subset when no exact match is available", () => {
    // target = 7, change_target = 1, pool {5,3,2}: applicable {5,3,2} sum 10.
    // Stochastic should find {5,3}=8 or {5,2}=7 (best). Seeded for determinism.
    const pool = [
      group({ value: 5n, txid: "a" }),
      group({ value: 3n, txid: "b" }),
      group({ value: 2n, txid: "c" }),
    ];
    const res = knapsackSolver(pool, 7n, 1n, new SeededRng(123), MAX_STANDARD_TX_WEIGHT);
    expect("result" in res).toBe(true);
    if ("result" in res) {
      const sum = res.result.inputs.reduce((s, i) => s + i.coin.value, 0n);
      expect(sum).toBeGreaterThanOrEqual(7n);
    }
  });

  it("returns no_solution with no lowest_larger and no applicable subset", () => {
    const pool = [group({ value: 1n }), group({ value: 2n })];
    const res = knapsackSolver(pool, 100n, 1n, new SeededRng(1), MAX_STANDARD_TX_WEIGHT);
    expect("error" in res && res.error).toBe("no_solution");
  });
});

describe("approximateBestSubset", () => {
  it("converges on an exact match when one exists", () => {
    // Sorted descending by amount; an exact {5,3} = 8 exists.
    const groups = [group({ value: 5n }), group({ value: 3n }), group({ value: 2n })];
    const { vfBest, nBest } = approximateBestSubset(
      new SeededRng(1),
      groups,
      10n,
      8n,
      MAX_STANDARD_TX_WEIGHT,
    );
    expect(nBest).toBe(8n);
    const selected = groups.filter((_, i) => vfBest[i]);
    const sum = selected.reduce((s, g) => s + g.value, 0n);
    expect(sum).toBe(8n);
  });
});

// -- SRD --

describe("selectCoinsSRD", () => {
  it("hits target deterministically with a seeded RNG", () => {
    const pool = [
      group({ value: 200_000n, txid: "a" }),
      group({ value: 150_000n, txid: "b" }),
      group({ value: 100_000n, txid: "c" }),
    ];
    // target 100k + CHANGE_LOWER (50k) + change_fee (0) = 150k.
    const res = selectCoinsSRD(pool, 100_000n, 0n, new SeededRng(1), MAX_STANDARD_TX_WEIGHT);
    expect("result" in res).toBe(true);
    if ("result" in res) {
      const sum = res.result.inputs.reduce((s, i) => s + i.coin.value, 0n);
      expect(sum).toBeGreaterThanOrEqual(150_000n);
    }
  });

  it("returns no_solution when the entire pool can't reach target + CHANGE_LOWER", () => {
    const pool = [group({ value: 10_000n }), group({ value: 5_000n })];
    const res = selectCoinsSRD(pool, 100_000n, 0n, new SeededRng(1), MAX_STANDARD_TX_WEIGHT);
    expect("error" in res && res.error).toBe("no_solution");
  });
});

// -- SelectionResult --

describe("SelectionResult.recalculateWaste", () => {
  it("with change: waste = timing_cost + change_cost", () => {
    const r = new SelectionResult(100n, SelectionAlgorithm.KNAPSACK);
    r.addInput(group({ value: 200n, fee: 10n, longTermFee: 4n, effectiveValue: 190n }));
    // change = effective(190) - target(100) - change_fee(5) = 85 ≥ min_viable(10) → change exists
    r.recalculateWaste(/* min_viable */ 10n, /* change_cost */ 7n, /* change_fee */ 5n);
    // timing_cost = 10 - 4 = 6; waste = 6 + change_cost(7) = 13
    expect(r.getWaste()).toBe(13n);
  });

  it("without change: waste = timing_cost + (selected_effective - target)", () => {
    const r = new SelectionResult(100n, SelectionAlgorithm.BNB);
    r.addInput(group({ value: 105n, fee: 2n, longTermFee: 1n, effectiveValue: 103n }));
    // change = 103 - 100 - 0 = 3; min_viable = 5 → change == 0 → no-change branch
    r.recalculateWaste(/* min_viable */ 5n, /* change_cost */ 100n, /* change_fee */ 0n);
    // timing_cost = 1; excess = 103 - 100 = 3; waste = 4
    expect(r.getWaste()).toBe(4n);
  });

  it("tie-break: same waste prefers more inputs", () => {
    const r1 = new SelectionResult(10n, SelectionAlgorithm.KNAPSACK);
    r1.addInput(group({ value: 20n, fee: 1n, longTermFee: 0n, effectiveValue: 19n }));
    r1.recalculateWaste(0n, 0n, 0n); // waste = 1 + (19-10) = 10

    const r2 = new SelectionResult(10n, SelectionAlgorithm.KNAPSACK);
    r2.addInput(group({ value: 15n, fee: 0n, longTermFee: 0n, effectiveValue: 15n, txid: "x" }));
    r2.addInput(group({ value: 5n, fee: 0n, longTermFee: 0n, effectiveValue: 5n, txid: "y" }));
    r2.recalculateWaste(0n, 0n, 0n); // waste = 0 + (20-10) = 10

    // Both waste 10 → r2 wins (more inputs).
    expect(r1.compare(r2)).toBeGreaterThan(0);
    expect(r2.compare(r1)).toBeLessThan(0);
  });
});

// -- SFFA toggle --

describe("subtractFeeOutputs (SFFA) toggle", () => {
  it("getSelectionAmount switches face/effective per group flag", () => {
    const nonSffa = group({
      value: 100n,
      fee: 5n,
      effectiveValue: 95n,
      subtractFeeOutputs: false,
    });
    expect(getSelectionAmount(nonSffa)).toBe(95n);

    const sffa = group({
      value: 100n,
      fee: 5n,
      effectiveValue: 95n,
      subtractFeeOutputs: true,
    });
    expect(getSelectionAmount(sffa)).toBe(100n);
  });

  it("SelectionResult.getChange uses face value (no change_fee) when SFFA is on", () => {
    const r = new SelectionResult(100n, SelectionAlgorithm.BNB);
    r.addInput(
      group({
        value: 110n,
        fee: 3n,
        effectiveValue: 107n,
        subtractFeeOutputs: true,
      }),
    );
    // useEffective = false → change = 110 - 100 = 10 (no change_fee subtraction)
    expect(r.getChange(/* min_viable */ 5n, /* change_fee */ 999n)).toBe(10n);
  });

  it("SelectionResult.getChange uses effective value minus change_fee when SFFA is off", () => {
    const r = new SelectionResult(100n, SelectionAlgorithm.BNB);
    r.addInput(group({ value: 110n, fee: 3n, effectiveValue: 107n }));
    // useEffective = true → change = 107 - 100 - 4 = 3
    expect(r.getChange(/* min_viable */ 0n, /* change_fee */ 4n)).toBe(3n);
  });
});

// -- Eligibility --

describe("eligibleForSpending", () => {
  it("from-me coins use confMine threshold", () => {
    const g = group({ value: 100n, depth: 3 });
    expect(eligibleForSpending(g, mkFilter({ confMine: 1 }))).toBe(true);
    expect(eligibleForSpending(g, mkFilter({ confMine: 6 }))).toBe(false);
  });

  it("from-other coins use confTheirs threshold", () => {
    const g = group({ value: 100n, depth: 3 });
    g.fromMe = false;
    expect(eligibleForSpending(g, mkFilter({ confTheirs: 1 }))).toBe(true);
    expect(eligibleForSpending(g, mkFilter({ confTheirs: 6 }))).toBe(false);
  });
});

function mkFilter(
  overrides: Partial<{
    confMine: number;
    confTheirs: number;
    maxAncestors: number;
    maxDescendants: number;
    includePartialGroups: boolean;
  }>,
) {
  return {
    confMine: 1,
    confTheirs: 6,
    maxAncestors: 0,
    maxDescendants: 0,
    includePartialGroups: false,
    ...overrides,
  };
}

// -- Group outputs --

describe("groupOutputs (avoidPartialSpends = false)", () => {
  it("creates one OutputGroup per COutput and distributes by filter", () => {
    const c1 = out(coin({ value: 100n, txid: "a", height: 100 }), {
      currentHeight: 200,
    });
    const c2 = out(coin({ value: 200n, txid: "b", height: 198 }), {
      currentHeight: 200,
    });
    const params = mkParams();
    const result = groupOutputs([c1, c2], params, [
      { filter: mkFilter({ confMine: 100 }) },
      { filter: mkFilter({ confMine: 1 }) },
    ]);

    // Filter 0 (≥100 confs) accepts only c1 (101 confs); c2 (3 confs) is rejected.
    // Filter 1 (≥1 conf) accepts both.
    // Each coin becomes its own group.
    expect(result.byFilter.size).toBe(2);
    expect(result.discarded.length).toBe(0);
  });

  it("throws if avoidPartialSpends is true (not implemented)", () => {
    const params = mkParams({ avoidPartialSpends: true });
    expect(() => groupOutputs([], params, [])).toThrowError();
  });
});

function mkParams(overrides: Partial<CoinSelectionParams> = {}): CoinSelectionParams {
  return {
    rng: new SeededRng(1),
    changeOutputSize: 43,
    changeSpendSize: 91,
    minChangeTarget: 50_000n,
    minViableChange: 294n,
    changeFee: 100n,
    costOfChange: 373n,
    effectiveFeerate: new CFeeRate(1_000n),
    longTermFeerate: new CFeeRate(10_000n),
    discardFeerate: new CFeeRate(3_000n),
    txNoinputsSize: 50,
    subtractFeeOutputs: false,
    avoidPartialSpends: false,
    includeUnsafeInputs: true,
    ...overrides,
  };
}

// -- End-to-end (attemptSelection + automaticCoinSelection + selectCoins) --

describe("attemptSelection + automaticCoinSelection", () => {
  it("returns insufficient_funds when totals don't cover target", () => {
    const coins = [out(coin({ value: 100n })), out(coin({ value: 50n }))];
    const params = mkParams();
    const res = selectCoins(coins, 1_000_000n, params);
    expect("error" in res && res.error).toBe("insufficient_funds");
  });

  it("picks a working subset for a realistic input", () => {
    // Three confirmed positive-effective coins, target well within reach.
    const coins = [
      out(coin({ value: 500_000n, height: 100, txid: "a" }), {
        effectiveFeerate: new CFeeRate(1_000n),
        longTermFeerate: new CFeeRate(10_000n),
        currentHeight: 200,
      }),
      out(coin({ value: 300_000n, height: 100, txid: "b" }), {
        effectiveFeerate: new CFeeRate(1_000n),
        longTermFeerate: new CFeeRate(10_000n),
        currentHeight: 200,
      }),
      out(coin({ value: 200_000n, height: 100, txid: "c" }), {
        effectiveFeerate: new CFeeRate(1_000n),
        longTermFeerate: new CFeeRate(10_000n),
        currentHeight: 200,
      }),
    ];
    const params = mkParams();
    const res = selectCoins(coins, 250_000n, params);
    expect("result" in res).toBe(true);
    if ("result" in res) {
      expect(res.result.inputs.length).toBeGreaterThan(0);
      expect(Object.values(SelectionAlgorithm)).toContain(res.result.algo);
    }
  });

  it("respects the libnunchuk filter ladder (rejects unconfirmed at the strict filter)", () => {
    // Single unconfirmed coin → rejected by (1,6,0) and (1,1,0); accepted by
    // (0,1,...) levels. Should still succeed via Knapsack/SRD.
    const coins = [
      out(coin({ value: 500_000n, height: 0 }), {
        effectiveFeerate: new CFeeRate(1_000n),
        longTermFeerate: new CFeeRate(10_000n),
        currentHeight: 200,
      }),
    ];
    const params = mkParams();
    const res = selectCoins(coins, 250_000n, params);
    expect("result" in res).toBe(true);
  });

  it("does not call attemptSelection with empty groups", () => {
    // No coins → groupOutputs returns no filters; insufficient_funds.
    const res = automaticCoinSelection([], 100n, mkParams());
    expect("error" in res && res.error).toBe("insufficient_funds");
  });

  it("returns insufficient_funds in attemptSelection when all solvers fail", () => {
    // Pool whose positive group can't satisfy any solver — e.g., one coin whose
    // effective value is less than target+CHANGE_LOWER but enough for face match.
    const g = group({ value: 100n, fee: 0n, longTermFee: 0n, effectiveValue: 100n });
    const res = attemptSelection(1_000n, { positive: [g], mixed: [g] }, mkParams());
    expect("error" in res && res.error).toBe("no_solution");
  });
});

// -- SFFO does NOT skip BnB (libnunchuk selector.cpp parity) --
//
// Upstream Bitcoin Core's ChooseSelectionResult (contrib/.../spend.cpp) skips BnB
// when subtract-fee-from-outputs is active ("SFFO frequently causes issues in the
// context of changeless input sets"). libnunchuk's own selector.cpp — the code the
// driver actually invokes — predates that guard and runs BnB UNCONDITIONALLY, so the
// port must too. This test pins that divergence: it fails if someone "fixes" the port
// toward upstream Core by gating BnB on subtractFeeOutputs (the winner would flip from
// bnb to knapsack for the same coins).
describe("SFFO does not skip BnB", () => {
  it("runs BnB and selects its changeless exact match when subtractFeeOutputs is on", () => {
    // pool 10/5/3, target 8 → BnB finds the exact changeless match {5,3}=8 and, being
    // pushed first, wins the waste tie. If BnB were skipped, Knapsack would return the
    // same coins but labelled "knapsack".
    const mkGroups = (): Groups => ({
      positive: [
        group({ value: 10n, txid: "a", subtractFeeOutputs: true }),
        group({ value: 5n, txid: "b", subtractFeeOutputs: true }),
        group({ value: 3n, txid: "c", subtractFeeOutputs: true }),
      ],
      mixed: [
        group({ value: 10n, txid: "a", subtractFeeOutputs: true }),
        group({ value: 5n, txid: "b", subtractFeeOutputs: true }),
        group({ value: 3n, txid: "c", subtractFeeOutputs: true }),
      ],
    });
    const params = mkParams({ subtractFeeOutputs: true, costOfChange: 1n });
    const res = chooseSelectionResult(8n, mkGroups(), params);
    expect("result" in res).toBe(true);
    if ("result" in res) {
      expect(res.result.algo).toBe(SelectionAlgorithm.BNB);
      const txids = res.result.inputs.map((i) => i.coin.txid).sort();
      expect(txids).toEqual(["b", "c"]);
    }
  });
});
