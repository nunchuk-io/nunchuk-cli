// Port of Bitcoin Core's coin selection algorithm as used by libnunchuk.
// Sources:
//   libnunchuk/contrib/bitcoin/src/wallet/coinselection.{h,cpp}
//   libnunchuk/src/selector.cpp
//   libnunchuk/src/spender.cpp (param setup — see coin-selection-params.ts)
//
// libnunchuk runs BnB + Knapsack + SRD only (CoinGrinder is NOT ported).
// All amounts are bigint sats. This module is pure: no I/O, no Node deps.

// -- Constants --

export const CHANGE_LOWER = 50_000n;
export const CHANGE_UPPER = 1_000_000n;
export const TOTAL_TRIES = 100_000;
export const MAX_STANDARD_TX_WEIGHT = 400_000;
export const WITNESS_SCALE_FACTOR = 4;
export const MAX_MONEY = 21_000_000n * 100_000_000n;

// -- Fee rate (Bitcoin Core CFeeRate, ported) --

// Sats per 1000 virtual bytes (sat/kvB). Matches Bitcoin Core's CFeeRate.GetFee
// arithmetic, including the "bump-to-1" special case for non-zero size with a
// positive feerate that would otherwise truncate to 0 (policy/feerate.cpp).
export class CFeeRate {
  constructor(public readonly satPerKvB: bigint) {}

  getFee(vbytes: number): bigint {
    if (vbytes <= 0) return 0n;
    const size = BigInt(vbytes);
    let fee = (this.satPerKvB * size) / 1000n; // truncating division
    if (fee === 0n) {
      if (this.satPerKvB > 0n) fee = 1n;
      else if (this.satPerKvB < 0n) fee = -1n;
    }
    return fee;
  }
}

// -- Types --

export interface CoinInput {
  txid: string;
  vout: number;
  value: bigint;
  // Signed virtual size of this coin's input (vbytes), precomputed by caller.
  inputVBytes: number;
  // Confirmation height (0 or negative = unconfirmed).
  height: number;
  // Block timestamp; informational, not used by selection itself.
  blocktime?: number;
  // True when the coin sits on an internal (change) address.
  isChange: boolean;
}

export interface COutput {
  coin: CoinInput;
  depth: number;
  fee: bigint;
  longTermFee: bigint;
  effectiveValue: bigint;
  ancestorBumpFees: bigint;
  weight: number;
}

export interface OutputGroup {
  outputs: COutput[];
  fromMe: boolean;
  value: bigint;
  depth: number;
  ancestors: number;
  descendants: number;
  effectiveValue: bigint;
  fee: bigint;
  longTermFee: bigint;
  subtractFeeOutputs: boolean;
  weight: number;
}

export interface CoinEligibilityFilter {
  confMine: number;
  confTheirs: number;
  maxAncestors: number;
  maxDescendants: number;
  includePartialGroups: boolean;
}

export interface SelectionRng {
  randbool(): boolean;
  randrange(n: bigint): bigint;
  shuffle<T>(arr: T[]): void;
}

export interface CoinSelectionParams {
  rng: SelectionRng;
  changeOutputSize: number;
  changeSpendSize: number;
  minChangeTarget: bigint;
  minViableChange: bigint;
  changeFee: bigint;
  costOfChange: bigint;
  effectiveFeerate: CFeeRate;
  longTermFeerate: CFeeRate;
  discardFeerate: CFeeRate;
  txNoinputsSize: number;
  subtractFeeOutputs: boolean;
  avoidPartialSpends: boolean;
  includeUnsafeInputs: boolean;
  maxTxWeight?: number;
}

export const SelectionAlgorithm = {
  BNB: "bnb",
  KNAPSACK: "knapsack",
  SRD: "srd",
  MANUAL: "manual",
} as const;
export type SelectionAlgorithm = (typeof SelectionAlgorithm)[keyof typeof SelectionAlgorithm];

export type SelectionError = "no_solution" | "max_weight" | "insufficient_funds";

// -- COutput / OutputGroup helpers --

export function makeCOutput(
  coin: CoinInput,
  args: {
    effectiveFeerate: CFeeRate;
    longTermFeerate: CFeeRate;
    currentHeight: number;
  },
): COutput {
  const fee = args.effectiveFeerate.getFee(coin.inputVBytes);
  const longTermFee = args.longTermFeerate.getFee(coin.inputVBytes);
  const effectiveValue = coin.value - fee;
  const depth = coin.height > 0 ? Math.max(0, args.currentHeight - coin.height + 1) : 0;
  const weight = coin.inputVBytes > 0 ? coin.inputVBytes * WITNESS_SCALE_FACTOR : 0;
  return { coin, depth, fee, longTermFee, effectiveValue, ancestorBumpFees: 0n, weight };
}

export function makeOutputGroup(subtractFeeOutputs: boolean): OutputGroup {
  return {
    outputs: [],
    fromMe: true,
    value: 0n,
    depth: 999,
    ancestors: 0,
    descendants: 0,
    effectiveValue: 0n,
    fee: 0n,
    longTermFee: 0n,
    subtractFeeOutputs,
    weight: 0,
  };
}

export function insertIntoGroup(
  group: OutputGroup,
  output: COutput,
  ancestors = 0,
  descendants = 0,
): void {
  group.outputs.push(output);
  group.fee += output.fee;
  group.longTermFee += output.longTermFee;
  group.effectiveValue += output.effectiveValue;
  group.value += output.coin.value;
  group.depth = Math.min(group.depth, output.depth);
  group.ancestors += ancestors;
  group.descendants = Math.max(group.descendants, descendants);
  if (output.coin.inputVBytes > 0) {
    group.weight += output.coin.inputVBytes * WITNESS_SCALE_FACTOR;
  }
}

// Wraps one COutput in a one-coin OutputGroup so preset coins can go through
// SelectionResult.addInput (mirrors SelectionResult::AddInputs, which appends
// pre-selected coins one by one).
export function singleCoinGroup(output: COutput, params: CoinSelectionParams): OutputGroup {
  const group = makeOutputGroup(params.subtractFeeOutputs);
  insertIntoGroup(group, output);
  return group;
}

export function getSelectionAmount(group: OutputGroup): bigint {
  return group.subtractFeeOutputs ? group.value : group.effectiveValue;
}

export function eligibleForSpending(group: OutputGroup, filter: CoinEligibilityFilter): boolean {
  const required = group.fromMe ? filter.confMine : filter.confTheirs;
  return (
    group.depth >= required &&
    group.ancestors <= filter.maxAncestors &&
    group.descendants <= filter.maxDescendants
  );
}

// -- SelectionResult --

export class SelectionResult {
  inputs: COutput[] = [];
  useEffective = false;
  weight = 0;
  bumpFeeGroupDiscount = 0n;
  algoCompleted = true;
  private waste: bigint | null = null;
  private outpoints = new Set<string>();

  constructor(
    public target: bigint,
    public readonly algo: SelectionAlgorithm,
  ) {}

  clear(): void {
    this.inputs = [];
    this.outpoints = new Set<string>();
    this.waste = null;
    this.weight = 0;
  }

  addInput(group: OutputGroup): void {
    for (const out of group.outputs) {
      const key = `${out.coin.txid}:${out.coin.vout}`;
      if (this.outpoints.has(key)) {
        throw new Error(`SelectionResult: shared UTXO ${key}`);
      }
      this.outpoints.add(key);
      this.inputs.push(out);
    }
    this.useEffective = !group.subtractFeeOutputs;
    this.weight += group.weight;
  }

  getSelectedValue(): bigint {
    let sum = 0n;
    for (const coin of this.inputs) sum += coin.coin.value;
    return sum;
  }

  getSelectedEffectiveValue(): bigint {
    let sum = 0n;
    for (const coin of this.inputs) sum += coin.effectiveValue;
    return sum + this.bumpFeeGroupDiscount;
  }

  getChange(minViableChange: bigint, changeFee: bigint): bigint {
    const change = this.useEffective
      ? this.getSelectedEffectiveValue() - this.target - changeFee
      : this.getSelectedValue() - this.target;
    if (change < minViableChange) return 0n;
    return change;
  }

  recalculateWaste(minViableChange: bigint, changeCost: bigint, changeFee: bigint): void {
    if (this.inputs.length === 0) {
      throw new Error("recalculateWaste called on empty selection");
    }
    let waste = 0n;
    for (const coin of this.inputs) {
      waste += coin.fee - coin.longTermFee;
    }
    waste -= this.bumpFeeGroupDiscount;

    if (this.getChange(minViableChange, changeFee) > 0n) {
      waste += changeCost;
    } else {
      const selectedValue = this.useEffective
        ? this.getSelectedEffectiveValue()
        : this.getSelectedValue();
      if (selectedValue < this.target) {
        throw new Error("recalculateWaste: selected value below target");
      }
      waste += selectedValue - this.target;
    }
    this.waste = waste;
  }

  getWaste(): bigint {
    if (this.waste === null) throw new Error("waste not computed");
    return this.waste;
  }

  // std::min_element-compatible: returns < 0 if `this` is better, > 0 if `other`
  // is better, 0 if tied. Tie-break: prefer more inputs (matches
  // coinselection.cpp SelectionResult::operator<).
  compare(other: SelectionResult): number {
    const a = this.getWaste();
    const b = other.getWaste();
    if (a < b) return -1;
    if (a > b) return 1;
    if (this.inputs.length > other.inputs.length) return -1;
    if (this.inputs.length < other.inputs.length) return 1;
    return 0;
  }
}

// -- Comparators --

function descending(a: OutputGroup, b: OutputGroup): number {
  const va = getSelectionAmount(a);
  const vb = getSelectionAmount(b);
  if (va === vb) {
    const da = a.fee - a.longTermFee;
    const db = b.fee - b.longTermFee;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
  }
  return va > vb ? -1 : 1;
}

// -- Branch and Bound --
// coinselection.cpp SelectCoinsBnB
export function selectCoinsBnB(
  utxoPool: OutputGroup[],
  selectionTarget: bigint,
  costOfChange: bigint,
  maxSelectionWeight: number,
): { result: SelectionResult } | { error: "no_solution" | "max_weight" } {
  let currValue = 0n;
  const currSelection: number[] = [];
  let currSelectionWeight = 0;

  let currAvailableValue = 0n;
  for (const u of utxoPool) {
    if (getSelectionAmount(u) <= 0n) {
      throw new Error("BnB pool contains non-positive UTXO");
    }
    currAvailableValue += getSelectionAmount(u);
  }
  if (currAvailableValue < selectionTarget) {
    return { error: "no_solution" };
  }

  utxoPool.sort(descending);

  let currWaste = 0n;
  let bestSelection: number[] | null = null;
  let bestWaste = MAX_MONEY;

  const isFeerateHigh = utxoPool[0].fee > utxoPool[0].longTermFee;
  let maxTxWeightExceeded = false;

  let utxoIndex = 0;
  for (let currTry = 0; currTry < TOTAL_TRIES; currTry++, utxoIndex++) {
    let backtrack = false;
    if (
      currValue + currAvailableValue < selectionTarget ||
      currValue > selectionTarget + costOfChange ||
      (currWaste > bestWaste && isFeerateHigh)
    ) {
      backtrack = true;
    } else if (currSelectionWeight > maxSelectionWeight) {
      maxTxWeightExceeded = true;
      backtrack = true;
    } else if (currValue >= selectionTarget) {
      currWaste += currValue - selectionTarget;
      if (currWaste <= bestWaste) {
        bestSelection = currSelection.slice();
        bestWaste = currWaste;
      }
      currWaste -= currValue - selectionTarget;
      backtrack = true;
    }

    if (backtrack) {
      if (currSelection.length === 0) break;
      const lastIncluded = currSelection[currSelection.length - 1];
      for (utxoIndex--; utxoIndex > lastIncluded; utxoIndex--) {
        currAvailableValue += getSelectionAmount(utxoPool[utxoIndex]);
      }
      if (utxoIndex !== lastIncluded) {
        throw new Error("BnB: index invariant broken during backtrack");
      }
      const utxo = utxoPool[utxoIndex];
      currValue -= getSelectionAmount(utxo);
      currWaste -= utxo.fee - utxo.longTermFee;
      currSelectionWeight -= utxo.weight;
      currSelection.pop();
    } else {
      const utxo = utxoPool[utxoIndex];
      currAvailableValue -= getSelectionAmount(utxo);

      const prevIncluded =
        currSelection.length > 0 && currSelection[currSelection.length - 1] === utxoIndex - 1;
      const prevEquivalent =
        utxoIndex > 0 &&
        getSelectionAmount(utxo) === getSelectionAmount(utxoPool[utxoIndex - 1]) &&
        utxo.fee === utxoPool[utxoIndex - 1].fee;

      if (currSelection.length === 0 || prevIncluded || !prevEquivalent) {
        currSelection.push(utxoIndex);
        currValue += getSelectionAmount(utxo);
        currWaste += utxo.fee - utxo.longTermFee;
        currSelectionWeight += utxo.weight;
      }
    }
  }

  if (!bestSelection) {
    return { error: maxTxWeightExceeded ? "max_weight" : "no_solution" };
  }

  const result = new SelectionResult(selectionTarget, SelectionAlgorithm.BNB);
  for (const i of bestSelection) result.addInput(utxoPool[i]);
  result.recalculateWaste(costOfChange, costOfChange, 0n);
  if (result.getWaste() !== bestWaste) {
    throw new Error("BnB: bestWaste mismatch after RecalculateWaste");
  }
  return { result };
}

// -- Knapsack + ApproximateBestSubset --
// coinselection.cpp ApproximateBestSubset / KnapsackSolver

export function approximateBestSubset(
  rng: SelectionRng,
  groups: OutputGroup[],
  nTotalLower: bigint,
  nTargetValue: bigint,
  maxSelectionWeight: number,
  iterations = 1000,
): { vfBest: boolean[]; nBest: bigint } {
  let vfBest = new Array<boolean>(groups.length).fill(true);
  let nBest = nTotalLower;

  for (let nRep = 0; nRep < iterations && nBest !== nTargetValue; nRep++) {
    const vfIncluded = new Array<boolean>(groups.length).fill(false);
    let nTotal = 0n;
    let weight = 0;
    let reached = false;
    for (let nPass = 0; nPass < 2 && !reached; nPass++) {
      for (let i = 0; i < groups.length; i++) {
        const include = nPass === 0 ? rng.randbool() : !vfIncluded[i];
        if (!include) continue;
        nTotal += getSelectionAmount(groups[i]);
        weight += groups[i].weight;
        vfIncluded[i] = true;
        if (nTotal >= nTargetValue && weight <= maxSelectionWeight) {
          reached = true;
          if (nTotal < nBest) {
            nBest = nTotal;
            vfBest = vfIncluded.slice();
          }
          nTotal -= getSelectionAmount(groups[i]);
          weight -= groups[i].weight;
          vfIncluded[i] = false;
        }
      }
    }
  }
  return { vfBest, nBest };
}

export function knapsackSolver(
  groups: OutputGroup[],
  nTargetValue: bigint,
  changeTarget: bigint,
  rng: SelectionRng,
  maxSelectionWeight: number,
): { result: SelectionResult } | { error: "no_solution" | "max_weight" } {
  const result = new SelectionResult(nTargetValue, SelectionAlgorithm.KNAPSACK);
  let maxWeightExceeded = false;
  let lowestLarger: OutputGroup | null = null;
  const applicableGroups: OutputGroup[] = [];
  let nTotalLower = 0n;

  rng.shuffle(groups);

  for (const group of groups) {
    if (group.weight > maxSelectionWeight) {
      maxWeightExceeded = true;
      continue;
    }
    const amount = getSelectionAmount(group);
    if (amount === nTargetValue) {
      result.addInput(group);
      return { result };
    } else if (amount < nTargetValue + changeTarget) {
      applicableGroups.push(group);
      nTotalLower += amount;
    } else if (!lowestLarger || amount < getSelectionAmount(lowestLarger)) {
      lowestLarger = group;
    }
  }

  if (nTotalLower === nTargetValue) {
    for (const g of applicableGroups) result.addInput(g);
    if (result.weight <= maxSelectionWeight) return { result };
    maxWeightExceeded = true;
    result.clear();
  }

  if (nTotalLower < nTargetValue) {
    if (!lowestLarger) {
      return { error: maxWeightExceeded ? "max_weight" : "no_solution" };
    }
    result.addInput(lowestLarger);
    return { result };
  }

  applicableGroups.sort(descending);
  let { vfBest, nBest } = approximateBestSubset(
    rng,
    applicableGroups,
    nTotalLower,
    nTargetValue,
    maxSelectionWeight,
  );
  if (nBest !== nTargetValue && nTotalLower >= nTargetValue + changeTarget) {
    ({ vfBest, nBest } = approximateBestSubset(
      rng,
      applicableGroups,
      nTotalLower,
      nTargetValue + changeTarget,
      maxSelectionWeight,
    ));
  }

  if (
    lowestLarger &&
    ((nBest !== nTargetValue && nBest < nTargetValue + changeTarget) ||
      getSelectionAmount(lowestLarger) <= nBest)
  ) {
    result.addInput(lowestLarger);
  } else {
    for (let i = 0; i < applicableGroups.length; i++) {
      if (vfBest[i]) result.addInput(applicableGroups[i]);
    }
    if (result.weight > maxSelectionWeight) {
      if (!lowestLarger) return { error: "max_weight" };
      result.clear();
      result.addInput(lowestLarger);
    }
  }
  return { result };
}

// -- Single Random Draw --
// coinselection.cpp SelectCoinsSRD

export function selectCoinsSRD(
  utxoPool: OutputGroup[],
  targetValue: bigint,
  changeFee: bigint,
  rng: SelectionRng,
  maxSelectionWeight: number,
): { result: SelectionResult } | { error: "no_solution" | "max_weight" } {
  const result = new SelectionResult(targetValue, SelectionAlgorithm.SRD);
  const target = targetValue + CHANGE_LOWER + changeFee;

  const indexes = utxoPool.map((_, i) => i);
  rng.shuffle(indexes);

  // Min-sorted array by selection amount (head = smallest).
  const selected: OutputGroup[] = [];
  let effValue = 0n;
  let weight = 0;
  let maxTxWeightExceeded = false;

  const insertSorted = (group: OutputGroup): void => {
    const amt = getSelectionAmount(group);
    let lo = 0;
    let hi = selected.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (getSelectionAmount(selected[mid]) <= amt) lo = mid + 1;
      else hi = mid;
    }
    selected.splice(lo, 0, group);
  };

  for (const i of indexes) {
    const group = utxoPool[i];
    if (getSelectionAmount(group) <= 0n) {
      throw new Error("SRD pool contains non-positive UTXO");
    }
    insertSorted(group);
    effValue += getSelectionAmount(group);
    weight += group.weight;

    if (weight > maxSelectionWeight) {
      maxTxWeightExceeded = true;
      while (selected.length > 0 && weight > maxSelectionWeight) {
        const removed = selected.shift()!;
        effValue -= getSelectionAmount(removed);
        weight -= removed.weight;
      }
    }

    if (effValue >= target) {
      for (const g of selected) result.addInput(g);
      return { result };
    }
  }
  return { error: maxTxWeightExceeded ? "max_weight" : "no_solution" };
}

// -- Change target --
// coinselection.cpp GenerateChangeTarget
export function generateChangeTarget(
  paymentValue: bigint,
  changeFee: bigint,
  rng: SelectionRng,
): bigint {
  if (paymentValue <= CHANGE_LOWER / 2n) {
    return changeFee + CHANGE_LOWER;
  }
  const upper = paymentValue * 2n < CHANGE_UPPER ? paymentValue * 2n : CHANGE_UPPER;
  return changeFee + rng.randrange(upper - CHANGE_LOWER) + CHANGE_LOWER;
}

// -- Group outputs (avoidPartialSpends=false simplification) --
// selector.cpp GroupOutputs

export interface Groups {
  positive: OutputGroup[];
  mixed: OutputGroup[];
}

export interface SelectionFilter {
  filter: CoinEligibilityFilter;
  allowMixedOutputTypes?: boolean;
}

export interface FilteredGroups {
  byFilter: Map<string, Groups>;
  discarded: OutputGroup[];
}

function filterKey(f: CoinEligibilityFilter): string {
  return `${f.confMine}|${f.confTheirs}|${f.maxAncestors}|${f.maxDescendants}|${f.includePartialGroups ? 1 : 0}`;
}

export function groupOutputs(
  coins: COutput[],
  params: CoinSelectionParams,
  filters: SelectionFilter[],
): FilteredGroups {
  if (params.avoidPartialSpends) {
    throw new Error(
      "avoidPartialSpends grouping is not implemented (libnunchuk runs with avoidPartialSpends=false)",
    );
  }
  const byFilter = new Map<string, Groups>();
  const discarded: OutputGroup[] = [];

  for (const coin of coins) {
    const group = makeOutputGroup(params.subtractFeeOutputs);
    insertIntoGroup(group, coin, 0, 0);

    let accepted = false;
    for (const sel of filters) {
      if (!eligibleForSpending(group, sel.filter)) continue;
      const key = filterKey(sel.filter);
      let g = byFilter.get(key);
      if (!g) {
        g = { positive: [], mixed: [] };
        byFilter.set(key, g);
      }
      if (getSelectionAmount(group) > 0n) g.positive.push(group);
      g.mixed.push(group);
      accepted = true;
    }
    if (!accepted) discarded.push(group);
  }
  return { byFilter, discarded };
}

// -- ChooseSelectionResult --
// selector.cpp ChooseSelectionResult

export function chooseSelectionResult(
  target: bigint,
  groups: Groups,
  params: CoinSelectionParams,
): { result: SelectionResult } | { error: "no_solution" | "max_weight" } {
  const results: SelectionResult[] = [];
  let firstWeightError: "max_weight" | null = null;
  const record = (e: "no_solution" | "max_weight"): void => {
    if (e === "max_weight" && firstWeightError === null) firstWeightError = "max_weight";
  };

  let maxInputsWeight = MAX_STANDARD_TX_WEIGHT - params.txNoinputsSize * WITNESS_SCALE_FACTOR;

  const bnb = selectCoinsBnB(groups.positive.slice(), target, params.costOfChange, maxInputsWeight);
  if ("result" in bnb) results.push(bnb.result);
  else record(bnb.error);

  // Knapsack and SRD always produce change → also deduct change weight.
  maxInputsWeight -= params.changeOutputSize * WITNESS_SCALE_FACTOR;

  const knap = knapsackSolver(
    groups.mixed.slice(),
    target,
    params.minChangeTarget,
    params.rng,
    maxInputsWeight,
  );
  if ("result" in knap) results.push(knap.result);
  else record(knap.error);

  const srd = selectCoinsSRD(
    groups.positive.slice(),
    target,
    params.changeFee,
    params.rng,
    maxInputsWeight,
  );
  if ("result" in srd) results.push(srd.result);
  else record(srd.error);

  if (results.length === 0) {
    return { error: firstWeightError ?? "no_solution" };
  }

  for (const r of results) {
    r.recalculateWaste(params.minViableChange, params.costOfChange, params.changeFee);
  }

  let best = results[0];
  for (let i = 1; i < results.length; i++) {
    if (results[i].compare(best) < 0) best = results[i];
  }
  return { result: best };
}

// -- AttemptSelection --
// selector.cpp AttemptSelection — collapses to chooseSelectionResult for a single
// output type (libnunchuk wallets have one addressType).
export function attemptSelection(
  target: bigint,
  groups: Groups,
  params: CoinSelectionParams,
): { result: SelectionResult } | { error: "no_solution" | "max_weight" } {
  return chooseSelectionResult(target, groups, params);
}

// -- AutomaticCoinSelection --
// selector.cpp AutomaticCoinSelection (eligibility filter ladder)
export function automaticCoinSelection(
  availableCoins: COutput[],
  valueToSelect: bigint,
  params: CoinSelectionParams,
): { result: SelectionResult } | { error: SelectionError } {
  const maxAncestors = 25;
  const maxDescendants = 25;

  const filters: SelectionFilter[] = [
    {
      filter: {
        confMine: 1,
        confTheirs: 6,
        maxAncestors: 0,
        maxDescendants: 0,
        includePartialGroups: false,
      },
      allowMixedOutputTypes: false,
    },
    {
      filter: {
        confMine: 1,
        confTheirs: 1,
        maxAncestors: 0,
        maxDescendants: 0,
        includePartialGroups: false,
      },
    },
    {
      filter: {
        confMine: 0,
        confTheirs: 1,
        maxAncestors: 2,
        maxDescendants: 2,
        includePartialGroups: false,
      },
    },
    {
      filter: {
        confMine: 0,
        confTheirs: 1,
        maxAncestors: Math.min(4, Math.floor(maxAncestors / 3)),
        maxDescendants: Math.min(4, Math.floor(maxDescendants / 3)),
        includePartialGroups: false,
      },
    },
    {
      filter: {
        confMine: 0,
        confTheirs: 1,
        maxAncestors: Math.floor(maxAncestors / 2),
        maxDescendants: Math.floor(maxDescendants / 2),
        includePartialGroups: false,
      },
    },
    {
      filter: {
        confMine: 0,
        confTheirs: 1,
        maxAncestors: maxAncestors - 1,
        maxDescendants: maxDescendants - 1,
        includePartialGroups: true,
      },
    },
  ];

  if (params.includeUnsafeInputs) {
    filters.push({
      filter: {
        confMine: 0,
        confTheirs: 0,
        maxAncestors: maxAncestors - 1,
        maxDescendants: maxDescendants - 1,
        includePartialGroups: true,
      },
    });
  }

  const filtered = groupOutputs(availableCoins, params, filters);

  let firstWeightError: "max_weight" | null = null;
  for (const sel of filters) {
    const groups = filtered.byFilter.get(filterKey(sel.filter));
    if (!groups) continue;
    const r = attemptSelection(valueToSelect, groups, params);
    if ("result" in r) return r;
    if (r.error === "max_weight" && firstWeightError === null) {
      firstWeightError = "max_weight";
    }
  }
  return { error: firstWeightError ?? "insufficient_funds" };
}

// -- selectCoins --
// selector.cpp SelectCoins — top-level entry.
//
// Preset inputs are EXACT-SET: NunchukImpl::CreatePsbt passes the user's chosen
// coins as the entire available pool, so the automatic pool is empty and the
// preset either covers the target by itself (MANUAL result with every preset
// coin — no subset optimization, mirroring SelectionResult::AddInputs on
// PreSelectedInputs) or the spend fails with insufficient funds. The upstream
// Bitcoin Core Merge / m_allow_other_inputs auto-top-up branches are dead code
// in the libnunchuk integration and are intentionally not ported.
export function selectCoins(
  availableCoins: COutput[],
  targetValue: bigint,
  params: CoinSelectionParams,
  presetInputs: COutput[] = [],
): { result: SelectionResult } | { error: SelectionError } {
  if (presetInputs.length > 0) {
    if (availableCoins.length > 0) {
      // Exact-set semantics leave no role for an automatic pool; a caller
      // passing both is a bug, not a selection failure.
      throw new Error("selectCoins: presetInputs requires an empty availableCoins pool");
    }
    // FetchSelectedInputs: total is effective value, or raw value under
    // subtract-fee-from-outputs.
    let presetTotal = 0n;
    for (const c of presetInputs) {
      presetTotal += params.subtractFeeOutputs ? c.coin.value : c.effectiveValue;
    }
    if (targetValue - presetTotal > 0n) {
      return { error: "insufficient_funds" };
    }
    const result = new SelectionResult(targetValue, SelectionAlgorithm.MANUAL);
    for (const c of presetInputs) {
      result.addInput(singleCoinGroup(c, params));
    }
    result.recalculateWaste(params.minViableChange, params.costOfChange, params.changeFee);
    return { result };
  }
  let totalAvailable = 0n;
  for (const c of availableCoins) {
    if (params.subtractFeeOutputs) {
      totalAvailable += c.coin.value;
    } else if (c.effectiveValue > 0n) {
      totalAvailable += c.effectiveValue;
    }
  }
  if (targetValue > totalAvailable) {
    return { error: "insufficient_funds" };
  }
  return automaticCoinSelection(availableCoins, targetValue, params);
}
