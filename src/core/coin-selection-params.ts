// CoinSelectionParams factory + RNG implementations.
// Mirrors libnunchuk spender.cpp CreateTransaction setup. The pure algorithm lives in
// coin-selection.ts; this module composes the inputs it consumes.

import { randomBytes } from "node:crypto";
import {
  CFeeRate,
  generateChangeTarget,
  type CoinSelectionParams,
  type SelectionRng,
} from "./coin-selection.js";

// libnunchuk pins this for change_spend_size — the assumed virtual size of a
// future input that spends the change output. Not the wallet's real input size:
// Bitcoin Core uses a nested-segwit estimate as a conservative proxy.
// Source: contrib/bitcoin/src/wallet/wallet.h DUMMY_NESTED_P2WPKH_INPUT_SIZE.
export const DUMMY_NESTED_P2WPKH_INPUT_SIZE = 91;

// libnunchuk pins these in spender.cpp CreateTransaction (long-term and discard feerates).
export const DEFAULT_LONG_TERM_FEERATE_SAT_PER_KVB = 10_000n;
export const DEFAULT_DISCARD_FEERATE_SAT_PER_KVB = 3_000n;

// -- RNG implementations --

// Cryptographically random source. Production default; provides privacy for
// change-target randomization and Knapsack/SRD shuffles.
export class CryptoRng implements SelectionRng {
  randbool(): boolean {
    return (randomBytes(1)[0] & 1) === 1;
  }

  randrange(n: bigint): bigint {
    if (n <= 0n) throw new Error("randrange requires positive n");
    let bits = 0;
    let tmp = n - 1n;
    while (tmp > 0n) {
      bits++;
      tmp >>= 1n;
    }
    const byteLen = Math.max(1, Math.ceil(bits / 8));
    const mask = (1n << BigInt(bits)) - 1n;
    while (true) {
      const buf = randomBytes(byteLen);
      let v = 0n;
      for (const byte of buf) v = (v << 8n) | BigInt(byte);
      v &= mask;
      if (v < n) return v;
    }
  }

  shuffle<T>(arr: T[]): void {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Number(this.randrange(BigInt(i + 1)));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
  }
}

// Mulberry32-based deterministic RNG for tests. Same API as CryptoRng; given
// the same seed, produces the same stream. Byte-for-byte parity with C++
// FastRandomContext is not a goal — only reproducibility within these tests.
export class SeededRng implements SelectionRng {
  private state: number;

  constructor(seed: number) {
    this.state = seed | 0;
  }

  private next32(): number {
    this.state = (this.state + 0x6d2b79f5) | 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  }

  randbool(): boolean {
    return (this.next32() & 1) === 1;
  }

  randrange(n: bigint): bigint {
    if (n <= 0n) throw new Error("randrange requires positive n");
    if (n <= 0x1_0000_0000n) {
      const ceiling = 0x1_0000_0000n - (0x1_0000_0000n % n);
      while (true) {
        const v = BigInt(this.next32());
        if (v < ceiling) return v % n;
      }
    }
    const span = 1n << 64n;
    const ceiling = span - (span % n);
    while (true) {
      const v = (BigInt(this.next32()) << 32n) | BigInt(this.next32());
      if (v < ceiling) return v % n;
    }
  }

  shuffle<T>(arr: T[]): void {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Number(this.randrange(BigInt(i + 1)));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
  }
}

// -- tx_noinputs_size helper --

// Bitcoin compact-size encoding length, used to write the tx output count.
export function compactSizeBytes(n: number): number {
  if (n < 253) return 1;
  if (n < 0x1_0000) return 3;
  if (n < 0x1_0000_0000) return 5;
  return 9;
}

// Mirrors spender.cpp CreateTransaction (tx_noinputs_size):
//   tx_noinputs_size = 10 (header) + compactSize(n_recipients) + Σ serialize(output)
// Each recipient output is serialized as 8 (value) + compactSize(scriptLen) + scriptLen.
// Caller passes the script lengths.
export function computeTxNoinputsSize(recipientScriptLens: number[]): number {
  let size = 10 + compactSizeBytes(recipientScriptLens.length);
  for (const scriptLen of recipientScriptLens) {
    size += 8 + compactSizeBytes(scriptLen) + scriptLen;
  }
  return size;
}

// -- CoinSelectionParams builder --

export interface BuildCoinSelectionParamsArgs {
  // Effective fee rate in sat/kvB (Bitcoin Core's CFeeRate unit).
  feeRateSatPerKvB: bigint;
  // Optional overrides (default to libnunchuk's pinned values).
  longTermFeerateSatPerKvB?: bigint;
  discardFeerateSatPerKvB?: bigint;
  // Serialized size of the change CTxOut (= 8 + compactSize(scriptLen) + scriptLen).
  changeOutputSize: number;
  // Assumed vsize of a future input spending the change output.
  // Defaults to DUMMY_NESTED_P2WPKH_INPUT_SIZE to match libnunchuk.
  changeSpendSize?: number;
  // Pre-computed dust threshold for the change output, in sats. Caller computes
  // via Bitcoin Core's GetDustThreshold formula (policy/policy.cpp) using the
  // change output's serialized size and the discard feerate.
  changeOutputDust: bigint;
  // tx_noinputs_size (header + output overhead + Σ recipient outputs).
  txNoinputsSize: number;
  // Average payment value, used to randomize the minimum change target.
  // libnunchuk passes floor(recipients_sum / n_recipients) (spender.cpp CreateTransaction).
  paymentValue: bigint;
  subtractFeeOutputs?: boolean;
  rng: SelectionRng;
}

export function buildCoinSelectionParams(args: BuildCoinSelectionParamsArgs): CoinSelectionParams {
  const subtractFeeOutputs = args.subtractFeeOutputs ?? false;
  const effectiveFeerate = new CFeeRate(args.feeRateSatPerKvB);
  const longTermFeerate = new CFeeRate(
    args.longTermFeerateSatPerKvB ?? DEFAULT_LONG_TERM_FEERATE_SAT_PER_KVB,
  );
  const discardFeerate = new CFeeRate(
    args.discardFeerateSatPerKvB ?? DEFAULT_DISCARD_FEERATE_SAT_PER_KVB,
  );

  const changeOutputSize = args.changeOutputSize;
  const changeSpendSize = args.changeSpendSize ?? DUMMY_NESTED_P2WPKH_INPUT_SIZE;

  // spender.cpp CreateTransaction (change_fee, cost_of_change)
  const changeFee = effectiveFeerate.getFee(changeOutputSize);
  const costOfChange = discardFeerate.getFee(changeSpendSize) + changeFee;

  // spender.cpp CreateTransaction (min_viable_change)
  const changeSpendFee = discardFeerate.getFee(changeSpendSize);
  const dust = args.changeOutputDust;
  const minViableChange = changeSpendFee + 1n > dust ? changeSpendFee + 1n : dust;

  // spender.cpp CreateTransaction (min_change_target)
  const minChangeTarget = generateChangeTarget(args.paymentValue, changeFee, args.rng);

  return {
    rng: args.rng,
    changeOutputSize,
    changeSpendSize,
    minChangeTarget,
    minViableChange,
    changeFee,
    costOfChange,
    effectiveFeerate,
    longTermFeerate,
    discardFeerate,
    txNoinputsSize: args.txNoinputsSize,
    subtractFeeOutputs,
    avoidPartialSpends: false,
    includeUnsafeInputs: true,
  };
}

// -- Dust threshold helper --

// Bitcoin Core's GetDustThreshold (policy/policy.cpp). For a witness-program
// output (P2WPKH, P2WSH, P2TR), Core assumes a future input cost discounted by
// the witness-scale factor. Caller passes the output's serialized size and
// whether the output's scriptPubKey is a witness program.
//
// Output cost components (mirrors the C++ branches):
//   nSize = serializedOutputSize +
//     (witness ? (32 + 4 + 1 + ceil(107 / 4) + 4) : (32 + 4 + 1 + 107 + 4))
//   dust  = discardFeerate.getFee(nSize)
//
// Note: 107/4 truncates in C++ → 26. We match that exactly with Math.floor.
export function getDustThreshold(
  serializedOutputSize: number,
  isWitness: boolean,
  discardFeerate: CFeeRate,
): bigint {
  const inputOverhead = isWitness ? 32 + 4 + 1 + Math.floor(107 / 4) + 4 : 32 + 4 + 1 + 107 + 4;
  return discardFeerate.getFee(serializedOutputSize + inputOverhead);
}
