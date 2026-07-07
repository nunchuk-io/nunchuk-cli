// Fee rate estimation from Nunchuk API with Electrum fallback
// Reference: NunchukImpl::EstimateFee (nunchukimpl.cpp:1854-1895)

import { DEFAULT_FEE_LEVEL, type FeeLevel, type Network } from "./config.js";
import type { ElectrumClient } from "./electrum.js";

const FEE_URLS: Record<Network, string> = {
  mainnet: "https://api.nunchuk.io/v1.1/fees/recommended",
  testnet: "https://api.nunchuk.io/v1.1/fees/testnet/recommended",
};

interface RecommendedFees {
  fastestFee: number;
  halfHourFee: number;
  hourFee: number;
  minimumFee: number;
}

// Fee level → recommended-fees field and the matching Electrum conf_target.
const FEE_FIELD: Record<FeeLevel, keyof RecommendedFees> = {
  economy: "hourFee",
  standard: "halfHourFee",
  priority: "fastestFee",
};

const FEE_CONF_TARGET: Record<FeeLevel, number> = {
  economy: 6,
  standard: 3,
  priority: 2,
};

export async function fetchRecommendedFees(network: Network): Promise<RecommendedFees> {
  const response = await fetch(FEE_URLS[network]);
  if (!response.ok) {
    throw new Error(`Fee API returned ${response.status}`);
  }
  return (await response.json()) as RecommendedFees;
}

// Estimate fee rate in sat/kvB (satoshis per 1000 virtual bytes) for the given
// level using the Nunchuk API, falling back to Electrum. sat/kvB is Bitcoin
// Core's CFeeRate unit; keeping this resolution (rather than rounding to sat/vB)
// lets callers express fractional sat/vB rates such as 1.5 (= 1500 sat/kvB).
export async function estimateFeeRate(
  network: Network,
  electrum: ElectrumClient,
  level: FeeLevel = DEFAULT_FEE_LEVEL,
): Promise<bigint> {
  try {
    const fees = await fetchRecommendedFees(network);
    const rate = fees[FEE_FIELD[level]]; // sat/kvB
    if (rate > 0) {
      return BigInt(Math.ceil(rate));
    }
  } catch {
    // API unavailable — fall through to Electrum
  }

  const btcPerKb = await electrum.estimateFee(FEE_CONF_TARGET[level]);
  if (btcPerKb <= 0) {
    return 1000n; // 1 sat/vB floor
  }
  return BigInt(Math.ceil(btcPerKb * 100_000_000)); // BTC/kvB → sat/kvB
}

// The three user-facing recommended rates in sat/kvB. Mirrors the mobile app's
// "Processing speed" panel; `minimumFee` is intentionally omitted (it is a
// network floor, not a selectable speed).
export interface FeeRateLevels {
  priority: bigint;
  standard: bigint;
  economy: bigint;
}

// Fetch all three recommended levels at once. Uses a single Nunchuk API call
// when available; on failure (or any non-positive rate) falls back to per-level
// Electrum estimates via estimateFeeRate.
export async function estimateFeeRateLevels(
  network: Network,
  electrum: ElectrumClient,
): Promise<FeeRateLevels> {
  try {
    const fees = await fetchRecommendedFees(network);
    const priority = fees[FEE_FIELD.priority];
    const standard = fees[FEE_FIELD.standard];
    const economy = fees[FEE_FIELD.economy];
    if (priority > 0 && standard > 0 && economy > 0) {
      return {
        priority: BigInt(Math.ceil(priority)),
        standard: BigInt(Math.ceil(standard)),
        economy: BigInt(Math.ceil(economy)),
      };
    }
  } catch {
    // API unavailable — fall through to per-level Electrum estimates.
  }

  const [priority, standard, economy] = await Promise.all([
    estimateFeeRate(network, electrum, "priority"),
    estimateFeeRate(network, electrum, "standard"),
    estimateFeeRate(network, electrum, "economy"),
  ]);
  return { priority, standard, economy };
}
