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

// Estimate fee rate (sat/vB) for the given level using the Nunchuk API, falling
// back to Electrum. API returns sat/kvB (satoshis per 1000 virtual bytes) — same
// unit as Bitcoin Core's CFeeRate. Divide by 1000 to get sat/vB.
export async function estimateFeeRate(
  network: Network,
  electrum: ElectrumClient,
  level: FeeLevel = DEFAULT_FEE_LEVEL,
): Promise<bigint> {
  try {
    const fees = await fetchRecommendedFees(network);
    const rate = fees[FEE_FIELD[level]];
    if (rate > 0) {
      return BigInt(Math.ceil(rate / 1000));
    }
  } catch {
    // API unavailable — fall through to Electrum
  }

  const btcPerKb = await electrum.estimateFee(FEE_CONF_TARGET[level]);
  if (btcPerKb <= 0) {
    return 1n;
  }
  return BigInt(Math.ceil(btcPerKb * 100_000));
}
