// Fee rate estimation from Nunchuk API with Electrum fallback
// Reference: NunchukImpl::EstimateFee (nunchukimpl.cpp:1854-1895)

import type { Network } from "./config.js";
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

export async function fetchRecommendedFees(network: Network): Promise<RecommendedFees> {
  const response = await fetch(FEE_URLS[network]);
  if (!response.ok) {
    throw new Error(`Fee API returned ${response.status}`);
  }
  return (await response.json()) as RecommendedFees;
}

// Estimate fee rate (sat/vB) using Nunchuk API, falling back to Electrum.
// API returns sat/kvB (satoshis per 1000 virtual bytes) — same unit as
// Bitcoin Core's CFeeRate. Divide by 1000 to get sat/vB.
// libnunchuk default: conf_target=6 → hourFee
export async function estimateFeeRate(network: Network, electrum: ElectrumClient): Promise<bigint> {
  try {
    const fees = await fetchRecommendedFees(network);
    if (fees.hourFee > 0) {
      return BigInt(Math.ceil(fees.hourFee / 1000));
    }
  } catch {
    // API unavailable — fall through to Electrum
  }

  const btcPerKb = await electrum.estimateFee(6);
  if (btcPerKb <= 0) {
    return 1n;
  }
  return BigInt(Math.ceil(btcPerKb * 100_000));
}
