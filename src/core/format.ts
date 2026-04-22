// Formatting utilities for Bitcoin transactions

import { OutScript, Address, NETWORK, TEST_NETWORK } from "@scure/btc-signer";
import type { Network } from "./config.js";

export const SATS_PER_BTC = 100_000_000n;

export function formatBtc(sats: bigint): string {
  const negative = sats < 0n;
  const absSats = negative ? -sats : sats;
  const whole = absSats / SATS_PER_BTC;
  const frac = absSats % SATS_PER_BTC;
  const fracStr = frac.toString().padStart(8, "0");
  const btc = `${whole}.${fracStr}`;
  return negative ? `-${btc} BTC` : `${btc} BTC`;
}

export function formatSats(sats: bigint): string {
  return `${sats} sat`;
}

export function formatDate(unixTimestamp: number): string {
  if (unixTimestamp === 0) return "pending";
  return new Date(unixTimestamp * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC");
}

export function getOutputAddress(script: Uint8Array, network: Network): string | null {
  try {
    const net = network === "mainnet" ? NETWORK : TEST_NETWORK;
    const decoded = OutScript.decode(script);
    return Address(net).encode(decoded);
  } catch {
    return null;
  }
}

export function statusFromHeight(height: number): string {
  if (height > 0) return "CONFIRMED";
  if (height === -2) return "NETWORK_REJECTED";
  return "PENDING_CONFIRMATION";
}
