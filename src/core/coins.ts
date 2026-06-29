// Coin (UTXO) listing with status derivation + memo/lock join.
// Source-of-truth references:
//   libnunchuk include/nunchuk.h (CoinStatus enum)
//   libnunchuk src/storage/walletdb.cpp NunchukWalletDb::GetCoinsFromTransactions (status derivation)
//
// Status priority (monotonic, only raise):
//   INCOMING_PENDING_CONFIRMATION (0)
//   CONFIRMED (1)
//   OUTGOING_PENDING_SIGNATURES (2)
//   OUTGOING_PENDING_BROADCAST (3)
//   OUTGOING_PENDING_CONFIRMATION (4)  — deferred (needs spending-tx history)
//   SPENT (5)                          — deferred (coin would be off-chain by then)

import { Transaction } from "@scure/btc-signer";
import type { ApiClient } from "./api-client.js";
import type { ElectrumClient } from "./electrum.js";
import type { Network } from "./config.js";
import type { WalletData } from "./storage.js";
import { listCoinMeta } from "./coin-store.js";
import {
  decodePsbtDetail,
  fetchPendingTransactions,
  scanUtxos,
  type PendingTx,
} from "./transaction.js";

export type CoinStatus =
  | "INCOMING_PENDING_CONFIRMATION"
  | "CONFIRMED"
  | "OUTGOING_PENDING_SIGNATURES"
  | "OUTGOING_PENDING_BROADCAST"
  | "OUTGOING_PENDING_CONFIRMATION"
  | "SPENT";

export interface CoinDetail {
  txid: string;
  vout: number;
  address: string;
  amount: bigint;
  height: number;
  confirmations: number;
  status: CoinStatus;
  isChange: boolean;
  memo: string | null;
  locked: boolean;
}

const STATUS_RANK: Record<CoinStatus, number> = {
  INCOMING_PENDING_CONFIRMATION: 0,
  CONFIRMED: 1,
  OUTGOING_PENDING_SIGNATURES: 2,
  OUTGOING_PENDING_BROADCAST: 3,
  OUTGOING_PENDING_CONFIRMATION: 4,
  SPENT: 5,
};

export function raiseStatus(current: CoinStatus, candidate: CoinStatus): CoinStatus {
  return STATUS_RANK[candidate] > STATUS_RANK[current] ? candidate : current;
}

function outpointKey(txid: string, vout: number): string {
  return `${txid}:${vout}`;
}

export async function listCoins(args: {
  email: string;
  wallet: WalletData;
  network: Network;
  electrum: ElectrumClient;
  client?: ApiClient;
}): Promise<CoinDetail[]> {
  const { utxos } = await scanUtxos(args.wallet, args.network, args.electrum);

  let tipHeight = 0;
  try {
    tipHeight = (await args.electrum.headersSubscribe()).height;
  } catch {
    // electrum tip unavailable → confirmations stay 0 for unconfirmed handling
  }

  const coins = new Map<string, CoinDetail>();
  for (const utxo of utxos) {
    const status: CoinStatus = utxo.height > 0 ? "CONFIRMED" : "INCOMING_PENDING_CONFIRMATION";
    coins.set(outpointKey(utxo.txHash, utxo.txPos), {
      txid: utxo.txHash,
      vout: utxo.txPos,
      address: utxo.address,
      amount: utxo.value,
      height: utxo.height,
      confirmations: utxo.height > 0 ? Math.max(0, tipHeight - utxo.height + 1) : 0,
      status,
      isChange: utxo.chain === 1,
      memo: null,
      locked: false,
    });
  }

  if (args.client) {
    let pending: PendingTx[] = [];
    try {
      pending = await fetchPendingTransactions(args.client, args.wallet);
    } catch {
      // Group server unavailable — base statuses stay.
    }
    for (const ptx of pending) {
      const detail = decodePsbtDetail(
        ptx.psbt,
        args.network,
        args.wallet.m,
        args.wallet.signers,
        args.wallet.descriptor,
      );
      if (!detail) continue;
      const candidate: CoinStatus =
        detail.status === "READY_TO_BROADCAST"
          ? "OUTGOING_PENDING_BROADCAST"
          : "OUTGOING_PENDING_SIGNATURES";

      let tx: Transaction;
      try {
        tx = Transaction.fromPSBT(Buffer.from(ptx.psbt, "base64"));
      } catch {
        continue;
      }
      for (let i = 0; i < tx.inputsLength; i++) {
        const inp = tx.getInput(i);
        if (!inp.txid) continue;
        const key = outpointKey(Buffer.from(inp.txid).toString("hex"), inp.index ?? 0);
        const coin = coins.get(key);
        if (!coin) continue;
        coin.status = raiseStatus(coin.status, candidate);
      }
    }
  }

  const metas = listCoinMeta(args.email, args.network, args.wallet.walletId);
  for (const meta of metas) {
    const coin = coins.get(outpointKey(meta.txid, meta.vout));
    if (!coin) continue;
    coin.memo = meta.memo;
    coin.locked = meta.locked;
  }

  return [...coins.values()].sort((a, b) =>
    b.height === a.height ? a.txid.localeCompare(b.txid) : b.height - a.height,
  );
}
