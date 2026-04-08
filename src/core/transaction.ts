// Transaction operations for group wallets
// Reference: libnunchuk nunchukimpl.cpp, groupservice.cpp

import { Transaction, bip32Path, selectUTXO, NETWORK, TEST_NETWORK } from "@scure/btc-signer";
import { RawPSBTV0 } from "@scure/btc-signer/psbt.js";
import { base58 } from "@scure/base";
import { getElectrumServer } from "./config.js";
import type { Network } from "./config.js";
import { ApiClient } from "./api-client.js";
import { ElectrumClient, addressToScripthash, parseBlockTime } from "./electrum.js";
import type { HistoryItem } from "./electrum.js";
import { deriveAddresses, deriveMultisigPayment } from "./address.js";
import type { WalletData } from "./storage.js";
import {
  hashMessage,
  signWalletMessage,
  encryptWalletPayload,
  decryptWalletPayload,
} from "./wallet-keys.js";
import { buildAnyDescriptor, parseSignerDescriptor } from "./descriptor.js";
import { formatBtc, formatSats, getOutputAddress } from "./format.js";
import { estimateFeeRate } from "./fees.js";

const GAP_LIMIT = 20;

// -- Interfaces --

export interface WalletUtxo {
  txHash: string;
  txPos: number;
  value: bigint;
  chain: 0 | 1;
  index: number;
  address: string;
}

export interface PendingTx {
  txId: string;
  psbt: string;
}

export interface ServerTxEvent {
  id: string;
  data: {
    version: number;
    msg: string;
    sig: string;
  };
}

export interface ServerTxResponse {
  transaction: ServerTxEvent;
}

export interface PendingTxDetail {
  txId: string;
  status: string;
  signedCount: number;
  requiredCount: number;
  fee: string;
  feeBtc: string;
  outputs: Array<{ address: string | null; amount: string; amountBtc: string; isChange: boolean }>;
  subAmount: string;
  subAmountBtc: string;
  signers: Record<string, boolean>;
}

export interface ConfirmedTx {
  txHash: string;
  height: number;
  fee: number;
  amount: bigint;
  blocktime: number;
  confirmations: number;
  addresses: string[];
}

// -- Transaction creation --
// Reference: NunchukImpl::CreateTransaction (nunchukimpl.cpp:1145-1207)
// Reference: FillPsbt (walletdb.cpp:1066-1122)

// Decode xpub base58 string to raw 78-byte serialized key
function xpubToRawBytes(xpub: string): Uint8Array {
  const withChecksum = base58.decode(xpub);
  return new Uint8Array(withChecksum.slice(0, 78));
}

// Add global xpubs to PSBT (PSBT_GLOBAL_XPUB entries)
// Reference: FillPsbt stores signer xpubs so all signers can identify the wallet
function addGlobalXpubs(psbtBytes: Uint8Array, signers: string[]): Uint8Array {
  const raw = RawPSBTV0.decode(psbtBytes);
  const xpubEntries: Array<[Uint8Array, { fingerprint: number; path: number[] }]> = [];

  for (const desc of signers) {
    const parsed = parseSignerDescriptor(desc);
    const xpubBytes = xpubToRawBytes(parsed.xpub);
    const fingerprint = parseInt(parsed.masterFingerprint, 16);
    const path = bip32Path("m" + parsed.derivationPath);
    xpubEntries.push([xpubBytes, { fingerprint, path }]);
  }

  raw.global.xpub = xpubEntries;
  return RawPSBTV0.encode(raw);
}

export interface CreateTransactionParams {
  wallet: WalletData;
  network: Network;
  electrum: ElectrumClient;
  toAddress: string;
  amount: bigint;
}

export interface CreateTransactionResult {
  psbtB64: string;
  txId: string;
  fee: bigint;
  feePerByte: bigint;
  changeAddress: string | null;
}

// Create a transaction PSBT with all metadata matching libnunchuk's FillPsbt
// Flow: scan UTXOs → coin selection → build PSBT → add nonWitnessUtxo,
//       bip32Derivation (inputs + outputs), witnessScript, global xpubs
export async function createTransaction(
  params: CreateTransactionParams,
): Promise<CreateTransactionResult> {
  const { wallet, network, electrum, toAddress, amount } = params;
  const btcNet = network === "mainnet" ? NETWORK : TEST_NETWORK;

  // Step 1: Scan UTXOs
  const { utxos, nextChangeIndex } = await scanUtxos(wallet, network, electrum);
  if (utxos.length === 0) {
    throw new Error("No UTXOs found. Wallet has no funds.");
  }

  // Step 2: Fetch full previous transactions for nonWitnessUtxo
  // Reference: FillPsbt adds non_witness_utxo from database (walletdb.cpp:1074-1089)
  const prevTxCache = new Map<string, string>();
  for (const utxo of utxos) {
    if (!prevTxCache.has(utxo.txHash)) {
      const rawHex = await electrum.getTransaction(utxo.txHash);
      prevTxCache.set(utxo.txHash, rawHex);
    }
  }

  // Step 3: Build PSBT input metadata for each UTXO
  // Reference: FillPsbt populates witnessUtxo, bip32Derivation, witnessScript
  const psbtInputs = utxos.map((utxo) => {
    const payment = deriveMultisigPayment(
      wallet.signers,
      wallet.m,
      wallet.addressType,
      network,
      utxo.chain,
      utxo.index,
    );
    const input: Record<string, unknown> = {
      txid: utxo.txHash,
      index: utxo.txPos,
      nonWitnessUtxo: prevTxCache.get(utxo.txHash),
      witnessUtxo: { script: payment.script, amount: utxo.value },
      bip32Derivation: payment.bip32Derivation,
      sequence: 0xfffffffd, // MAX_BIP125_RBF_SEQUENCE — enables RBF
    };
    if (payment.witnessScript) input.witnessScript = payment.witnessScript;
    if (payment.redeemScript) input.redeemScript = payment.redeemScript;
    return input;
  });

  // Step 4: Determine change address (first unused internal address)
  // Reference: nunchukimpl.cpp:2449-2456 GetAddresses(wallet_id, false, true)
  const changeAddrs = deriveAddresses(
    wallet.signers,
    wallet.m,
    wallet.addressType,
    network,
    1,
    nextChangeIndex,
    1,
  );
  const changeAddress = changeAddrs[0];

  // Step 5: Fee estimation from Nunchuk API (hourFee) with Electrum fallback
  // Reference: NunchukImpl::EstimateFee (nunchukimpl.cpp:1854-1895)
  const feePerByte = await estimateFeeRate(network, electrum);

  // Step 6: Coin selection + transaction building
  // Reference: wallet::CreateTransaction in spender.cpp:200-511 (BnB + Knapsack)
  // CLI uses @scure/btc-signer's selectUTXO for MVP
  const result = selectUTXO(psbtInputs as any, [{ address: toAddress, amount }], "default", {
    feePerByte,
    changeAddress,
    network: btcNet,
    createTx: true,
    dust: 546n as any,
  });

  if (!result) {
    throw new Error("Insufficient funds to cover amount + fee.");
  }

  const tx = result.tx!;

  // Step 7: Add metadata to change output (bip32Derivation, witnessScript, redeemScript)
  // Reference: FillPsbt calls UpdatePSBTOutput for ALL outputs (walletdb.cpp:1096-1099)
  // BIP-174: outputs should include redeemScript (0x00), witnessScript (0x01), bip32Derivation (0x02)
  if (result.change) {
    const changePayment = deriveMultisigPayment(
      wallet.signers,
      wallet.m,
      wallet.addressType,
      network,
      1,
      nextChangeIndex,
    );
    for (let i = 0; i < tx.outputsLength; i++) {
      const out = tx.getOutput(i);
      if (out.script && getOutputAddress(out.script, network) === changeAddress) {
        const outputUpdate: Record<string, unknown> = {
          bip32Derivation: changePayment.bip32Derivation,
        };
        if (changePayment.witnessScript) outputUpdate.witnessScript = changePayment.witnessScript;
        if (changePayment.redeemScript) outputUpdate.redeemScript = changePayment.redeemScript;
        tx.updateOutput(i, outputUpdate);
        break;
      }
    }
  }

  // Step 8: Add global xpubs
  // Reference: FillPsbt stores signer xpubs in PSBT (walletdb.cpp:1101-1119)
  const psbtBytes = addGlobalXpubs(tx.toPSBT(), wallet.signers);

  const psbtB64 = Buffer.from(psbtBytes).toString("base64");
  const txId = tx.id;

  return {
    psbtB64,
    txId,
    fee: result.fee ?? 0n,
    feePerByte,
    changeAddress: result.change ? changeAddress : null,
  };
}

// -- Wallet balance --
// Reference: libnunchuk NunchukWalletDb::GetBalance (walletdb.cpp:990-1002)

export async function getWalletBalance(
  wallet: WalletData,
  network: Network,
  electrum: ElectrumClient,
): Promise<bigint> {
  let total = 0n;

  for (const chain of [0, 1] as const) {
    let startIndex = 0;
    let consecutiveEmpty = 0;
    while (consecutiveEmpty < GAP_LIMIT) {
      const addresses = deriveAddresses(
        wallet.signers,
        wallet.m,
        wallet.addressType,
        network,
        chain,
        startIndex,
        1,
      );
      const scripthash = addressToScripthash(addresses[0], network);
      const bal = await electrum.getBalance(scripthash);

      if (bal.confirmed !== 0 || bal.unconfirmed !== 0) {
        total += BigInt(bal.confirmed) + BigInt(bal.unconfirmed);
        consecutiveEmpty = 0;
      } else {
        consecutiveEmpty++;
      }
      startIndex++;
    }
  }

  return total;
}

export async function getNextReceiveAddress(
  wallet: WalletData,
  network: Network,
  electrum: ElectrumClient,
): Promise<{ address: string; index: number }> {
  let startIndex = 0;
  let consecutiveEmpty = 0;
  let highestUsedIndex = -1;

  while (consecutiveEmpty < GAP_LIMIT) {
    const address = deriveAddresses(
      wallet.signers,
      wallet.m,
      wallet.addressType,
      network,
      0,
      startIndex,
      1,
    )[0];
    const scripthash = addressToScripthash(address, network);
    const history = await electrum.getHistory(scripthash);

    if (history.length > 0) {
      highestUsedIndex = startIndex;
      consecutiveEmpty = 0;
    } else {
      consecutiveEmpty++;
    }

    startIndex++;
  }

  const index = highestUsedIndex + 1;
  const address = deriveAddresses(
    wallet.signers,
    wallet.m,
    wallet.addressType,
    network,
    0,
    index,
    1,
  )[0];
  return { address, index };
}

// -- UTXO scanning --
// Reference: libnunchuk ElectrumSynchronizer::ListUnspent (synchronizer.cpp:587-613)

export async function scanUtxos(
  wallet: WalletData,
  network: Network,
  electrum: ElectrumClient,
): Promise<{ utxos: WalletUtxo[]; nextChangeIndex: number }> {
  const utxos: WalletUtxo[] = [];
  let nextChangeIndex = 0;

  for (const chain of [0, 1] as const) {
    let startIndex = 0;
    let consecutiveEmpty = 0;
    while (consecutiveEmpty < GAP_LIMIT) {
      const addresses = deriveAddresses(
        wallet.signers,
        wallet.m,
        wallet.addressType,
        network,
        chain,
        startIndex,
        1,
      );
      const addr = addresses[0];
      const scripthash = addressToScripthash(addr, network);
      const unspent = await electrum.listUnspent(scripthash);

      if (unspent.length > 0) {
        for (const u of unspent) {
          utxos.push({
            txHash: u.tx_hash,
            txPos: u.tx_pos,
            value: BigInt(u.value),
            chain,
            index: startIndex,
            address: addr,
          });
        }
        consecutiveEmpty = 0;
        if (chain === 1) nextChangeIndex = startIndex + 1;
      } else {
        consecutiveEmpty++;
      }
      startIndex++;
    }
  }

  return { utxos, nextChangeIndex };
}

// -- Group server transaction helpers --
// Reference: GroupService::TransactionToEvent (groupservice.cpp:471-490)

export async function uploadTransaction(
  client: ApiClient,
  wallet: WalletData,
  psbtB64: string,
  txId: string,
): Promise<void> {
  const secretboxKey = new Uint8Array(Buffer.from(wallet.secretboxKey, "base64"));
  const payload = await encryptWalletPayload(wallet, { psbt: psbtB64, txId });
  const txGid = hashMessage(secretboxKey, txId);

  await client.post(
    `/v1.1/shared-wallets/wallets/${wallet.gid}/transactions`,
    JSON.stringify({ id: txGid, data: payload }),
  );
}

// Fetch a single pending transaction by txId
// Reference: GroupService::GetTransaction (groupservice.cpp:1046-1054)
export async function fetchPendingTransaction(
  client: ApiClient,
  wallet: WalletData,
  txId: string,
): Promise<PendingTx> {
  const secretboxKey = new Uint8Array(Buffer.from(wallet.secretboxKey, "base64"));
  const txGid = hashMessage(secretboxKey, txId);

  const data = await client.get<{ transaction: ServerTxEvent }>(
    `/v1.1/shared-wallets/wallets/${wallet.gid}/transactions/${txGid}`,
  );

  const event = (data as any).transaction ?? data;
  if (!event?.data?.msg) {
    throw new Error("Transaction not found on server");
  }

  const parsed = decryptWalletPayload<{ txId?: string; tx_id?: string; psbt: string }>(
    wallet,
    event,
  );
  return { txId: parsed.txId || parsed.tx_id || "", psbt: parsed.psbt };
}

// Fetch all pending transactions
export async function fetchPendingTransactions(
  client: ApiClient,
  wallet: WalletData,
): Promise<PendingTx[]> {
  try {
    const data = await client.get<{ transactions: ServerTxEvent[] }>(
      `/v1.1/shared-wallets/wallets/${wallet.gid}/transactions?page=0&page_size=100&sort=desc`,
    );

    const events = Array.isArray(data) ? data : (data?.transactions ?? data ?? []);
    const pending: PendingTx[] = [];

    for (const event of events as ServerTxEvent[]) {
      try {
        const parsed = decryptWalletPayload<{ txId?: string; tx_id?: string; psbt: string }>(
          wallet,
          event,
        );
        pending.push({ txId: parsed.txId || parsed.tx_id || "", psbt: parsed.psbt });
      } catch {
        // skip events we can't decrypt
      }
    }
    return pending;
  } catch {
    return [];
  }
}

// Delete transaction from server after broadcast
// Reference: GroupService::DeleteTransaction (groupservice.cpp:1085-1107)
export async function deleteTransaction(
  client: ApiClient,
  wallet: WalletData,
  txId: string,
): Promise<void> {
  const secretboxKey = new Uint8Array(Buffer.from(wallet.secretboxKey, "base64"));
  const descriptor = buildAnyDescriptor(wallet.signers, wallet.m, wallet.addressType);
  const txGid = hashMessage(secretboxKey, txId);

  // Note: DELETE body uses plaintext msg (NOT encrypted) — matches libnunchuk
  const plaintextMsg = JSON.stringify({ ts: Math.floor(Date.now() / 1000), txGid });
  const sig = await signWalletMessage(descriptor, plaintextMsg);

  await client.del(
    `/v1.1/shared-wallets/wallets/${wallet.gid}/transactions`,
    JSON.stringify({
      id: txGid,
      data: { version: 1, msg: plaintextMsg, sig },
    }),
  );
}

export interface CombinePendingPsbtResult {
  psbtB64: string;
  changed: boolean;
}

export function combinePendingPsbt(
  currentPsbtB64: string,
  nextPsbtB64: string,
): CombinePendingPsbtResult {
  const currentTx = Transaction.fromPSBT(Buffer.from(currentPsbtB64, "base64"));
  const currentCanonical = Buffer.from(currentTx.toPSBT());

  try {
    currentTx.combine(Transaction.fromPSBT(Buffer.from(nextPsbtB64, "base64")));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.startsWith("Transaction/combine:")) {
      throw new Error(
        `Provided PSBT does not match the current pending transaction: ${message.replace("Transaction/combine: ", "")}`,
        { cause: err },
      );
    }
    throw err;
  }

  const combinedCanonical = Buffer.from(currentTx.toPSBT());
  return {
    psbtB64: combinedCanonical.toString("base64"),
    changed: !combinedCanonical.equals(currentCanonical),
  };
}

// Determine PSBT status by analyzing signatures
// Reference: libnunchuk src/utils/txutils.hpp:514-554
export function decodePsbtDetail(
  psbtB64: string,
  network: Network,
  walletM?: number,
  walletSigners?: string[],
): PendingTxDetail | null {
  try {
    const tx = Transaction.fromPSBT(Buffer.from(psbtB64, "base64"));

    // -- Change output detection via bip32Derivation --
    // Reference: libnunchuk FillSendReceiveData checks isMyChange(addr)
    // PSBT outputs with bip32Derivation belong to the wallet;
    // path second-to-last element: 1 = change, 0 = receive-to-self
    const outputs: PendingTxDetail["outputs"] = [];
    let subAmount = 0n;
    for (let i = 0; i < tx.outputsLength; i++) {
      const out = tx.getOutput(i);
      const addr = out.script ? getOutputAddress(out.script, network) : null;
      const amt = out.amount ?? 0n;
      let isChange = false;
      const bip32 = out.bip32Derivation as
        | Array<[Uint8Array, { fingerprint: number; path: number[] }]>
        | undefined;
      if (bip32 && bip32.length > 0) {
        const path = bip32[0][1].path;
        const chain = path[path.length - 2];
        isChange = chain === 1;
      }
      if (!isChange) {
        // External recipient or receive-to-self — counts toward subAmount
        if (!bip32 || bip32.length === 0) {
          subAmount += amt;
        }
      }
      outputs.push({
        address: addr,
        amount: formatSats(amt),
        amountBtc: formatBtc(amt),
        isChange,
      });
    }

    const requiredCount = walletM ?? 0;

    let status: string;
    if (tx.isFinal) {
      status = "READY_TO_BROADCAST";
    } else {
      try {
        const clone = tx.clone();
        clone.finalize();
        status = "READY_TO_BROADCAST";
      } catch {
        status = "PENDING_SIGNATURES";
      }
    }

    // -- Signer identification via partialSig cross-reference --
    // Reference: libnunchuk GetTransactionFromPartiallySignedTransaction
    // iterates partial_sigs, matches pubkeys against hd_keypaths to find xfp
    let signedCount = 0;
    const signedXfps = new Set<number>();

    if (tx.inputsLength > 0) {
      const inp = tx.getInput(0);
      const partialSig = inp.partialSig as Array<[Uint8Array, Uint8Array]> | undefined;
      const bip32Derivation = inp.bip32Derivation as
        | Array<[Uint8Array, { fingerprint: number; path: number[] }]>
        | undefined;

      if (status === "READY_TO_BROADCAST") {
        signedCount = requiredCount;
        // For finalized PSBTs, all signers in bip32Derivation that contributed are marked
        // but partialSig is cleared after finalize — mark all as signed
        if (bip32Derivation) {
          for (const [, { fingerprint }] of bip32Derivation) {
            signedXfps.add(fingerprint);
          }
        }
      } else {
        signedCount = partialSig?.length ?? 0;
        if (partialSig && bip32Derivation) {
          for (const [pubkey] of partialSig) {
            for (const [bip32Pub, { fingerprint }] of bip32Derivation) {
              if (Buffer.from(pubkey).equals(Buffer.from(bip32Pub))) {
                signedXfps.add(fingerprint);
                break;
              }
            }
          }
        }
      }
    }

    // Build signers map from wallet signers descriptors
    const signers: Record<string, boolean> = {};
    if (walletSigners) {
      for (const desc of walletSigners) {
        const xfp = parseSignerDescriptor(desc).masterFingerprint;
        signers[xfp] = signedXfps.has(parseInt(xfp, 16));
      }
    }

    return {
      txId: "",
      status,
      signedCount,
      requiredCount,
      fee: formatSats(tx.fee),
      feeBtc: formatBtc(tx.fee),
      outputs,
      subAmount: formatSats(subAmount),
      subAmountBtc: formatBtc(subAmount),
      signers,
    };
  } catch {
    return null;
  }
}

// -- Confirmed transactions from Electrum --

export async function fetchConfirmedTransactions(
  wallet: WalletData,
  network: Network,
): Promise<ConfirmedTx[]> {
  const server = getElectrumServer(network);
  const electrum = new ElectrumClient();
  try {
    await electrum.connect(server.host, server.port, server.protocol);
    await electrum.serverVersion("nunchuk-cli", "1.4");

    const tip = await electrum.headersSubscribe();
    const tipHeight = tip.height;

    const walletAddresses = new Set<string>();
    const allHistory: HistoryItem[] = [];

    for (const chain of [0, 1] as const) {
      let startIndex = 0;
      let consecutiveEmpty = 0;
      while (consecutiveEmpty < GAP_LIMIT) {
        const batchSize = GAP_LIMIT - consecutiveEmpty;
        const addresses = deriveAddresses(
          wallet.signers,
          wallet.m,
          wallet.addressType,
          network,
          chain,
          startIndex,
          batchSize,
        );
        for (const addr of addresses) {
          walletAddresses.add(addr);
          const scripthash = addressToScripthash(addr, network);
          const history = await electrum.getHistory(scripthash);
          if (history.length > 0) {
            allHistory.push(...history);
            consecutiveEmpty = 0;
          } else {
            consecutiveEmpty++;
          }
          if (consecutiveEmpty >= GAP_LIMIT) break;
        }
        startIndex += batchSize;
      }
    }

    const uniqueTxs = new Map<string, { height: number; fee: number }>();
    for (const h of allHistory) {
      const existing = uniqueTxs.get(h.tx_hash);
      if (!existing || h.height > 0) {
        uniqueTxs.set(h.tx_hash, { height: h.height, fee: h.fee ?? 0 });
      }
    }

    const blockTimeCache = new Map<number, number>();

    const confirmed: ConfirmedTx[] = [];
    for (const [txHash, { height, fee: historyFee }] of uniqueTxs) {
      try {
        const rawHex = await electrum.getTransaction(txHash);
        const tx = Transaction.fromRaw(Buffer.from(rawHex, "hex"), { allowUnknownOutputs: true });

        let amount = 0n;
        let totalIn = 0n;
        let totalOut = 0n;
        const toAddresses: string[] = [];
        const fromAddresses: string[] = [];

        for (let i = 0; i < tx.outputsLength; i++) {
          const out = tx.getOutput(i);
          const outAmt = out.amount ?? 0n;
          totalOut += outAmt;
          if (out.script) {
            const outAddr = getOutputAddress(out.script, network);
            if (outAddr && walletAddresses.has(outAddr)) {
              amount += outAmt;
              fromAddresses.push(outAddr);
            } else if (outAddr) {
              toAddresses.push(outAddr);
            }
          }
        }

        for (let i = 0; i < tx.inputsLength; i++) {
          const inp = tx.getInput(i);
          if (inp.txid) {
            try {
              const prevTxId = Buffer.from(inp.txid).toString("hex");
              const prevHex = await electrum.getTransaction(prevTxId);
              const prevTx = Transaction.fromRaw(Buffer.from(prevHex, "hex"), {
                allowUnknownOutputs: true,
              });
              const prevOut = prevTx.getOutput(inp.index ?? 0);
              const prevAmt = prevOut.amount ?? 0n;
              totalIn += prevAmt;
              if (prevOut.script) {
                const prevAddr = getOutputAddress(prevOut.script, network);
                if (prevAddr && walletAddresses.has(prevAddr)) {
                  amount -= prevAmt;
                }
              }
            } catch {
              // skip if we can't resolve the input
            }
          }
        }

        // Compute fee from transaction data: totalInputs - totalOutputs
        // Reference: libnunchuk FillSendReceiveData (walletdb.cpp:1216-1233)
        // recalculates fee from inputs/outputs for send transactions.
        // Electrum's get_history only returns fee for unconfirmed txs.
        const fee = totalIn > 0n ? Number(totalIn - totalOut) : historyFee;

        let blocktime = 0;
        if (height > 0) {
          if (blockTimeCache.has(height)) {
            blocktime = blockTimeCache.get(height)!;
          } else {
            try {
              const headerHex = await electrum.getBlockHeader(height);
              blocktime = parseBlockTime(headerHex);
              blockTimeCache.set(height, blocktime);
            } catch {
              // blocktime stays 0
            }
          }
        }

        const confirmations = height > 0 ? tipHeight - height + 1 : 0;
        const isSend = amount < 0n;
        const addresses = isSend ? toAddresses : fromAddresses;

        confirmed.push({ txHash, height, fee, amount, blocktime, confirmations, addresses });
      } catch {
        confirmed.push({
          txHash,
          height,
          fee: historyFee,
          amount: 0n,
          blocktime: 0,
          confirmations: 0,
          addresses: [],
        });
      }
    }

    return confirmed.sort((a, b) => b.height - a.height);
  } finally {
    electrum.close();
  }
}
