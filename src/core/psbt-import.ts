// Import an externally created PSBT into a group wallet's pending transactions.

import fs from "node:fs";
import { createHash } from "node:crypto";
import { Transaction } from "@scure/btc-signer";
import type { ApiClient } from "./api-client.js";
import type { Network } from "./config.js";
import { scriptToScripthash, type ElectrumClient } from "./electrum.js";
import {
  assertCanonicalSighashForPrevout,
  findDescriptorPathForScript,
  inputDerivationPathCandidates,
} from "./psbt-sign.js";
import type { WalletData } from "./storage.js";
import {
  combinePendingPsbt,
  fetchPendingTransactionIfExists,
  uploadTransaction,
} from "./transaction.js";

// Errors are thrown as { error, message } so the command layer can hand them
// straight to printError, the same shape ApiClient uses.
export interface PsbtImportError {
  error: string;
  message: string;
}

function importError(error: string, message: string): PsbtImportError {
  return { error, message };
}

export type PsbtImportAction = "created" | "merged" | "unchanged";

export interface PsbtImportResult {
  txId: string;
  action: PsbtImportAction;
  // The PSBT now held by the group server (canonical base64).
  psbtB64: string;
  updated: boolean;
  // Non-fatal conditions worth telling the user about (e.g. chain unreachable).
  warnings: string[];
}

export interface PsbtOwnershipProblem {
  inputIndex: number;
  outpoint: string;
  reason: string;
}

const PSBT_MAGIC = Buffer.from("70736274ff", "hex");
const BASE64_PSBT_PREFIX = "cHNidP8";

// -- Input decoding --------------------------------------------------------

// Accept a binary .psbt file, base64 text, or hex text. Detection is by content, not
// file extension. Returns base64.
export function normalizePsbtInput(content: Buffer): string {
  if (content.subarray(0, PSBT_MAGIC.length).equals(PSBT_MAGIC)) {
    return content.toString("base64");
  }

  // Text formats: tolerate surrounding whitespace and line-wrapped base64.
  const text = content.toString("utf8").replace(/\s+/g, "");
  if (text.length === 0) {
    throw importError("INVALID_PSBT", "File is empty");
  }

  if (/^[0-9a-fA-F]+$/.test(text) && text.length % 2 === 0) {
    const lower = text.toLowerCase();
    if (lower.startsWith("70736274ff")) {
      return Buffer.from(lower, "hex").toString("base64");
    }
    if (lower.startsWith("01000000") || lower.startsWith("02000000")) {
      throw importError(
        "RAW_TX_NOT_SUPPORTED",
        "File contains a raw transaction, not a PSBT. A fully signed raw transaction should be broadcast, not imported.",
      );
    }
    throw importError("INVALID_PSBT", "File is hex but does not start with the PSBT magic bytes");
  }

  if (text.startsWith(BASE64_PSBT_PREFIX)) {
    const decoded = Buffer.from(text, "base64");
    if (decoded.subarray(0, PSBT_MAGIC.length).equals(PSBT_MAGIC)) {
      return decoded.toString("base64");
    }
  }

  throw importError(
    "INVALID_PSBT",
    "File is not a PSBT (expected a binary .psbt file, base64 text, or hex text)",
  );
}

export function readPsbtFile(filePath: string): string {
  let content: Buffer;
  try {
    content = fs.readFileSync(filePath);
  } catch {
    throw importError("FILE_NOT_FOUND", `Could not read file: ${filePath}`);
  }
  return normalizePsbtInput(content);
}

export function parsePsbt(psbtB64: string): Transaction {
  let tx: Transaction;
  try {
    tx = Transaction.fromPSBT(Buffer.from(psbtB64, "base64"), { allowUnknown: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw importError("INVALID_PSBT", `Failed to decode PSBT: ${message}`);
  }
  // libnunchuk's embedded Bitcoin Core only reads PSBT v0 (PSBT_HIGHEST_VERSION = 0),
  // so a v2 upload would be unreadable on every device. @scure re-emits the parsed
  // version from toPSBT() and cannot downgrade, so refuse up front.
  if (tx.opts.PSBTVersion !== 0) {
    throw importError(
      "INVALID_PSBT",
      `PSBT version ${tx.opts.PSBTVersion} is not supported by Nunchuk apps; export the transaction as PSBT v0`,
    );
  }
  if (tx.inputsLength === 0 || tx.outputsLength === 0) {
    throw importError("INVALID_PSBT", "PSBT has no inputs or no outputs");
  }
  return tx;
}

// -- Transaction id ---------------------------------------------------------

// Hash of the PSBT's global unsigned transaction, which is the id every Nunchuk
// device uses on the group server. Not tx.id: that includes finalScriptSig once the
// PSBT is finalized, so it diverges from the unsigned txid for LEGACY / NESTED_SEGWIT.
export function getPsbtTxId(tx: Transaction): string {
  const sha256 = (data: Uint8Array) => createHash("sha256").update(data).digest();
  return Buffer.from(sha256(sha256(tx.unsignedTx)).reverse()).toString("hex");
}

// -- Input resolution --------------------------------------------------------

export interface ResolvedInput {
  inputIndex: number;
  outpoint: string;
  prevTxId: string;
  prevVout: number;
  script: Uint8Array | null;
  // Amount the PSBT (or the chain) claims for the spent output; null when unknown.
  amount: bigint | null;
}

function inputOutpoint(
  tx: Transaction,
  inputIndex: number,
): { prevTxId: string; prevVout: number } {
  const input = tx.getInput(inputIndex);
  return {
    prevTxId: input.txid ? Buffer.from(input.txid).toString("hex") : "",
    prevVout: input.index ?? 0,
  };
}

// Resolve each input's previous output script: from witnessUtxo, else from the
// embedded nonWitnessUtxo, else by fetching the previous transaction from Electrum.
export async function resolvePsbtInputScripts(
  tx: Transaction,
  electrum: ElectrumClient | null,
): Promise<ResolvedInput[]> {
  const resolved: ResolvedInput[] = [];
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    const { prevTxId, prevVout } = inputOutpoint(tx, i);
    let script: Uint8Array | null = input.witnessUtxo?.script ?? null;
    let amount: bigint | null = input.witnessUtxo?.amount ?? null;
    if (!script && input.nonWitnessUtxo) {
      // The parser has already checked that nonWitnessUtxo hashes to the input's txid.
      const prevOut = input.nonWitnessUtxo.outputs[prevVout];
      script = prevOut?.script ?? null;
      amount = prevOut?.amount ?? null;
    }
    resolved.push({
      inputIndex: i,
      outpoint: `${prevTxId}:${prevVout}`,
      prevTxId,
      prevVout,
      script,
      amount,
    });
  }

  const missing = resolved.filter((r) => !r.script && r.prevTxId);
  if (missing.length > 0 && electrum) {
    const prevTxIds = [...new Set(missing.map((r) => r.prevTxId))];
    let rawTxs: string[];
    try {
      rawTxs = await electrum.getTransactionBatch(prevTxIds);
    } catch {
      rawTxs = [];
    }
    const rawByTxId = new Map<string, string>();
    prevTxIds.forEach((txId, idx) => {
      if (rawTxs[idx]) rawByTxId.set(txId, rawTxs[idx]);
    });
    for (const entry of missing) {
      const raw = rawByTxId.get(entry.prevTxId);
      if (!raw) continue;
      try {
        const prevTx = Transaction.fromRaw(Buffer.from(raw, "hex"), { allowUnknownOutputs: true });
        // Only trust a transaction that actually hashes to the outpoint we asked for.
        if (prevTx.id !== entry.prevTxId) continue;
        const prevOut = prevTx.getOutput(entry.prevVout);
        entry.script = prevOut.script ?? null;
        entry.amount = prevOut.amount ?? null;
      } catch {
        // leave unresolved; reported by the ownership check
      }
    }
  }

  return resolved;
}

// -- Ownership -------------------------------------------------------------------

// Every input must be spendable by the wallet descriptor: the upload goes to a server
// shared by every member's device, so a wrong-wallet PSBT is rejected before it leaves.
export function checkPsbtInputsBelongToWallet(
  tx: Transaction,
  inputs: ResolvedInput[],
  wallet: WalletData,
  network: Network,
): PsbtOwnershipProblem[] {
  const problems: PsbtOwnershipProblem[] = [];
  for (const entry of inputs) {
    if (!entry.script) {
      problems.push({
        inputIndex: entry.inputIndex,
        outpoint: entry.outpoint,
        reason:
          "previous output could not be resolved (PSBT has no witnessUtxo/nonWitnessUtxo and the chain was unavailable)",
      });
      continue;
    }
    const candidates = inputDerivationPathCandidates(tx.getInput(entry.inputIndex));
    const path = findDescriptorPathForScript(entry.script, candidates, wallet.descriptor, network);
    if (!path) {
      problems.push({
        inputIndex: entry.inputIndex,
        outpoint: entry.outpoint,
        reason: `not an address of wallet ${wallet.walletId}`,
      });
    }
  }
  return problems;
}

// -- Sighash ---------------------------------------------------------------------

// A non-canonical sighash flag (NONE, SINGLE, ANYONECANPAY) would let a co-signer's
// signature authorize a different transaction than the one they reviewed. The CLI's own
// signer refuses such inputs; importing one would push it to every other device.
export function checkPsbtInputSighashes(tx: Transaction, inputs: ResolvedInput[]): string[] {
  const problems: string[] = [];
  for (const entry of inputs) {
    if (!entry.script) continue;
    try {
      assertCanonicalSighashForPrevout(tx, entry.inputIndex, entry.script);
    } catch (err) {
      problems.push(err instanceof Error ? err.message : String(err));
    }
  }
  return problems;
}

// -- Spent check -------------------------------------------------------------------

export interface PsbtInputChainCheck {
  // Outpoints that are no longer unspent (broadcast, replaced, or conflicting).
  spent: string[];
  // Outpoints whose PSBT-claimed amount differs from the chain's.
  amountMismatch: string[];
}

// Verify each input against the chain: the outpoint must still be unspent *for the
// script the PSBT claims* (so a forged witnessUtxo cannot pass the ownership check),
// and the claimed amount must match (so the displayed fee is honest). Returns null when
// the chain could not be queried. Checking inputs rather than looking the txId up
// on-chain also works for LEGACY / NESTED_SEGWIT wallets, where the broadcast txid
// differs from the unsigned one.
export async function checkPsbtInputsOnChain(
  inputs: ResolvedInput[],
  electrum: ElectrumClient,
): Promise<PsbtInputChainCheck | null> {
  const withScript = inputs.filter((r): r is ResolvedInput & { script: Uint8Array } =>
    Boolean(r.script),
  );
  if (withScript.length === 0) {
    return null;
  }
  const scripthashes = [...new Set(withScript.map((r) => scriptToScripthash(r.script)))];
  let unspentLists: Array<Array<{ tx_hash: string; tx_pos: number; value: number }>>;
  try {
    unspentLists = await electrum.listUnspentBatch(scripthashes);
  } catch {
    return null;
  }
  // outpoint → (scripthash it pays to, value) as reported by the chain
  const unspent = new Map<string, { scripthash: string; value: bigint }>();
  scripthashes.forEach((scripthash, idx) => {
    for (const item of unspentLists[idx] ?? []) {
      unspent.set(`${item.tx_hash}:${item.tx_pos}`, { scripthash, value: BigInt(item.value) });
    }
  });

  const spent: string[] = [];
  const amountMismatch: string[] = [];
  for (const entry of withScript) {
    const found = unspent.get(entry.outpoint);
    if (!found || found.scripthash !== scriptToScripthash(entry.script)) {
      spent.push(entry.outpoint);
      continue;
    }
    if (entry.amount !== null && entry.amount !== found.value) {
      amountMismatch.push(
        `${entry.outpoint} (PSBT says ${entry.amount} sat, chain says ${found.value} sat)`,
      );
    }
  }
  return { spent, amountMismatch };
}

// -- Orchestrator -------------------------------------------------------------------

export interface ImportPsbtParams {
  client: ApiClient;
  wallet: WalletData;
  network: Network;
  psbtB64: string;
  // null when Electrum could not be reached; ownership then relies on PSBT UTXO data
  // and the spent check is skipped with a warning.
  electrum: ElectrumClient | null;
}

export async function importPsbt(params: ImportPsbtParams): Promise<PsbtImportResult> {
  const { client, wallet, network, electrum } = params;
  const warnings: string[] = [];

  const tx = parsePsbt(params.psbtB64);
  const txId = getPsbtTxId(tx);
  // Canonical re-encoding, same as tx sign / combinePendingPsbt.
  const psbtB64 = Buffer.from(tx.toPSBT()).toString("base64");

  const inputs = await resolvePsbtInputScripts(tx, electrum);
  const problems = checkPsbtInputsBelongToWallet(tx, inputs, wallet, network);
  if (problems.length > 0) {
    const detail = problems
      .map((p) => `input ${p.inputIndex}: ${p.outpoint} ${p.reason}`)
      .join("; ");
    throw importError(
      "PSBT_WALLET_MISMATCH",
      `PSBT does not belong to wallet ${wallet.walletId} (${detail})`,
    );
  }

  const sighashProblems = checkPsbtInputSighashes(tx, inputs);
  if (sighashProblems.length > 0) {
    throw importError("PSBT_INVALID_SIGHASH", sighashProblems.join("; "));
  }

  if (electrum) {
    const chain = await checkPsbtInputsOnChain(inputs, electrum);
    if (chain === null) {
      warnings.push("Could not verify inputs against the chain; skipped the spent-input check.");
    } else if (chain.spent.length > 0) {
      throw importError(
        "PSBT_INPUTS_SPENT",
        `Inputs are not unspent outputs of this wallet (transaction broadcast, replaced, conflicting, or forged UTXO data): ${chain.spent.join(", ")}`,
      );
    } else if (chain.amountMismatch.length > 0) {
      throw importError(
        "PSBT_INPUT_AMOUNT_MISMATCH",
        `PSBT input amounts do not match the chain: ${chain.amountMismatch.join(", ")}`,
      );
    }
  } else {
    warnings.push("Chain unavailable; skipped the spent-input check.");
  }

  const existing = await fetchPendingTransactionIfExists(client, wallet, txId);
  if (!existing) {
    await uploadTransaction(client, wallet, psbtB64, txId);
    return { txId, action: "created", psbtB64, updated: true, warnings };
  }

  let merged;
  try {
    merged = combinePendingPsbt(existing.psbt, psbtB64);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw importError(
      "PSBT_COMBINE_FAILED",
      `Failed to combine with pending transaction: ${message}`,
    );
  }

  if (!merged.changed) {
    return { txId, action: "unchanged", psbtB64: merged.psbtB64, updated: false, warnings };
  }
  await uploadTransaction(client, wallet, merged.psbtB64, txId);
  return { txId, action: "merged", psbtB64: merged.psbtB64, updated: true, warnings };
}
