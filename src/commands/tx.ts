import { Command, InvalidArgumentError } from "commander";
import { Transaction } from "@scure/btc-signer";
import { requireApiKey, requireEmail, getNetwork, getElectrumServer } from "../core/config.js";
import type { Network } from "../core/config.js";
import { ApiClient } from "../core/api-client.js";
import { ElectrumClient, addressToScripthash, parseBlockTime } from "../core/electrum.js";
import { deriveDescriptorAddresses } from "../core/address.js";
import { loadWallet } from "../core/storage.js";
import type { WalletData } from "../core/storage.js";
import { secretOpen } from "../core/crypto.js";
import { hashMessage } from "../core/wallet-keys.js";
import { resolveSignerKeys } from "../core/signer-key.js";
import { signWalletPsbtWithKey } from "../core/psbt-sign.js";
import { parseDescriptor } from "../core/descriptor.js";
import { finalizeMiniscriptPsbt } from "../core/miniscript-finalize.js";
import {
  addMiniscriptPreimagesToPsbt,
  formatMiniscriptPreimageRequirement,
  type MiniscriptPreimageRequirement,
} from "../core/miniscript-preimage.js";
import {
  createTransaction,
  uploadTransaction,
  fetchPendingTransaction,
  fetchPendingTransactions,
  deleteTransaction,
  combinePendingPsbt,
  decodePsbtDetail,
  fetchConfirmedTransactions,
  ServerTxResponse,
} from "../core/transaction.js";
import {
  formatBtc,
  formatSats,
  formatDate,
  getOutputAddress,
  statusFromHeight,
} from "../core/format.js";
import { convertAmountInputToSats, fetchMarketRates, normalizeCurrency } from "../core/currency.js";
import { print, printError } from "../output.js";

function parseMiniscriptPathOption(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new InvalidArgumentError("--miniscript-path must be a non-negative integer");
  }
  return parsed;
}

function parsePreimageOption(value: string, previous: string[]): string[] {
  const next = value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return [...previous, ...next];
}

function printMiniscriptPathSummary(
  miniscriptPath:
    | {
        index: number;
        lockTime: number;
        preimageRequirements: MiniscriptPreimageRequirement[];
        requiredSignatures: number;
        sequence: number;
        signerNames: string[];
      }
    | undefined,
  indent = "  ",
): void {
  if (!miniscriptPath) {
    return;
  }

  console.log(`${indent}Miniscript path: #${miniscriptPath.index}`);
  console.log(`${indent}Required signers: ${miniscriptPath.requiredSignatures}`);
  console.log(`${indent}Locktime: ${miniscriptPath.lockTime}`);
  console.log(`${indent}Sequence: ${miniscriptPath.sequence}`);
  if (miniscriptPath.preimageRequirements.length > 0) {
    console.log(
      `${indent}Hash preimages: ${miniscriptPath.preimageRequirements.map(formatMiniscriptPreimageRequirement).join(", ")}`,
    );
  }
  console.log(
    `${indent}Path signers: ${miniscriptPath.signerNames.length > 0 ? miniscriptPath.signerNames.join(", ") : "(none)"}`,
  );
}

function getGlobals(cmd: Command): { apiKey: string; network: Network; email: string } {
  const globals = cmd.optsWithGlobals();
  return {
    apiKey: requireApiKey(globals.apiKey, globals.network),
    network: getNetwork(globals.network),
    email: requireEmail(globals.network),
  };
}

function requireWallet(email: string, network: Network, walletId: string): WalletData {
  const wallet = loadWallet(email, network, walletId);
  if (!wallet) {
    console.error(
      `Error: Wallet "${walletId}" not found locally. Run "nunchuk wallet finalize" first.`,
    );
    process.exit(1);
  }
  return wallet;
}

export const txCommand = new Command("tx").description("Create, sign, and broadcast transactions");

// tx create — Build PSBT locally, upload to group server
// Reference: NunchukImpl::CreateTransaction (nunchukimpl.cpp:1145-1207)
txCommand
  .command("create")
  .description("Create a new transaction")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--to <address>", "Recipient address")
  .requiredOption("--amount <value>", "Amount to send")
  .option(
    "--currency <code>",
    "Currency for amount (default: sat). Supports BTC, USD, and fiat codes",
  )
  .option(
    "--preimage <hex>",
    "Attach a 32-byte miniscript hash preimage (repeat or comma-separate)",
    parsePreimageOption,
    [],
  )
  .option(
    "--miniscript-path <index>",
    "Select a miniscript signing path by index",
    parseMiniscriptPathOption,
  )
  .action(async (options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const client = new ApiClient(apiKey, network);

      const server = getElectrumServer(network);
      const electrum = new ElectrumClient();
      try {
        await electrum.connect(server.host, server.port, server.protocol);
        await electrum.serverVersion("nunchuk-cli", "1.4");

        const currency = options.currency ? normalizeCurrency(options.currency) : "sat";
        const rates =
          currency === "sat" || currency === "BTC" ? undefined : await fetchMarketRates();
        const sendAmount = convertAmountInputToSats(options.amount, currency, rates);
        if (sendAmount <= 0n) {
          throw new Error("Amount must convert to at least 1 sat");
        }
        const result = await createTransaction({
          wallet,
          network,
          electrum,
          toAddress: options.to,
          amount: sendAmount,
          miniscriptPath: options.miniscriptPath,
          preimages: options.preimage,
          // Fee rate always estimated from Nunchuk API (with Electrum fallback)
        });

        await uploadTransaction(client, wallet, result.psbtB64, result.txId);

        const globals = cmd.optsWithGlobals();
        if (globals.json) {
          print(
            {
              txId: result.txId,
              feeRate: result.feePerByte.toString(),
              fee: result.fee.toString(),
              feeBtc: formatBtc(result.fee),
              changeAddress: result.changeAddress,
              miniscriptPath: result.miniscriptPath,
            },
            cmd,
          );
          return;
        }

        console.log("Transaction created and uploaded to group server.");
        console.log(`  Transaction ID: ${result.txId}`);
        console.log(`  Fee rate: ${result.feePerByte} sat/vB`);
        console.log(`  Fee: ${formatBtc(result.fee)} (${formatSats(result.fee)})`);
        console.log(`  Recipient: ${options.to}`);
        console.log(`  Amount: ${formatBtc(sendAmount)} (${formatSats(sendAmount)})`);
        if (result.changeAddress) {
          console.log(`  Change: ${result.changeAddress}`);
        }
        printMiniscriptPathSummary(result.miniscriptPath);
        console.log(
          `\nSign with: nunchuk tx sign --wallet ${options.wallet} --tx-id ${result.txId} --xprv <your-xprv>`,
        );
      } finally {
        electrum.close();
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

/** Check if a signer (by xfp) already signed input 0 of the PSBT. */
function hasSignerAlreadySigned(tx: Transaction, xfpInt: number): boolean {
  if (tx.inputsLength === 0) return false;
  const inp = tx.getInput(0);
  const partialSig = inp.partialSig as Array<[Uint8Array, Uint8Array]> | undefined;
  const bip32Derivation = inp.bip32Derivation as
    | Array<[Uint8Array, { fingerprint: number; path: number[] }]>
    | undefined;
  if (!partialSig || !bip32Derivation) return false;

  for (const [pubkey] of partialSig) {
    for (const [bip32Pub, { fingerprint }] of bip32Derivation) {
      if (fingerprint === xfpInt && Buffer.from(pubkey).equals(Buffer.from(bip32Pub))) {
        return true;
      }
    }
  }
  return false;
}

// tx sign — Sign PSBT locally, re-upload to server
// Reference: NunchukImpl::SignTransaction (nunchukimpl.cpp:1297-1371)
// Reference: SoftwareSigner::SignTx (softwaresigner.cpp:192-216)
txCommand
  .command("sign")
  .description("Sign a transaction")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--tx-id <tx-id>", "Transaction ID")
  .option("--psbt <psbt>", "Signed PSBT to merge into the current pending transaction")
  .option("--xprv <xprv>", "Extended private key for signing")
  .option("--fingerprint <xfp>", "Fingerprint of a stored key")
  .option(
    "--preimage <hex>",
    "Attach a 32-byte miniscript hash preimage (repeat or comma-separate)",
    parsePreimageOption,
    [],
  )
  .action(async (options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const client = new ApiClient(apiKey, network);

      const pendingTx = await fetchPendingTransaction(client, wallet, options.txId);
      let nextPsbtB64: string;
      const hasPreimages = Array.isArray(options.preimage) && options.preimage.length > 0;
      const hasExplicitSigner = Boolean(options.xprv || options.fingerprint);
      const wantsLocalSigning = !options.psbt && (hasExplicitSigner || !hasPreimages);
      let didAddPreimages = false;
      let didLocalSign = false;

      if (options.psbt) {
        if (options.xprv || options.fingerprint) {
          printError(
            {
              error: "INVALID_PARAM",
              message: "--psbt cannot be used with --xprv or --fingerprint",
            },
            cmd,
          );
          return;
        }
        const tx = Transaction.fromPSBT(Buffer.from(String(options.psbt).trim(), "base64"));
        if (hasPreimages) {
          addMiniscriptPreimagesToPsbt(tx, wallet.descriptor, options.preimage);
          didAddPreimages = true;
        }
        nextPsbtB64 = Buffer.from(tx.toPSBT()).toString("base64");
      } else {
        const tx = Transaction.fromPSBT(Buffer.from(pendingTx.psbt, "base64"));
        if (wantsLocalSigning) {
          const resolved = resolveSignerKeys(options, email, network, wallet.signers);
          if ("error" in resolved) {
            printError({ error: "INVALID_PARAM", message: resolved.error }, cmd);
            return;
          }

          const toSign = resolved.matched.filter(
            (m) => !hasSignerAlreadySigned(tx, parseInt(m.signerXfp, 16)),
          );

          if (toSign.length === 0 && !hasPreimages) {
            const names = resolved.matched
              .map((m) => (m.keyName ? `${m.keyName} (${m.signerXfp})` : m.signerXfp))
              .join(", ");
            printError({ error: "ALREADY_SIGNED", message: `Already signed by: ${names}` }, cmd);
            return;
          }

          for (const matched of toSign) {
            signWalletPsbtWithKey(
              tx,
              matched.signerKey,
              parseInt(matched.signerXfp, 16),
              wallet.descriptor,
            );
            didLocalSign = true;
          }
        }

        if (hasPreimages) {
          addMiniscriptPreimagesToPsbt(tx, wallet.descriptor, options.preimage);
          didAddPreimages = true;
        }
        nextPsbtB64 = Buffer.from(tx.toPSBT()).toString("base64");
      }

      let merged;
      try {
        merged = combinePendingPsbt(pendingTx.psbt, nextPsbtB64);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        printError(
          {
            error: options.psbt ? "INVALID_PARAM" : "PSBT_COMBINE_FAILED",
            message: options.psbt
              ? `Failed to combine provided PSBT: ${message}`
              : `Failed to merge signed PSBT: ${message}`,
          },
          cmd,
        );
        return;
      }

      if (merged.changed) {
        await uploadTransaction(client, wallet, merged.psbtB64, options.txId);
      }

      const detail = decodePsbtDetail(
        merged.psbtB64,
        network,
        wallet.m,
        wallet.signers,
        wallet.descriptor,
      );
      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            txId: options.txId,
            updated: merged.changed,
            status: detail?.status ?? "PENDING_SIGNATURES",
            signatures: detail ? `${detail.signedCount}/${detail.requiredCount}` : undefined,
            miniscriptPath: detail?.miniscriptPath,
          },
          cmd,
        );
        return;
      }

      const sigInfo = detail ? ` (${detail.signedCount}/${detail.requiredCount} signatures)` : "";
      if (options.psbt) {
        console.log(
          merged.changed
            ? "Transaction PSBT combined and uploaded to group server."
            : "Provided PSBT added no new data. Group server PSBT unchanged.",
        );
      } else if (didLocalSign && didAddPreimages) {
        console.log(
          merged.changed
            ? "Transaction updated with signatures and miniscript preimages and uploaded to group server."
            : "Transaction update produced no new PSBT changes.",
        );
      } else if (didAddPreimages) {
        console.log(
          merged.changed
            ? "Transaction updated with miniscript preimages and uploaded to group server."
            : "Transaction update produced no new PSBT changes.",
        );
      } else {
        console.log(
          merged.changed
            ? "Transaction signed and uploaded to group server."
            : "Transaction signed, but produced no new PSBT changes.",
        );
      }
      console.log(`  Transaction ID: ${options.txId}`);
      console.log(`  Status: ${detail?.status ?? "PENDING_SIGNATURES"}${sigInfo}`);
      printMiniscriptPathSummary(detail?.miniscriptPath);
      if (detail?.status === "READY_TO_BROADCAST") {
        console.log(
          `\nBroadcast with: nunchuk tx broadcast --wallet ${options.wallet} --tx-id ${options.txId}`,
        );
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

// tx broadcast — Finalize PSBT, broadcast via electrum, delete from server
// Reference: NunchukImpl::BroadcastTransaction (nunchukimpl.cpp:1491-1519)
txCommand
  .command("broadcast")
  .description("Broadcast a fully signed transaction")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--tx-id <tx-id>", "Transaction ID")
  .action(async (options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const client = new ApiClient(apiKey, network);

      const pendingTx = await fetchPendingTransaction(client, wallet, options.txId);
      const tx = Transaction.fromPSBT(Buffer.from(pendingTx.psbt, "base64"));
      const parsedDescriptor = parseDescriptor(wallet.descriptor);

      // If PSBT is already finalized (e.g. by mobile app), skip finalize()
      // Reference: finalize() clears partialSig and sets finalScriptWitness/finalScriptSig
      // Calling finalize() again on an already-finalized PSBT fails because partialSig is empty
      if (!tx.isFinal) {
        try {
          if (parsedDescriptor.kind === "miniscript") {
            finalizeMiniscriptPsbt(tx, wallet.descriptor, network);
          } else {
            tx.finalize();
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          if (parsedDescriptor.kind === "miniscript") {
            console.error(`Error: Failed to finalize miniscript transaction: ${msg}`);
          } else {
            console.error(`Error: Failed to finalize transaction: ${msg}`);
            console.error(`Wallet requires ${wallet.m} signatures to broadcast.`);
          }
          process.exit(1);
        }
      }

      // Weight validation — reject oversized transactions before broadcasting
      // Reference: nunchukimpl.cpp:1499-1503 checks MAX_STANDARD_TX_WEIGHT (400,000 WU)
      const MAX_STANDARD_TX_WEIGHT = 400_000;
      if (tx.weight > MAX_STANDARD_TX_WEIGHT) {
        console.error(
          `Error: Transaction weight ${tx.weight} exceeds maximum standard weight ${MAX_STANDARD_TX_WEIGHT}.`,
        );
        process.exit(1);
      }

      const rawTxHex = Buffer.from(tx.extract()).toString("hex");
      const server = getElectrumServer(network);
      const electrum = new ElectrumClient();
      let broadcastTxId: string;
      try {
        await electrum.connect(server.host, server.port, server.protocol);
        await electrum.serverVersion("nunchuk-cli", "1.4");
        broadcastTxId = await electrum.broadcast(rawTxHex);
      } finally {
        electrum.close();
      }

      try {
        await deleteTransaction(client, wallet, options.txId);
      } catch {
        // Non-fatal: tx is already broadcast even if server delete fails
      }

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print({ txId: broadcastTxId, status: "PENDING_CONFIRMATION" }, cmd);
        return;
      }

      console.log("Transaction broadcast successfully.");
      console.log(`  Transaction ID: ${broadcastTxId}`);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

txCommand
  .command("list")
  .description("List transactions for a wallet")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .action(async (options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const client = new ApiClient(apiKey, network);

      const [allPending, confirmed] = await Promise.all([
        fetchPendingTransactions(client, wallet),
        fetchConfirmedTransactions(wallet, network),
      ]);

      // Dedup: filter pending txs already confirmed on-chain
      // Reference: libnunchuk uses txid as primary key in SQLite — single entry per tx
      const confirmedTxIds = new Set(confirmed.map((c) => c.txHash));
      const pending = allPending.filter((p) => !confirmedTxIds.has(p.txId));

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            pending: pending.map((p) => {
              const detail = decodePsbtDetail(
                p.psbt,
                network,
                wallet.m,
                wallet.signers,
                wallet.descriptor,
              );
              return {
                txId: p.txId,
                status: detail?.status ?? "PENDING_SIGNATURES",
                signatures: detail ? `${detail.signedCount}/${detail.requiredCount}` : undefined,
                fee: detail?.fee,
                subAmount: detail?.subAmount,
                subAmountBtc: detail?.subAmountBtc,
                miniscriptPath: detail?.miniscriptPath,
                outputs: detail?.outputs,
                signers: detail?.signers,
              };
            }),
            confirmed: confirmed.map((c) => ({
              txHash: c.txHash,
              status: statusFromHeight(c.height),
              amount: c.amount.toString(),
              amountBtc: formatBtc(c.amount),
              ...(c.amount < 0n ? { fee: c.fee } : {}),
              blocktime: c.blocktime,
              datetime: formatDate(c.blocktime),
              confirmations: c.confirmations,
              addresses: c.addresses,
            })),
          },
          cmd,
        );
        return;
      }

      if (pending.length === 0 && confirmed.length === 0) {
        console.log("No transactions found.");
        return;
      }

      if (pending.length > 0) {
        console.log("Pending transactions (from group server):");
        pending.forEach((p, i) => {
          const detail = decodePsbtDetail(
            p.psbt,
            network,
            wallet.m,
            wallet.signers,
            wallet.descriptor,
          );
          const status = detail?.status ?? "PENDING_SIGNATURES";
          const sigInfo = detail
            ? ` (${detail.signedCount}/${detail.requiredCount} signatures)`
            : "";
          console.log(`  ${i}: ${p.txId}`);
          console.log(`     Status: ${status}${sigInfo}`);
          if (detail) {
            console.log(`     Fee: ${detail.feeBtc} (${detail.fee})`);
            console.log(`     Send: ${detail.subAmountBtc} (${detail.subAmount})`);
            detail.outputs.forEach((o, j) => {
              const changeLabel = o.isChange ? " (change)" : "";
              console.log(
                `     Output ${j}: ${o.amountBtc} (${o.amount}) -> ${o.address ?? "unknown"}${changeLabel}`,
              );
            });
            const signerEntries = Object.entries(detail.signers);
            if (signerEntries.length > 0) {
              const signerStr = signerEntries
                .map(([xfp, signed]) => `${xfp} ${signed ? "✓" : "✗"}`)
                .join("  ");
              console.log(`     Signers: ${signerStr}`);
            }
            printMiniscriptPathSummary(detail.miniscriptPath, "     ");
          }
        });
      }

      if (confirmed.length > 0) {
        if (pending.length > 0) console.log();
        console.log("Transaction history (from electrum):");
        confirmed.forEach((c, i) => {
          const dir = c.amount >= 0n ? "receive" : "send";
          console.log(`  ${i}: ${c.txHash}`);
          console.log(`     Type: ${dir}`);
          console.log(`     Amount: ${formatBtc(c.amount)} (${formatSats(c.amount)})`);
          if (dir === "send") {
            console.log(`     Fee: ${formatSats(BigInt(c.fee))}`);
          }
          console.log(`     Date: ${formatDate(c.blocktime)}`);
          console.log(`     Confirmations: ${c.confirmations}`);
          if (c.addresses.length > 0) {
            const label = dir === "send" ? "To" : "Address";
            c.addresses.forEach((a) => console.log(`     ${label}: ${a}`));
          }
        });
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

txCommand
  .command("get")
  .description("Get transaction details")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--tx-id <tx-id>", "Transaction ID")
  .action(async (options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const client = new ApiClient(apiKey, network);

      // Check electrum first — broadcast txs may still linger on group server
      const server = getElectrumServer(network);
      const electrum = new ElectrumClient();
      let foundOnChain = false;
      try {
        await electrum.connect(server.host, server.port, server.protocol);
        await electrum.serverVersion("nunchuk-cli", "1.4");

        const tip = await electrum.headersSubscribe();

        let rawHex: string;
        try {
          rawHex = await electrum.getTransaction(options.txId);
        } catch {
          rawHex = "";
        }

        if (rawHex) {
          foundOnChain = true;
          const tx = Transaction.fromRaw(Buffer.from(rawHex, "hex"), {
            allowUnknownOutputs: true,
          });

          // Derive change addresses to detect change outputs
          const changeAddrs = new Set(
            deriveDescriptorAddresses(wallet.descriptor, network, 1, 0, 20),
          );

          let totalOut = 0n;
          const outputs: Array<{
            index: number;
            address: string | null;
            amount: bigint;
            isChange: boolean;
          }> = [];
          for (let i = 0; i < tx.outputsLength; i++) {
            const out = tx.getOutput(i);
            const addr = out.script ? getOutputAddress(out.script, network) : null;
            const amt = out.amount ?? 0n;
            totalOut += amt;
            outputs.push({
              index: i,
              address: addr,
              amount: amt,
              isChange: !!addr && changeAddrs.has(addr),
            });
          }

          let totalIn = 0n;
          const inputs: Array<{
            index: number;
            prevTxId: string;
            prevVout: number;
            address: string | null;
            amount: bigint;
          }> = [];
          for (let i = 0; i < tx.inputsLength; i++) {
            const inp = tx.getInput(i);
            if (inp.txid) {
              try {
                const prevTxId = Buffer.from(inp.txid).toString("hex");
                const prevHex = await electrum.getTransaction(prevTxId);
                const prevTx = Transaction.fromRaw(Buffer.from(prevHex, "hex"), {
                  allowUnknownOutputs: true,
                });
                const vout = inp.index ?? 0;
                const prevOut = prevTx.getOutput(vout);
                const addr = prevOut.script ? getOutputAddress(prevOut.script, network) : null;
                const amt = prevOut.amount ?? 0n;
                totalIn += amt;
                inputs.push({ index: i, prevTxId, prevVout: vout, address: addr, amount: amt });
              } catch {
                inputs.push({
                  index: i,
                  prevTxId: Buffer.from(inp.txid).toString("hex"),
                  prevVout: inp.index ?? 0,
                  address: null,
                  amount: 0n,
                });
              }
            }
          }

          const fee = totalIn > 0n ? totalIn - totalOut : 0n;

          let height = 0;
          let blocktime = 0;
          // Check both receive (chain=0) and change (chain=1) addresses
          const receiveAddrs = deriveDescriptorAddresses(wallet.descriptor, network, 0, 0, 20);
          const allAddrs = [...receiveAddrs, ...changeAddrs];
          const histories = await electrum.getHistoryBatch(
            allAddrs.map((addr) => addressToScripthash(addr, network)),
          );
          for (const hist of histories) {
            const match = hist.find((h) => h.tx_hash === options.txId);
            if (match) {
              height = match.height;
              break;
            }
          }

          if (height > 0) {
            try {
              const headerHex = await electrum.getBlockHeader(height);
              blocktime = parseBlockTime(headerHex);
            } catch {
              // blocktime stays 0
            }
          }

          const confirmations = height > 0 ? tip.height - height + 1 : 0;
          const status = statusFromHeight(height);

          const globals = cmd.optsWithGlobals();
          if (globals.json) {
            print(
              {
                source: "electrum",
                txId: options.txId,
                status,
                blocktime,
                datetime: formatDate(blocktime),
                confirmations,
                fee: fee.toString(),
                feeBtc: formatBtc(fee),
                inputs: inputs.map((inp) => ({
                  prevTxId: inp.prevTxId,
                  prevVout: inp.prevVout,
                  address: inp.address,
                  amount: inp.amount.toString(),
                  amountBtc: formatBtc(inp.amount),
                })),
                outputs: outputs.map((out) => ({
                  index: out.index,
                  address: out.address,
                  amount: out.amount.toString(),
                  amountBtc: formatBtc(out.amount),
                  isChange: out.isChange,
                })),
              },
              cmd,
            );
            return;
          }

          console.log("Source: electrum (confirmed)");
          console.log(`Transaction ID: ${options.txId}`);
          console.log(`Status: ${status}`);
          console.log(`Date: ${formatDate(blocktime)}`);
          console.log(`Confirmations: ${confirmations}`);
          console.log(`Fee: ${formatBtc(fee)} (${formatSats(fee)})`);
          console.log(`Inputs (${inputs.length}):`);
          inputs.forEach((inp) => {
            console.log(
              `  ${inp.index}: ${formatBtc(inp.amount)} from ${inp.address ?? inp.prevTxId + ":" + inp.prevVout}`,
            );
          });
          console.log(`Outputs (${outputs.length}):`);
          outputs.forEach((out) => {
            const changeLabel = out.isChange ? " (change)" : "";
            console.log(
              `  ${out.index}: ${formatBtc(out.amount)} -> ${out.address ?? "unknown"}${changeLabel}`,
            );
          });
          return;
        }
      } finally {
        electrum.close();
      }

      // Fall back to group server (pending transactions not yet on-chain)
      if (!foundOnChain) {
        const secretboxKey = new Uint8Array(Buffer.from(wallet.secretboxKey, "base64"));
        const txGid = hashMessage(secretboxKey, options.txId);
        const data = await client.get<ServerTxResponse>(
          `/v1.1/shared-wallets/wallets/${wallet.gid}/transactions/${txGid}`,
        );
        if (data && data.transaction && data.transaction.data && data.transaction.data.msg) {
          const plain = secretOpen(data.transaction.data.msg, secretboxKey);
          const parsed = JSON.parse(plain);
          const detail = parsed.psbt
            ? decodePsbtDetail(parsed.psbt, network, wallet.m, wallet.signers, wallet.descriptor)
            : null;
          const status = detail?.status ?? "PENDING_SIGNATURES";

          const globals = cmd.optsWithGlobals();
          if (globals.json) {
            print(
              {
                source: "group_server",
                txId: parsed.txId || parsed.tx_id,
                status,
                signatures: detail ? `${detail.signedCount}/${detail.requiredCount}` : undefined,
                fee: detail?.fee,
                subAmount: detail?.subAmount,
                subAmountBtc: detail?.subAmountBtc,
                miniscriptPath: detail?.miniscriptPath,
                outputs: detail?.outputs,
                signers: detail?.signers,
                psbt: parsed.psbt,
              },
              cmd,
            );
            return;
          }
          const sigInfo = detail
            ? ` (${detail.signedCount}/${detail.requiredCount} signatures)`
            : "";
          console.log("Source: group server (pending)");
          console.log(`Transaction ID: ${parsed.txId || parsed.tx_id}`);
          console.log(`Status: ${status}${sigInfo}`);
          if (detail) {
            console.log(`Fee: ${detail.feeBtc} (${detail.fee})`);
            console.log(`Send: ${detail.subAmountBtc} (${detail.subAmount})`);
            console.log(`Outputs:`);
            detail.outputs.forEach((o, i) => {
              const changeLabel = o.isChange ? " (change)" : "";
              console.log(
                `  ${i}: ${o.amountBtc} (${o.amount}) -> ${o.address ?? "unknown"}${changeLabel}`,
              );
            });
            const signerEntries = Object.entries(detail.signers);
            if (signerEntries.length > 0) {
              const signerStr = signerEntries
                .map(([xfp, signed]) => `${xfp} ${signed ? "✓" : "✗"}`)
                .join("  ");
              console.log(`Signers: ${signerStr}`);
            }
            printMiniscriptPathSummary(detail.miniscriptPath, "");
          }
          if (parsed.psbt) {
            console.log(`PSBT: ${parsed.psbt}`);
          }
          return;
        }

        console.error(`Transaction ${options.txId} not found.`);
        process.exit(1);
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
