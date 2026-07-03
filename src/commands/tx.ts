import { Command, InvalidArgumentError } from "commander";
import { Transaction } from "@scure/btc-signer";
import {
  requireApiKey,
  requireEmail,
  getNetwork,
  getElectrumServer,
  loadConfig,
  getDefaultFeeLevel,
  isFeeLevel,
  DEFAULT_FEE_LEVEL,
  FEE_LEVELS,
} from "../core/config.js";
import type { FeeLevel, Network } from "../core/config.js";
import { estimateFeeRateLevels } from "../core/fees.js";
import { ApiClient } from "../core/api-client.js";
import { ElectrumClient, addressToScripthash, parseBlockTime } from "../core/electrum.js";
import { deriveDescriptorAddresses } from "../core/address.js";
import { loadWallet, removeMusigNonce } from "../core/storage.js";
import type { WalletData } from "../core/storage.js";
import { getLockedOutpoints } from "../core/coin-store.js";
import { reconcileNewCoins } from "../core/coin-rules.js";
import { getOutpointsByTag } from "../core/tag-store.js";
import { secretOpen } from "../core/crypto.js";
import { hashMessage } from "../core/wallet-keys.js";
import { resolveSignerKeys } from "../core/signer-key.js";
import { hasWalletSignerSignedPsbt, signWalletPsbtWithKey } from "../core/psbt-sign.js";
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
  createWalletOutputClassifier,
  decodePsbtDetail,
  fetchConfirmedTransactions,
  fetchPendingTxInputTimelockMetadataBatch,
  fetchPsbtInputTimelockMetadata,
  ServerTxResponse,
  type PendingTx,
  type PendingTxDetail,
  type WalletOutputClassifier,
  type PendingTxInputTimelockMetadata,
} from "../core/transaction.js";
import {
  formatBtc,
  formatSats,
  formatDate,
  getOutputAddress,
  statusFromHeight,
} from "../core/format.js";
import {
  convertAmount,
  convertAmountInputToSats,
  fetchMarketRates,
  formatAmount,
  normalizeCurrency,
  type MarketRates,
} from "../core/currency.js";
import { print, printError } from "../output.js";

function parseMiniscriptPathOption(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new InvalidArgumentError("--miniscript-path must be a non-negative integer");
  }
  return parsed;
}

// Parse --fee-rate as a decimal sat/vB and convert to integer sat/kvB (CFeeRate
// unit), rounding to the nearest sat/kvB. So 1.5 sat/vB → 1500, 12 → 12000.
function parseFeeRateOption(value: string): bigint {
  const satPerVb = Number(value);
  if (!Number.isFinite(satPerVb) || satPerVb <= 0) {
    throw new InvalidArgumentError("--fee-rate must be a positive number in sat/vB (e.g. 1.5)");
  }
  const satPerKvB = BigInt(Math.round(satPerVb * 1000));
  if (satPerKvB <= 0n) {
    throw new InvalidArgumentError("--fee-rate is too small (rounds to 0)");
  }
  return satPerKvB;
}

// Render a sat/kvB rate as sat/vB for display, trimming trailing zeros
// (1500 → "1.5", 12000 → "12", 1235 → "1.235").
function formatFeeRateSatPerVb(satPerKvB: bigint): string {
  const whole = satPerKvB / 1000n;
  const frac = (satPerKvB % 1000n).toString().padStart(3, "0").replace(/0+$/, "");
  return frac.length > 0 ? `${whole}.${frac}` : whole.toString();
}

function parseFeeLevelOption(value: string): FeeLevel {
  if (!isFeeLevel(value)) {
    throw new InvalidArgumentError(`--fee-level must be one of: ${FEE_LEVELS.join(", ")}`);
  }
  return value;
}

// Parse a repeatable --coin <txid:vout> into a preset outpoint list.
function parseCoinOption(
  value: string,
  previous: Array<{ txid: string; vout: number }>,
): Array<{ txid: string; vout: number }> {
  const match = /^([0-9a-fA-F]{64}):(\d+)$/.exec(value);
  if (!match) {
    throw new InvalidArgumentError(
      "--coin must be <txid>:<vout> (64-character hex transaction ID, then the output index)",
    );
  }
  return [...previous, { txid: match[1].toLowerCase(), vout: Number(match[2]) }];
}

// Resolve the recipient amount for `tx create` / `tx draft`. With --send-all the
// engine sweeps the whole balance, so no amount is needed (and any --amount is
// ignored with a warning). Otherwise exactly one --amount is required, converted
// from its --currency to sats.
async function resolveSendAmount(
  options: { amount?: string; currency?: string },
  sendAll: boolean,
): Promise<bigint> {
  if (sendAll) {
    if (options.amount != null) {
      console.error("Warning: --amount is ignored when --send-all is set.");
    }
    return 0n; // ignored by createTransaction when sendAll is true
  }
  if (options.amount == null) {
    throw new Error("Provide --amount, or use --send-all to send the entire balance.");
  }
  const currency = options.currency ? normalizeCurrency(options.currency) : "sat";
  const rates = currency === "sat" || currency === "BTC" ? undefined : await fetchMarketRates();
  const sendAmount = convertAmountInputToSats(options.amount, currency, rates);
  if (sendAmount <= 0n) {
    throw new Error("Amount must convert to at least 1 sat");
  }
  return sendAmount;
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

function printMiniscriptPathsSummary(
  miniscriptPaths: PendingTxDetail["miniscriptPaths"],
  selectedIndex?: number,
  indent = "  ",
): void {
  if (!miniscriptPaths || miniscriptPaths.length === 0) {
    return;
  }

  console.log(`${indent}Miniscript satisfaction paths:`);
  for (const path of miniscriptPaths) {
    const labels: string[] = [path.status];
    if (selectedIndex === path.index) {
      labels.unshift("selected");
    }
    const lock =
      path.lockTime > 0
        ? ` locktime=${path.lockTime}`
        : path.sequence > 0
          ? ` sequence=${path.sequence}`
          : "";
    const preimages =
      path.preimageRequirements.length > 0
        ? ` preimages=${path.preimageRequirements.map(formatMiniscriptPreimageRequirement).join(",")}`
        : "";
    console.log(
      `${indent}  #${path.index} ${labels.join(",")} signatures=${path.signedCount}/${path.requiredSignatures}${lock}${preimages}`,
    );
    console.log(
      `${indent}     Signers: ${path.signerNames.length > 0 ? path.signerNames.join(", ") : "(none)"}`,
    );
  }
}

function printTimelockSummary(
  timelockedUntil:
    | {
        based: string;
        mature: boolean | null;
        value: number | null;
      }
    | undefined,
  indent = "  ",
): void {
  if (!timelockedUntil || timelockedUntil.based === "NONE") {
    return;
  }

  const target =
    timelockedUntil.value == null
      ? "undetermined"
      : timelockedUntil.based === "TIME_LOCK"
        ? `${timelockedUntil.value} (${formatDate(timelockedUntil.value)})`
        : String(timelockedUntil.value);
  const state =
    timelockedUntil.mature == null ? "undetermined" : timelockedUntil.mature ? "mature" : "pending";
  console.log(`${indent}Timelock: ${state} ${timelockedUntil.based} until ${target}`);
}

function printProgressMap(
  label: string,
  values: Record<string, boolean> | undefined,
  indent = "  ",
): void {
  const entries = Object.entries(values ?? {});
  if (entries.length === 0) {
    return;
  }

  const formatted = entries.map(([xfp, done]) => `${xfp} ${done ? "✓" : "✗"}`).join("  ");
  console.log(`${indent}${label}: ${formatted}`);
}

function printKeysets(keysets: PendingTxDetail["keysets"], indent = "  "): void {
  if (!keysets || keysets.length === 0) {
    return;
  }

  console.log(`${indent}Keysets:`);
  for (const keyset of keysets) {
    const label = keyset.type === "key-path" ? "key-path" : "script-path";
    console.log(
      `${indent}  ${keyset.index}: ${label} ${keyset.signers.join(" ")} -> ${keyset.status}`,
    );
    printProgressMap("Nonces", keyset.nonces, `${indent}     `);
    printProgressMap("Signatures", keyset.signatures, `${indent}     `);
  }
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

interface DecodedPendingTx {
  tx: PendingTx;
  detail: PendingTxDetail | null;
}

function decodePendingTxWithoutMetadata(
  tx: PendingTx,
  network: Network,
  wallet: WalletData,
  outputClassifier?: WalletOutputClassifier,
): DecodedPendingTx {
  return {
    tx,
    detail: decodePsbtDetail(tx.psbt, network, wallet.m, wallet.signers, wallet.descriptor, {
      outputClassifier,
    }),
  };
}

async function decodePendingTxsWithTimelockMetadata(
  pending: PendingTx[],
  network: Network,
  wallet: WalletData,
  classifier?: WalletOutputClassifier,
): Promise<DecodedPendingTx[]> {
  if (pending.length === 0) {
    return [];
  }

  const outputClassifier = classifier ?? createWalletOutputClassifier(network, wallet.descriptor);
  const server = getElectrumServer(network);
  const electrum = new ElectrumClient();
  let currentHeight: number | undefined;
  let currentUnixTime: number | undefined;

  try {
    await electrum.connect(server.host, server.port, server.protocol);
    await electrum.serverVersion("nunchuk-cli", "1.4");
    const tip = await electrum.headersSubscribe();
    currentHeight = tip.height;
    currentUnixTime = parseBlockTime(tip.hex);

    let metadataByTxId = new Map<string, PendingTxInputTimelockMetadata[]>();
    try {
      metadataByTxId = await fetchPendingTxInputTimelockMetadataBatch(pending, electrum, network);
    } catch {
      metadataByTxId = new Map();
    }

    const decoded: DecodedPendingTx[] = [];
    for (const tx of pending) {
      decoded.push({
        tx,
        detail: decodePsbtDetail(tx.psbt, network, wallet.m, wallet.signers, wallet.descriptor, {
          currentHeight,
          currentUnixTime,
          inputUtxos: metadataByTxId.get(tx.txId),
          outputClassifier,
        }),
      });
    }
    return decoded;
  } catch {
    return pending.map((tx) =>
      decodePendingTxWithoutMetadata(tx, network, wallet, outputClassifier),
    );
  } finally {
    electrum.close();
  }
}

async function decodePsbtDetailWithTimelockMetadata(
  psbtB64: string,
  network: Network,
  wallet: WalletData,
  electrum: ElectrumClient,
): Promise<PendingTxDetail | null> {
  let currentHeight: number | undefined;
  let currentUnixTime: number | undefined;

  try {
    const tip = await electrum.headersSubscribe();
    currentHeight = tip.height;
    currentUnixTime = parseBlockTime(tip.hex);
  } catch {
    return decodePsbtDetail(psbtB64, network, wallet.m, wallet.signers, wallet.descriptor);
  }

  let inputUtxos: PendingTxInputTimelockMetadata[] | undefined;
  try {
    inputUtxos = await fetchPsbtInputTimelockMetadata(psbtB64, electrum, network);
  } catch {
    inputUtxos = undefined;
  }

  return decodePsbtDetail(psbtB64, network, wallet.m, wallet.signers, wallet.descriptor, {
    currentHeight,
    currentUnixTime,
    inputUtxos,
  });
}

async function decodePsbtDetailBestEffort(
  psbtB64: string,
  network: Network,
  wallet: WalletData,
): Promise<PendingTxDetail | null> {
  const server = getElectrumServer(network);
  const electrum = new ElectrumClient();
  try {
    await electrum.connect(server.host, server.port, server.protocol);
    await electrum.serverVersion("nunchuk-cli", "1.4");
    return await decodePsbtDetailWithTimelockMetadata(psbtB64, network, wallet, electrum);
  } catch {
    return decodePsbtDetail(psbtB64, network, wallet.m, wallet.signers, wallet.descriptor);
  } finally {
    electrum.close();
  }
}

export const txCommand = new Command("tx").description("Create, sign, and broadcast transactions");

// tx create — Build PSBT locally, upload to group server
// Reference: NunchukImpl::CreateTransaction (nunchukimpl.cpp:1145-1207)
txCommand
  .command("create")
  .description("Create a new transaction")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--to <address>", "Recipient address")
  .option("--amount <value>", "Amount to send (required unless --send-all)")
  .option(
    "--send-all",
    "Send the entire wallet balance (the fee is subtracted from the amount; overrides --amount)",
  )
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
  .option(
    "--taproot-script-path",
    "Spend a taproot wallet through its script path; key path is the default when available",
  )
  .option(
    "--fee-rate <sat/vB>",
    "Manual fee rate in sat/vB (default: auto-estimate)",
    parseFeeRateOption,
  )
  .option(
    "--fee-level <level>",
    `Fee level for auto-estimate: ${FEE_LEVELS.join(", ")} (overrides saved default; ignored with --fee-rate)`,
    parseFeeLevelOption,
  )
  .option(
    "--anti-fee-sniping",
    "Pin nLockTime to the current block height (a spending path's own locktime takes precedence)",
  )
  .option(
    "--subtract-fee",
    "Subtract the network fee from the amount so the recipient receives amount minus fee",
  )
  .option(
    "--coin <txid:vout>",
    "Spend exactly this coin; repeat to select multiple (manual coin selection)",
    parseCoinOption,
    [] as Array<{ txid: string; vout: number }>,
  )
  .option(
    "--from-tag <name>",
    "Restrict automatic coin selection to coins carrying this tag (case-sensitive)",
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

        const sendAll = Boolean(options.sendAll);
        const sendAmount = await resolveSendAmount(options, sendAll);
        // Effective fee level for the auto-estimate: one-shot --fee-level wins,
        // else the account's saved default, else the built-in default (economy).
        const feeLevel =
          options.feeLevel ?? getDefaultFeeLevel(loadConfig(), email) ?? DEFAULT_FEE_LEVEL;

        const result = await createTransaction({
          wallet,
          network,
          electrum,
          toAddress: options.to,
          amount: sendAmount,
          sendAll,
          miniscriptPath: options.miniscriptPath,
          taprootScriptPath: options.taprootScriptPath,
          preimages: options.preimage,
          // Manual fee rate (sat/kvB) when --fee-rate is given; else auto-estimate.
          feeRateSatPerKvB: options.feeRate,
          feeLevel,
          antiFeeSniping: Boolean(options.antiFeeSniping),
          subtractFeeFromAmount: Boolean(options.subtractFee),
          presetCoins: options.coin,
          // Reconcile coin-control state against the scan (first-seen collection
          // rules can lock a coin), then hand back the fresh locked set.
          reconcileScan: (scanned) => {
            reconcileNewCoins(email, network, wallet.walletId, scanned);
            return { lockedOutpoints: getLockedOutpoints(email, network, wallet.walletId) };
          },
          fromTag: options.fromTag
            ? getOutpointsByTag(email, network, wallet.walletId, options.fromTag)
            : undefined,
        });
        // Under send-all there is no requested amount; the gross amount sent is
        // the swept balance (recipient + fee). recipientAmount + fee also equals
        // the requested amount in the normal subtract case, so this is uniform.
        const grossAmount = sendAll ? result.recipientAmount + result.fee : sendAmount;
        const manualSelection = options.coin.length > 0;

        await uploadTransaction(client, wallet, result.psbtB64, result.txId);
        const detail = await decodePsbtDetailWithTimelockMetadata(
          result.psbtB64,
          network,
          wallet,
          electrum,
        );

        const globals = cmd.optsWithGlobals();
        if (globals.json) {
          print(
            {
              txId: result.txId,
              feeRate: formatFeeRateSatPerVb(result.feeRateSatPerKvB),
              feeRateSatPerKvB: result.feeRateSatPerKvB.toString(),
              feeRateManual: Boolean(options.feeRate),
              feeLevel: result.feeLevel ?? null,
              antiFeeSniping: Boolean(options.antiFeeSniping),
              lockTime: result.lockTime,
              sendAll,
              coinSelection: manualSelection ? "manual" : "auto",
              inputs: result.selectedInputs.map((i) => ({
                txid: i.txid,
                vout: i.vout,
                amount: i.value.toString(),
              })),
              subtractFee: result.subtractFee,
              amount: grossAmount.toString(),
              recipientAmount: result.recipientAmount.toString(),
              fee: result.fee.toString(),
              feeBtc: formatBtc(result.fee),
              changeAddress: result.changeAddress,
              miniscriptPath: result.miniscriptPath ?? detail?.miniscriptPath,
              miniscriptPaths: detail?.miniscriptPaths,
              timelockedUntil: detail?.timelockedUntil,
            },
            cmd,
          );
          return;
        }

        console.log("Transaction created and uploaded to group server.");
        console.log(`  Transaction ID: ${result.txId}`);
        console.log(
          `  Fee rate: ${formatFeeRateSatPerVb(result.feeRateSatPerKvB)} sat/vB${
            options.feeRate ? " (manual)" : result.feeLevel ? ` (${result.feeLevel})` : ""
          }`,
        );
        console.log(`  Fee: ${formatBtc(result.fee)} (${formatSats(result.fee)})`);
        console.log(`  Recipient: ${options.to}`);
        console.log(
          `  Amount: ${formatBtc(grossAmount)} (${formatSats(grossAmount)})${
            sendAll ? " (send all)" : ""
          }`,
        );
        if (result.subtractFee) {
          console.log(
            `  Recipient receives: ${formatBtc(result.recipientAmount)} (${formatSats(
              result.recipientAmount,
            )})`,
          );
        }
        if (result.changeAddress) {
          console.log(`  Change: ${result.changeAddress}`);
        }
        if (manualSelection) {
          console.log(`  Coins: ${result.selectedInputs.length} selected manually`);
          for (const i of result.selectedInputs) {
            console.log(`    ${i.txid}:${i.vout} (${formatSats(i.value)})`);
          }
        }
        if (options.antiFeeSniping) {
          console.log(`  Anti-fee sniping: locktime ${result.lockTime}`);
        }
        const selectedMiniscriptPath = result.miniscriptPath ?? detail?.miniscriptPath;
        printMiniscriptPathSummary(selectedMiniscriptPath);
        printMiniscriptPathsSummary(detail?.miniscriptPaths, selectedMiniscriptPath?.index);
        printTimelockSummary(detail?.timelockedUntil);
        console.log(
          `\nSign with: nunchuk tx sign --wallet ${options.wallet} --tx-id ${result.txId}`,
        );
      } finally {
        electrum.close();
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

// tx draft — Build the same PSBT as `tx create` and show the confirm screen,
// without uploading anything. Mirrors libnunchuk DraftTransaction.
txCommand
  .command("draft")
  .description("Preview a transaction (fee, total, change, input coins) without creating it")
  .requiredOption("--wallet <wallet-id>", "Wallet ID")
  .requiredOption("--to <address>", "Recipient address")
  .option("--amount <value>", "Amount to send (required unless --send-all)")
  .option(
    "--send-all",
    "Send the entire wallet balance (the fee is subtracted from the amount; overrides --amount)",
  )
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
  .option(
    "--taproot-script-path",
    "Spend a taproot wallet through its script path; key path is the default when available",
  )
  .option(
    "--fee-rate <sat/vB>",
    "Manual fee rate in sat/vB (default: auto-estimate)",
    parseFeeRateOption,
  )
  .option(
    "--fee-level <level>",
    `Fee level for auto-estimate: ${FEE_LEVELS.join(", ")} (overrides saved default; ignored with --fee-rate)`,
    parseFeeLevelOption,
  )
  .option(
    "--anti-fee-sniping",
    "Pin nLockTime to the current block height (a spending path's own locktime takes precedence)",
  )
  .option(
    "--subtract-fee",
    "Subtract the network fee from the amount so the recipient receives amount minus fee",
  )
  .option(
    "--coin <txid:vout>",
    "Spend exactly this coin; repeat to select multiple (manual coin selection)",
    parseCoinOption,
    [] as Array<{ txid: string; vout: number }>,
  )
  .option(
    "--from-tag <name>",
    "Restrict automatic coin selection to coins carrying this tag (case-sensitive)",
  )
  .option("--fiat <code>", "Show fiat values alongside BTC (e.g. --fiat USD)")
  .action(async (options, cmd) => {
    try {
      const { network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, options.wallet);
      const server = getElectrumServer(network);
      const electrum = new ElectrumClient();
      try {
        await electrum.connect(server.host, server.port, server.protocol);
        await electrum.serverVersion("nunchuk-cli", "1.4");

        const sendAll = Boolean(options.sendAll);
        const sendAmount = await resolveSendAmount(options, sendAll);

        const feeLevel =
          options.feeLevel ?? getDefaultFeeLevel(loadConfig(), email) ?? DEFAULT_FEE_LEVEL;

        // Build the transaction exactly as `tx create` would — but never upload.
        const result = await createTransaction({
          wallet,
          network,
          electrum,
          toAddress: options.to,
          amount: sendAmount,
          sendAll,
          miniscriptPath: options.miniscriptPath,
          taprootScriptPath: options.taprootScriptPath,
          preimages: options.preimage,
          feeRateSatPerKvB: options.feeRate,
          feeLevel,
          antiFeeSniping: Boolean(options.antiFeeSniping),
          subtractFeeFromAmount: Boolean(options.subtractFee),
          presetCoins: options.coin,
          // Reconcile coin-control state against the scan (first-seen collection
          // rules can lock a coin), then hand back the fresh locked set.
          reconcileScan: (scanned) => {
            reconcileNewCoins(email, network, wallet.walletId, scanned);
            return { lockedOutpoints: getLockedOutpoints(email, network, wallet.walletId) };
          },
          fromTag: options.fromTag
            ? getOutpointsByTag(email, network, wallet.walletId, options.fromTag)
            : undefined,
        });
        // Under send-all the gross amount sent is the swept balance (recipient +
        // fee); otherwise it is the requested amount.
        const grossAmount = sendAll ? result.recipientAmount + result.fee : sendAmount;
        const manualSelection = options.coin.length > 0;

        // Join selected inputs with their block date + confirmations.
        const inputMeta = await fetchPsbtInputTimelockMetadata(result.psbtB64, electrum, network);
        let tipHeight = 0;
        try {
          tipHeight = (await electrum.headersSubscribe()).height;
        } catch {
          // tip unavailable → confirmations stay 0
        }
        const metaByOutpoint = new Map(inputMeta.map((m) => [`${m.txHash}:${m.txPos}`, m]));
        const inputs = result.selectedInputs.map((i) => {
          const m = metaByOutpoint.get(`${i.txid}:${i.vout}`);
          const height = m?.height ?? 0;
          return {
            txid: i.txid,
            vout: i.vout,
            value: i.value,
            height,
            confirmations: height > 0 ? Math.max(0, tipHeight - height + 1) : 0,
            blocktime: m?.blocktime ?? 0,
          };
        });

        // Total spend on the payment side: recipient + fee (= amount + fee, or
        // just `amount` under --subtract-fee since the fee comes out of it).
        const total = result.recipientAmount + result.fee;

        // Optional fiat display.
        let fiatCode: string | null = null;
        let fiatRates: MarketRates | undefined;
        if (options.fiat) {
          const code = normalizeCurrency(options.fiat);
          if (code !== "sat" && code !== "BTC") {
            fiatCode = code;
            try {
              fiatRates = await fetchMarketRates();
            } catch {
              fiatRates = undefined;
            }
          }
        }
        const fiat = (sats: bigint): string => {
          if (!fiatCode || !fiatRates) return "";
          const v = convertAmount(Number(sats), "sat", fiatCode, fiatRates).converted;
          return ` ~ ${formatAmount(v, fiatCode)} ${fiatCode}`;
        };
        const fiatValue = (sats: bigint): string | undefined => {
          if (!fiatCode || !fiatRates) return undefined;
          return formatAmount(
            convertAmount(Number(sats), "sat", fiatCode, fiatRates).converted,
            fiatCode,
          );
        };

        const globals = cmd.optsWithGlobals();
        if (globals.json) {
          print(
            {
              recipient: options.to,
              sendAll,
              amount: grossAmount.toString(),
              amountBtc: formatBtc(grossAmount),
              recipientAmount: result.recipientAmount.toString(),
              fee: result.fee.toString(),
              feeBtc: formatBtc(result.fee),
              feeRate: formatFeeRateSatPerVb(result.feeRateSatPerKvB),
              feeRateSatPerKvB: result.feeRateSatPerKvB.toString(),
              feeRateManual: Boolean(options.feeRate),
              feeLevel: result.feeLevel ?? null,
              total: total.toString(),
              totalBtc: formatBtc(total),
              changeAddress: result.changeAddress,
              changeAmount: result.changeAmount.toString(),
              changeAmountBtc: formatBtc(result.changeAmount),
              subtractFee: result.subtractFee,
              antiFeeSniping: Boolean(options.antiFeeSniping),
              lockTime: result.lockTime,
              coinSelection: manualSelection ? "manual" : "auto",
              inputs: inputs.map((i) => ({
                txid: i.txid,
                vout: i.vout,
                amount: i.value.toString(),
                amountBtc: formatBtc(i.value),
                height: i.height,
                confirmations: i.confirmations,
                blocktime: i.blocktime,
              })),
              miniscriptPath: result.miniscriptPath,
              fiat:
                fiatCode && fiatRates
                  ? {
                      code: fiatCode,
                      amount: fiatValue(grossAmount),
                      fee: fiatValue(result.fee),
                      total: fiatValue(total),
                      change: fiatValue(result.changeAmount),
                    }
                  : null,
            },
            cmd,
          );
          return;
        }

        console.log("Draft transaction (not created)");
        console.log(`  Recipient: ${options.to}`);
        console.log(
          `  Amount: ${formatBtc(grossAmount)} (${formatSats(grossAmount)})${fiat(grossAmount)}${
            sendAll ? " (send all)" : ""
          }`,
        );
        if (result.subtractFee) {
          console.log(
            `  Recipient receives: ${formatBtc(result.recipientAmount)} (${formatSats(
              result.recipientAmount,
            )})${fiat(result.recipientAmount)}`,
          );
        }
        console.log(
          `  Fee rate: ${formatFeeRateSatPerVb(result.feeRateSatPerKvB)} sat/vB${
            options.feeRate ? " (manual)" : result.feeLevel ? ` (${result.feeLevel})` : ""
          }`,
        );
        console.log(
          `  Estimated fee: ${formatBtc(result.fee)} (${formatSats(result.fee)})${fiat(result.fee)}`,
        );
        console.log(`  Total amount: ${formatBtc(total)} (${formatSats(total)})${fiat(total)}`);
        if (result.changeAddress) {
          console.log(
            `  Change: ${result.changeAddress} - ${formatBtc(result.changeAmount)} (${formatSats(
              result.changeAmount,
            )})${fiat(result.changeAmount)}`,
          );
        }
        if (options.antiFeeSniping) {
          console.log(`  Anti-fee sniping: locktime ${result.lockTime}`);
        }
        console.log(`  Input coins${manualSelection ? " (selected manually)" : ""}:`);
        inputs.forEach((i) => {
          const date = i.blocktime > 0 ? formatDate(i.blocktime) : "unconfirmed";
          console.log(
            `    ${i.txid}:${i.vout}  ${formatBtc(i.value)} (${formatSats(i.value)})${fiat(
              i.value,
            )}  ${date} (${i.confirmations} confs)`,
          );
        });
        if (options.fiat && fiatCode && !fiatRates) {
          console.log("  (fiat values unavailable: market rate fetch failed)");
        }
        if (!options.feeRate) {
          console.log(
            "  Note: fee is auto-estimated and may change; pass --fee-rate <sat/vB> to lock it.",
          );
        }
      } finally {
        electrum.close();
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

/** Check if a signer (by xfp) already signed input 0 of the PSBT. */
function hasSignerAlreadySigned(
  tx: Transaction,
  xfpInt: number,
  wallet: WalletData,
  network: Network,
): boolean {
  return hasWalletSignerSignedPsbt(tx, xfpInt, wallet.descriptor, network);
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
      const consumedMusigNonceIds: string[] = [];

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
        const tx = Transaction.fromPSBT(Buffer.from(String(options.psbt).trim(), "base64"), {
          allowUnknown: true,
        });
        if (hasPreimages) {
          addMiniscriptPreimagesToPsbt(tx, wallet.descriptor, options.preimage);
          didAddPreimages = true;
        }
        nextPsbtB64 = Buffer.from(tx.toPSBT()).toString("base64");
      } else {
        const tx = Transaction.fromPSBT(Buffer.from(pendingTx.psbt, "base64"), {
          allowUnknown: true,
        });
        if (wantsLocalSigning) {
          const resolved = resolveSignerKeys(options, email, network, wallet.signers);
          if ("error" in resolved) {
            printError({ error: "INVALID_PARAM", message: resolved.error }, cmd);
            return;
          }

          const toSign = resolved.matched.filter(
            (m) => !hasSignerAlreadySigned(tx, parseInt(m.signerXfp, 16), wallet, network),
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
              {
                email,
                network,
                walletId: wallet.walletId,
                txId: options.txId,
                consumedNonceIds: consumedMusigNonceIds,
              },
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
      for (const nonceId of new Set(consumedMusigNonceIds)) {
        removeMusigNonce(email, network, nonceId);
      }

      const detail = await decodePsbtDetailBestEffort(merged.psbtB64, network, wallet);
      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            txId: options.txId,
            updated: merged.changed,
            status: detail?.status ?? "PENDING_SIGNATURES",
            signatures: detail ? `${detail.signedCount}/${detail.requiredCount}` : undefined,
            miniscriptPath: detail?.miniscriptPath,
            miniscriptPaths: detail?.miniscriptPaths,
            timelockedUntil: detail?.timelockedUntil,
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
      printMiniscriptPathsSummary(detail?.miniscriptPaths, detail?.miniscriptPath?.index);
      printTimelockSummary(detail?.timelockedUntil);
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
      const tx = Transaction.fromPSBT(Buffer.from(pendingTx.psbt, "base64"), {
        allowUnknown: true,
      });
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
      const outputClassifier = createWalletOutputClassifier(network, wallet.descriptor);

      const [allPending, confirmed] = await Promise.all([
        fetchPendingTransactions(client, wallet),
        fetchConfirmedTransactions(wallet, network, outputClassifier),
      ]);

      // Dedup: filter pending txs already confirmed on-chain
      // Reference: libnunchuk uses txid as primary key in SQLite — single entry per tx
      const confirmedTxIds = new Set(confirmed.map((c) => c.txHash));
      const pending = allPending.filter((p) => !confirmedTxIds.has(p.txId));
      const decodedPending = await decodePendingTxsWithTimelockMetadata(
        pending,
        network,
        wallet,
        outputClassifier,
      );

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(
          {
            pending: decodedPending.map(({ tx, detail }) => {
              return {
                txId: tx.txId,
                status: detail?.status ?? "PENDING_SIGNATURES",
                signatures: detail ? `${detail.signedCount}/${detail.requiredCount}` : undefined,
                fee: detail?.fee,
                subAmount: detail?.subAmount,
                subAmountBtc: detail?.subAmountBtc,
                miniscriptPath: detail?.miniscriptPath,
                miniscriptPaths: detail?.miniscriptPaths,
                timelockedUntil: detail?.timelockedUntil,
                outputs: detail?.outputs,
                keysets: detail?.keysets,
                nonces: detail?.nonces,
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
        decodedPending.forEach(({ tx, detail }, i) => {
          const status = detail?.status ?? "PENDING_SIGNATURES";
          const sigInfo = detail
            ? ` (${detail.signedCount}/${detail.requiredCount} signatures)`
            : "";
          console.log(`  ${i}: ${tx.txId}`);
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
            printProgressMap("Signers", detail.signers, "     ");
            printProgressMap("Nonces", detail.nonces, "     ");
            printKeysets(detail.keysets, "     ");
            printMiniscriptPathSummary(detail.miniscriptPath, "     ");
            printMiniscriptPathsSummary(
              detail.miniscriptPaths,
              detail.miniscriptPath?.index,
              "     ",
            );
            printTimelockSummary(detail.timelockedUntil, "     ");
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
      let currentHeight: number | undefined;
      let currentUnixTime: number | undefined;
      try {
        await electrum.connect(server.host, server.port, server.protocol);
        await electrum.serverVersion("nunchuk-cli", "1.4");

        const tip = await electrum.headersSubscribe();
        currentHeight = tip.height;
        currentUnixTime = parseBlockTime(tip.hex);

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

          const outputClassifier = createWalletOutputClassifier(network, wallet.descriptor);
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
            const classification = outputClassifier.classify(addr, null);
            totalOut += amt;
            outputs.push({
              index: i,
              address: addr,
              amount: amt,
              isChange: classification.isChange,
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

          console.log(`Source: electrum (${confirmations > 0 ? "confirmed" : "pending"})`);
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
          let inputUtxos: PendingTxInputTimelockMetadata[] | undefined;
          if (parsed.psbt) {
            const metadataElectrum = new ElectrumClient();
            try {
              await metadataElectrum.connect(server.host, server.port, server.protocol);
              await metadataElectrum.serverVersion("nunchuk-cli", "1.4");
              inputUtxos = await fetchPsbtInputTimelockMetadata(
                parsed.psbt,
                metadataElectrum,
                network,
              );
            } catch {
              inputUtxos = undefined;
            } finally {
              metadataElectrum.close();
            }
          }
          const detail = parsed.psbt
            ? decodePsbtDetail(parsed.psbt, network, wallet.m, wallet.signers, wallet.descriptor, {
                currentHeight,
                currentUnixTime,
                inputUtxos,
              })
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
                miniscriptPaths: detail?.miniscriptPaths,
                timelockedUntil: detail?.timelockedUntil,
                outputs: detail?.outputs,
                keysets: detail?.keysets,
                nonces: detail?.nonces,
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
            printProgressMap("Signers", detail.signers, "");
            printProgressMap("Nonces", detail.nonces, "");
            printKeysets(detail.keysets, "");
            printMiniscriptPathSummary(detail.miniscriptPath, "");
            printMiniscriptPathsSummary(detail.miniscriptPaths, detail.miniscriptPath?.index, "");
            printTimelockSummary(detail.timelockedUntil, "");
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

txCommand
  .command("fees")
  .description("Show current recommended fee rates (priority / standard / economy)")
  .action(async (_options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);

      const server = getElectrumServer(network);
      const electrum = new ElectrumClient();
      try {
        await electrum.connect(server.host, server.port, server.protocol);
        await electrum.serverVersion("nunchuk-cli", "1.4");

        const levels = await estimateFeeRateLevels(network, electrum);
        const defaultLevel = getDefaultFeeLevel(loadConfig(), email) ?? DEFAULT_FEE_LEVEL;

        if (globals.json) {
          print(
            {
              priority: formatFeeRateSatPerVb(levels.priority),
              standard: formatFeeRateSatPerVb(levels.standard),
              economy: formatFeeRateSatPerVb(levels.economy),
              prioritySatPerKvB: levels.priority.toString(),
              standardSatPerKvB: levels.standard.toString(),
              economySatPerKvB: levels.economy.toString(),
              defaultFeeLevel: defaultLevel,
            },
            cmd,
          );
          return;
        }

        console.log("Recommended fee rates:");
        const rows: [FeeLevel, bigint][] = [
          ["priority", levels.priority],
          ["standard", levels.standard],
          ["economy", levels.economy],
        ];
        for (const [level, rate] of rows) {
          const label = level.charAt(0).toUpperCase() + level.slice(1);
          const marker = level === defaultLevel ? "  (default)" : "";
          console.log(`  ${label.padEnd(9)}${formatFeeRateSatPerVb(rate)} sat/vB${marker}`);
        }
      } finally {
        electrum.close();
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
