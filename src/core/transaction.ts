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
import {
  deriveAddresses,
  deriveDescriptorAddresses,
  deriveDescriptorMiniscriptKeys,
  deriveDescriptorPayment,
  deriveMultisigPayment,
} from "./address.js";
import type { WalletData } from "./storage.js";
import {
  hashMessage,
  signWalletMessage,
  encryptWalletPayload,
  decryptWalletPayload,
} from "./wallet-keys.js";
import {
  buildAnyDescriptorForParsed,
  parseDescriptor,
  parseSignerDescriptor,
} from "./descriptor.js";
import {
  getMiniscriptSpendingPlans,
  isMiniscriptPlanSatisfied,
  selectMiniscriptSpendingPlan,
  type MiniscriptSpendingPlan,
} from "./miniscript-spend.js";
import {
  addMiniscriptPreimagesToPsbt,
  getInputMiniscriptPreimages,
  miniscriptPreimageRequirementKey,
  type MiniscriptPreimageRequirement,
} from "./miniscript-preimage.js";
import { formatBtc, formatSats, getOutputAddress } from "./format.js";
import { estimateFeeRate } from "./fees.js";
import { timelockFromK, type TimelockBased } from "./miniscript.js";

const GAP_LIMIT = 20;
const MAX_BIP125_RBF_SEQUENCE = 0xfffffffd;

function deriveWalletAddresses(
  wallet: WalletData,
  network: Network,
  chain: 0 | 1,
  startIndex: number,
  count: number,
): string[] {
  return deriveDescriptorAddresses(wallet.descriptor, network, chain, startIndex, count);
}

// -- Interfaces --

export interface WalletUtxo {
  txHash: string;
  txPos: number;
  value: bigint;
  height: number;
  blocktime?: number;
  chain: 0 | 1;
  index: number;
  address: string;
}

export interface PendingTxInputTimelockMetadata {
  txHash: string;
  txPos: number;
  height: number;
  blocktime?: number;
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
  miniscriptPath?: {
    index: number;
    lockTime: number;
    preimageRequirements: MiniscriptPreimageRequirement[];
    requiredSignatures: number;
    sequence: number;
    signerNames: string[];
  };
  timelockedUntil?: {
    based: TimelockBased;
    mature: boolean | null;
    value: number | null;
  };
  fee: string;
  feeBtc: string;
  outputs: Array<{ address: string | null; amount: string; amountBtc: string; isChange: boolean }>;
  subAmount: string;
  subAmountBtc: string;
  signers: Record<string, boolean>;
}

export interface PendingTxDecodeOptions {
  currentHeight?: number;
  currentUnixTime?: number;
  inputUtxos?: PendingTxInputTimelockMetadata[];
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
  miniscriptPath?: number;
  preimages?: string[];
}

export interface CreateTransactionResult {
  psbtB64: string;
  txId: string;
  fee: bigint;
  feePerByte: bigint;
  changeAddress: string | null;
  miniscriptPath?: {
    index: number;
    lockTime: number;
    preimageRequirements: MiniscriptPreimageRequirement[];
    requiredSignatures: number;
    sequence: number;
    signerNames: string[];
  };
}

type WalletInputUpdate = Parameters<Transaction["addInput"]>[0];

interface PreparedWalletInput {
  input: WalletInputUpdate;
  payment: ReturnType<typeof deriveDescriptorPayment>;
  utxo: WalletUtxo;
}

interface PendingTxPayload {
  psbt: string;
  txId?: string;
  tx_id?: string;
}

interface MiniscriptInputSignatureState {
  signedFingerprints: Set<number>;
  signedKeyExpressions: Set<string>;
}

interface MiniscriptPlanProgress {
  ready: boolean;
  signedCount: number;
  signedFingerprints: Set<number>;
}

interface PendingTxInputOutpoint extends PendingTxInputTimelockMetadata {
  inputIndex: number;
}

function buildMiniscriptDummyWitness(
  plan: MiniscriptSpendingPlan,
  witnessScript: Uint8Array,
): Uint8Array[] {
  const stack: Uint8Array[] = [];
  const multisigLeafCount = plan.leafNodes.filter((leaf) => leaf.type === "MULTI").length;
  const placeholderLeaves =
    plan.leafNodes.length > 0 ? plan.leafNodes : [{ type: "NONE" as const }];

  for (const leaf of placeholderLeaves) {
    switch (leaf.type) {
      case "HASH160":
      case "HASH256":
      case "RIPEMD160":
      case "SHA256":
        stack.push(new Uint8Array(32));
        break;
      default:
        stack.push(new Uint8Array());
        break;
    }
  }
  for (let i = 0; i < multisigLeafCount; i++) {
    stack.push(new Uint8Array());
  }
  for (let i = 0; i < plan.requiredSignatures; i++) {
    stack.push(new Uint8Array(72));
  }

  stack.push(witnessScript);
  return stack;
}

function buildMiniscriptPathSummary(plan: MiniscriptSpendingPlan) {
  return {
    index: plan.index,
    lockTime: plan.lockTime,
    preimageRequirements: plan.preimageRequirements,
    requiredSignatures: plan.requiredSignatures,
    sequence: plan.sequence,
    signerNames: plan.signerNames,
  };
}

function hasActiveLockTime(tx: Transaction): boolean {
  if (tx.lockTime === 0) {
    return false;
  }

  for (let index = 0; index < tx.inputsLength; index++) {
    if ((tx.getInput(index).sequence ?? 0xffffffff) !== 0xffffffff) {
      return true;
    }
  }

  return false;
}

function getInputOutpoint(
  tx: Transaction,
  inputIndex: number,
): { txHash: string; txPos: number } | null {
  const input = tx.getInput(inputIndex);
  if (!input.txid) {
    return null;
  }
  return {
    txHash: Buffer.from(input.txid).toString("hex"),
    txPos: input.index ?? 0,
  };
}

function getTimelockedUntil(
  tx: Transaction,
  plan: MiniscriptSpendingPlan | null,
  options?: PendingTxDecodeOptions,
): PendingTxDetail["timelockedUntil"] {
  if (!plan || (plan.lockTime === 0 && plan.sequence === 0)) {
    return undefined;
  }

  let based: TimelockBased = "NONE";
  let mature: boolean | null = true;
  let value: number | null = 0;

  const setUnknown = (lockBased: TimelockBased): void => {
    based = lockBased;
    mature = null;
    value = null;
  };

  if (hasActiveLockTime(tx) && plan.lockTime > 0) {
    const lock = timelockFromK(true, plan.lockTime);
    based = lock.based;
    value = lock.value;
    if (lock.based === "TIME_LOCK") {
      mature = (options?.currentUnixTime ?? Math.floor(Date.now() / 1000)) >= lock.value;
    } else if (lock.based === "HEIGHT_LOCK") {
      mature = options?.currentHeight == null ? null : options.currentHeight >= lock.value;
    }
  }

  if (plan.sequence > 0) {
    const lock = timelockFromK(false, plan.sequence);
    based = lock.based;

    let maxRelativeValue = value ?? 0;
    for (let inputIndex = 0; inputIndex < tx.inputsLength; inputIndex++) {
      const outpoint = getInputOutpoint(tx, inputIndex);
      const utxo = outpoint
        ? options?.inputUtxos?.find(
            (item) => item.txHash === outpoint.txHash && item.txPos === outpoint.txPos,
          )
        : undefined;

      if (!utxo || utxo.height <= 0) {
        setUnknown(lock.based);
        return { based, mature, value };
      }

      if (lock.based === "TIME_LOCK") {
        if (!utxo.blocktime || utxo.blocktime <= 0) {
          setUnknown(lock.based);
          return { based, mature, value };
        }
        maxRelativeValue = Math.max(maxRelativeValue, utxo.blocktime + lock.value);
      } else if (lock.based === "HEIGHT_LOCK") {
        maxRelativeValue = Math.max(maxRelativeValue, utxo.height + lock.value);
      }
    }

    value = maxRelativeValue;
    if (lock.based === "TIME_LOCK") {
      mature = (options?.currentUnixTime ?? Math.floor(Date.now() / 1000)) >= maxRelativeValue;
    } else if (lock.based === "HEIGHT_LOCK") {
      mature = options?.currentHeight == null ? null : options.currentHeight >= maxRelativeValue;
    }
  }

  return based === "NONE" ? undefined : { based, mature, value };
}

function getInputMiniscriptSignatureState(
  input: ReturnType<Transaction["getInput"]>,
  descriptor: string,
  network: Network,
): MiniscriptInputSignatureState {
  const { chain, index } = (() => {
    const bip32Derivation = input.bip32Derivation as
      | Array<[Uint8Array, { fingerprint: number; path: number[] }]>
      | undefined;
    if (!bip32Derivation || bip32Derivation.length === 0) {
      return { chain: 0 as const, index: 0 };
    }

    const [, { path }] = bip32Derivation[0];
    if (path.length < 2) {
      return { chain: 0 as const, index: path[path.length - 1] ?? 0 };
    }

    return {
      chain: path[path.length - 2] === 1 ? (1 as const) : (0 as const),
      index: path[path.length - 1],
    };
  })();

  const keyInfos = deriveDescriptorMiniscriptKeys(descriptor, network, chain, index);
  const byPubkey = new Map<string, { fingerprint: number; keyExpression: string }>();
  for (const info of keyInfos) {
    if (!info.bip32) {
      continue;
    }
    byPubkey.set(Buffer.from(info.pubkey).toString("hex"), {
      fingerprint: info.bip32.fingerprint,
      keyExpression: info.keyExpression,
    });
  }

  const signedFingerprints = new Set<number>();
  const signedKeyExpressions = new Set<string>();
  const partialSig = input.partialSig as Array<[Uint8Array, Uint8Array]> | undefined;
  for (const [pubkey] of partialSig ?? []) {
    const match = byPubkey.get(Buffer.from(pubkey).toString("hex"));
    if (!match) {
      continue;
    }
    signedFingerprints.add(match.fingerprint);
    signedKeyExpressions.add(match.keyExpression);
  }

  return { signedFingerprints, signedKeyExpressions };
}

function inferMiniscriptSpendingPlan(
  descriptor: string,
  tx: Transaction,
  txState: { inputs: Array<{ nSequence: number }>; lockTime: number },
): MiniscriptSpendingPlan | null {
  const parsed = parseDescriptor(descriptor);
  if (parsed.kind !== "miniscript" || !parsed.miniscript) {
    return null;
  }

  const plans = getMiniscriptSpendingPlans(parsed.miniscript).filter((plan) => plan.supported);
  if (tx.lockTime > 0) {
    const exactLockTime = plans
      .filter((plan) => plan.lockTime === tx.lockTime)
      .sort((left, right) => left.index - right.index);
    if (exactLockTime.length > 0) {
      return exactLockTime[0];
    }
  }

  const exactSequence = plans
    .filter(
      (plan) =>
        plan.sequence > 0 &&
        txState.inputs.length > 0 &&
        txState.inputs.every((input) => input.nSequence === plan.sequence),
    )
    .sort((left, right) => left.index - right.index);
  if (exactSequence.length > 0) {
    return exactSequence[0];
  }

  try {
    return selectMiniscriptSpendingPlan(parsed.miniscript, txState);
  } catch {
    return null;
  }
}

function getMiniscriptPlanProgress(
  tx: Transaction,
  descriptor: string,
  network: Network,
  plan: MiniscriptSpendingPlan,
): MiniscriptPlanProgress {
  const txState = {
    inputs: Array.from({ length: tx.inputsLength }, (_, index) => ({
      nSequence: tx.getInput(index).sequence ?? 0xffffffff,
    })),
    lockTime: tx.lockTime,
  };
  if (!plan.supported || !isMiniscriptPlanSatisfied(plan, txState)) {
    return { ready: false, signedCount: 0, signedFingerprints: new Set<number>() };
  }

  let signedCount = 0;
  const signedFingerprints = new Set<number>();

  for (let inputIndex = 0; inputIndex < tx.inputsLength; inputIndex++) {
    const input = tx.getInput(inputIndex);
    const signatures = getInputMiniscriptSignatureState(input, descriptor, network);
    if (inputIndex === 0) {
      for (const fingerprint of signatures.signedFingerprints) {
        signedFingerprints.add(fingerprint);
      }
    }

    const preimages = getInputMiniscriptPreimages(input);
    let inputSignedCount = 0;

    for (const leaf of plan.leafNodes) {
      switch (leaf.type) {
        case "PK": {
          if (!signatures.signedKeyExpressions.has(leaf.keys[0])) {
            return {
              ready: false,
              signedCount: inputIndex === 0 ? inputSignedCount : signedCount,
              signedFingerprints,
            };
          }
          if (inputIndex === 0) {
            inputSignedCount += 1;
          }
          break;
        }
        case "MULTI": {
          const present = leaf.keys.filter((key) =>
            signatures.signedKeyExpressions.has(key),
          ).length;
          if (inputIndex === 0) {
            inputSignedCount += Math.min(present, leaf.k);
          }
          if (present < leaf.k) {
            return {
              ready: false,
              signedCount: inputIndex === 0 ? inputSignedCount : signedCount,
              signedFingerprints,
            };
          }
          break;
        }
        case "HASH160":
        case "HASH256":
        case "RIPEMD160":
        case "SHA256": {
          if (!leaf.data) {
            return {
              ready: false,
              signedCount: inputIndex === 0 ? inputSignedCount : signedCount,
              signedFingerprints,
            };
          }
          const requirement = miniscriptPreimageRequirementKey({
            type: leaf.type,
            hash: leaf.data,
          });
          if (!preimages.has(requirement)) {
            return {
              ready: false,
              signedCount: inputIndex === 0 ? inputSignedCount : signedCount,
              signedFingerprints,
            };
          }
          break;
        }
        default:
          break;
      }
    }

    if (inputIndex === 0) {
      signedCount = inputSignedCount;
    }
  }

  return { ready: true, signedCount, signedFingerprints };
}

function estimateMiniscriptFee(
  inputs: PreparedWalletInput[],
  btcNet: typeof NETWORK,
  toAddress: string,
  amount: bigint,
  changeAddress: string,
  includeChange: boolean,
  txLockTime: number,
  plan: MiniscriptSpendingPlan,
  feePerByte: bigint,
): bigint {
  const tx = new Transaction({
    lockTime: txLockTime,
    allowUnknownInputs: true,
    disableScriptCheck: true,
  });

  const inputIndexes: number[] = [];
  for (const prepared of inputs) {
    inputIndexes.push(tx.addInput(prepared.input));
  }

  tx.addOutputAddress(toAddress, amount, btcNet);
  if (includeChange) {
    tx.addOutputAddress(changeAddress, 1n, btcNet);
  }

  for (let i = 0; i < inputs.length; i++) {
    const prepared = inputs[i];
    const index = inputIndexes[i];
    if (!prepared.payment.witnessScript) {
      throw new Error("Miniscript wallet input is missing witnessScript");
    }
    tx.updateInput(
      index,
      {
        finalScriptWitness: buildMiniscriptDummyWitness(plan, prepared.payment.witnessScript),
      },
      true,
    );
  }

  const vsize = Math.ceil(tx.weight / 4);
  return feePerByte * BigInt(vsize);
}

function buildMiniscriptTransaction(
  inputs: PreparedWalletInput[],
  wallet: WalletData,
  network: Network,
  toAddress: string,
  amount: bigint,
  changeAddress: string,
  changeAmount: bigint,
  nextChangeIndex: number,
  txLockTime: number,
): Transaction {
  const btcNet = network === "mainnet" ? NETWORK : TEST_NETWORK;
  const tx = new Transaction({
    lockTime: txLockTime,
    allowUnknownInputs: true,
    disableScriptCheck: true,
  });

  for (const prepared of inputs) {
    tx.addInput(prepared.input);
  }

  tx.addOutputAddress(toAddress, amount, btcNet);

  if (changeAmount > 0n) {
    tx.addOutputAddress(changeAddress, changeAmount, btcNet);

    const changePayment = deriveDescriptorPayment(wallet.descriptor, network, 1, nextChangeIndex);
    const outputUpdate: Record<string, unknown> = {
      bip32Derivation: changePayment.bip32Derivation,
    };
    if (changePayment.witnessScript) outputUpdate.witnessScript = changePayment.witnessScript;
    if (changePayment.redeemScript) outputUpdate.redeemScript = changePayment.redeemScript;
    tx.updateOutput(tx.outputsLength - 1, outputUpdate);
  }

  return tx;
}

// Create a transaction PSBT with all metadata matching libnunchuk's FillPsbt
// Flow: scan UTXOs → coin selection → build PSBT → add nonWitnessUtxo,
//       bip32Derivation (inputs + outputs), witnessScript, global xpubs
export async function createTransaction(
  params: CreateTransactionParams,
): Promise<CreateTransactionResult> {
  const { wallet, network, electrum, toAddress, amount, miniscriptPath, preimages = [] } = params;
  const parsed = parseDescriptor(wallet.descriptor);
  if (parsed.kind !== "miniscript" && miniscriptPath != null) {
    throw new Error("Miniscript signing path selection is only supported for miniscript wallets");
  }
  if (parsed.kind !== "miniscript" && preimages.length > 0) {
    throw new Error("Miniscript preimages are only supported for miniscript wallets");
  }
  const btcNet = network === "mainnet" ? NETWORK : TEST_NETWORK;
  const miniscriptPlan =
    parsed.kind === "miniscript"
      ? selectMiniscriptSpendingPlan(parsed.miniscript!, undefined, miniscriptPath)
      : null;
  const inputSequence = miniscriptPlan?.sequence || MAX_BIP125_RBF_SEQUENCE;
  const txLockTime = miniscriptPlan?.lockTime || 0;

  // Step 1: Scan UTXOs
  const { utxos, nextChangeIndex } = await scanUtxos(wallet, network, electrum);
  if (utxos.length === 0) {
    throw new Error("No UTXOs found. Wallet has no funds.");
  }

  // Step 2: Fetch full previous transactions for nonWitnessUtxo
  // Reference: FillPsbt adds non_witness_utxo from database (walletdb.cpp:1074-1089)
  const prevTxCache = new Map<string, string>();
  const uniquePrevTxIds = [...new Set(utxos.map((utxo) => utxo.txHash))];
  const prevTxHexes = await electrum.getTransactionBatch(uniquePrevTxIds);
  for (let i = 0; i < uniquePrevTxIds.length; i++) {
    prevTxCache.set(uniquePrevTxIds[i], prevTxHexes[i]);
  }

  // Step 3: Build PSBT input metadata for each UTXO
  // Reference: FillPsbt populates witnessUtxo, bip32Derivation, witnessScript
  const preparedInputs: PreparedWalletInput[] = utxos.map((utxo) => {
    const payment =
      parsed.kind === "multisig"
        ? deriveMultisigPayment(
            wallet.signers,
            wallet.m,
            wallet.addressType,
            network,
            utxo.chain,
            utxo.index,
          )
        : deriveDescriptorPayment(wallet.descriptor, network, utxo.chain, utxo.index);
    const input: Record<string, unknown> = {
      txid: utxo.txHash,
      index: utxo.txPos,
      nonWitnessUtxo: prevTxCache.get(utxo.txHash),
      witnessUtxo: { script: payment.script, amount: utxo.value },
      bip32Derivation: payment.bip32Derivation,
      sequence: inputSequence,
    };
    if (payment.witnessScript) input.witnessScript = payment.witnessScript;
    if (payment.redeemScript) input.redeemScript = payment.redeemScript;
    return { input, payment, utxo };
  });

  // Step 4: Determine change address (first unused internal address)
  // Reference: nunchukimpl.cpp:2449-2456 GetAddresses(wallet_id, false, true)
  const changeAddrs =
    parsed.kind === "multisig"
      ? deriveAddresses(
          wallet.signers,
          wallet.m,
          wallet.addressType,
          network,
          1,
          nextChangeIndex,
          1,
        )
      : deriveDescriptorAddresses(wallet.descriptor, network, 1, nextChangeIndex, 1);
  const changeAddress = changeAddrs[0];

  // Step 5: Fee estimation from Nunchuk API (hourFee) with Electrum fallback
  // Reference: NunchukImpl::EstimateFee (nunchukimpl.cpp:1854-1895)
  const feePerByte = await estimateFeeRate(network, electrum);

  // Step 6: Coin selection + transaction building
  // Reference: wallet::CreateTransaction in spender.cpp:200-511 (BnB + Knapsack)
  // CLI uses @scure/btc-signer's selectUTXO for MVP
  let fee = 0n;
  let tx: Transaction | null = null;
  let txChangeAddress: string | null = null;

  if (parsed.kind === "multisig") {
    const result = selectUTXO(
      preparedInputs.map((prepared) => prepared.input),
      [{ address: toAddress, amount }],
      "default",
      {
        feePerByte,
        changeAddress,
        lockTime: txLockTime,
        network: btcNet,
        createTx: true,
      },
    );

    if (!result) {
      throw new Error("Insufficient funds to cover amount + fee.");
    }

    tx = result.tx!;
    fee = result.fee ?? 0n;
    txChangeAddress = result.change ? changeAddress : null;

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
  } else {
    if (!miniscriptPlan) {
      throw new Error("Unable to select a miniscript signing path");
    }

    const selected: PreparedWalletInput[] = [];
    let totalSelected = 0n;

    for (const prepared of preparedInputs) {
      selected.push(prepared);
      totalSelected += prepared.utxo.value;

      const feeWithChange = estimateMiniscriptFee(
        selected,
        btcNet,
        toAddress,
        amount,
        changeAddress,
        true,
        txLockTime,
        miniscriptPlan,
        feePerByte,
      );
      const candidateChange = totalSelected - amount - feeWithChange;
      if (candidateChange >= 546n) {
        fee = feeWithChange;
        txChangeAddress = changeAddress;
        tx = buildMiniscriptTransaction(
          selected,
          wallet,
          network,
          toAddress,
          amount,
          changeAddress,
          candidateChange,
          nextChangeIndex,
          txLockTime,
        );
        break;
      }

      const feeWithoutChange = estimateMiniscriptFee(
        selected,
        btcNet,
        toAddress,
        amount,
        changeAddress,
        false,
        txLockTime,
        miniscriptPlan,
        feePerByte,
      );
      if (totalSelected >= amount + feeWithoutChange) {
        fee = feeWithoutChange;
        txChangeAddress = null;
        tx = buildMiniscriptTransaction(
          selected,
          wallet,
          network,
          toAddress,
          amount,
          changeAddress,
          0n,
          nextChangeIndex,
          txLockTime,
        );
        break;
      }
    }

    if (!tx) {
      throw new Error("Insufficient funds to cover amount + fee.");
    }
  }

  // Step 8: Add global xpubs
  // Reference: FillPsbt stores signer xpubs in PSBT (walletdb.cpp:1101-1119)
  if (!tx) {
    throw new Error("Insufficient funds to cover amount + fee.");
  }
  if (parsed.kind === "miniscript" && preimages.length > 0) {
    addMiniscriptPreimagesToPsbt(tx, wallet.descriptor, preimages);
  }
  const psbtBytes = addGlobalXpubs(tx.toPSBT(), wallet.signers);

  const psbtB64 = Buffer.from(psbtBytes).toString("base64");
  const txId = tx.id;

  return {
    psbtB64,
    txId,
    fee,
    feePerByte,
    changeAddress: txChangeAddress,
    miniscriptPath: miniscriptPlan
      ? {
          index: miniscriptPlan.index,
          lockTime: miniscriptPlan.lockTime,
          preimageRequirements: miniscriptPlan.preimageRequirements,
          requiredSignatures: miniscriptPlan.requiredSignatures,
          sequence: miniscriptPlan.sequence,
          signerNames: miniscriptPlan.signerNames,
        }
      : undefined,
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
      const batchSize = GAP_LIMIT - consecutiveEmpty;
      const addresses = deriveWalletAddresses(wallet, network, chain, startIndex, batchSize);
      const scripthashes = addresses.map((address) => addressToScripthash(address, network));
      const histories = await electrum.getHistoryBatch(scripthashes);
      const usedScripthashes = scripthashes.filter((_, index) => histories[index].length > 0);
      const balances =
        usedScripthashes.length > 0 ? await electrum.getBalanceBatch(usedScripthashes) : [];
      let balanceIndex = 0;

      for (const history of histories) {
        if (history.length > 0) {
          const bal = balances[balanceIndex++];
          total += BigInt(bal.confirmed) + BigInt(bal.unconfirmed);
          consecutiveEmpty = 0;
        } else {
          consecutiveEmpty++;
        }
        if (consecutiveEmpty >= GAP_LIMIT) break;
      }
      startIndex += batchSize;
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
    const batchSize = GAP_LIMIT - consecutiveEmpty;
    const addresses = deriveWalletAddresses(wallet, network, 0, startIndex, batchSize);
    const scripthashes = addresses.map((address) => addressToScripthash(address, network));
    const histories = await electrum.getHistoryBatch(scripthashes);

    for (let offset = 0; offset < histories.length; offset++) {
      if (histories[offset].length > 0) {
        highestUsedIndex = startIndex + offset;
        consecutiveEmpty = 0;
      } else {
        consecutiveEmpty++;
      }
      if (consecutiveEmpty >= GAP_LIMIT) break;
    }

    startIndex += batchSize;
  }

  const index = highestUsedIndex + 1;
  const address = deriveWalletAddresses(wallet, network, 0, index, 1)[0];
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
      const batchSize = GAP_LIMIT - consecutiveEmpty;
      const addresses = deriveWalletAddresses(wallet, network, chain, startIndex, batchSize);
      const scripthashes = addresses.map((address) => addressToScripthash(address, network));
      const unspentBatch = await electrum.listUnspentBatch(scripthashes);
      const emptyIndexes = unspentBatch
        .map((unspent, index) => (unspent.length === 0 ? index : -1))
        .filter((index) => index >= 0);
      const emptyHistories =
        emptyIndexes.length > 0
          ? await electrum.getHistoryBatch(emptyIndexes.map((index) => scripthashes[index]))
          : [];
      const emptyHistoryByIndex = new Map<number, HistoryItem[]>();
      for (let i = 0; i < emptyIndexes.length; i++) {
        emptyHistoryByIndex.set(emptyIndexes[i], emptyHistories[i]);
      }

      for (let offset = 0; offset < addresses.length; offset++) {
        const addr = addresses[offset];
        const unspent = unspentBatch[offset];
        const isUsed = unspent.length > 0 || (emptyHistoryByIndex.get(offset)?.length ?? 0) > 0;

        for (const u of unspent) {
          utxos.push({
            txHash: u.tx_hash,
            txPos: u.tx_pos,
            value: BigInt(u.value),
            height: u.height,
            chain,
            index: startIndex + offset,
            address: addr,
          });
        }

        if (isUsed) {
          consecutiveEmpty = 0;
          if (chain === 1) nextChangeIndex = startIndex + offset + 1;
        } else {
          consecutiveEmpty++;
        }
        if (consecutiveEmpty >= GAP_LIMIT) break;
      }
      startIndex += batchSize;
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

  const data = await client.get<{ transaction?: ServerTxEvent } | ServerTxEvent>(
    `/v1.1/shared-wallets/wallets/${wallet.gid}/transactions/${txGid}`,
  );

  const event = "transaction" in data ? data.transaction : "data" in data ? data : undefined;
  if (!event?.data?.msg) {
    throw new Error("Transaction not found on server");
  }

  const parsed = decryptWalletPayload<PendingTxPayload>(wallet, event);
  return {
    txId: parsed.txId || parsed.tx_id || "",
    psbt: parsed.psbt,
  };
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
        const parsed = decryptWalletPayload<PendingTxPayload>(wallet, event);
        pending.push({
          txId: parsed.txId || parsed.tx_id || "",
          psbt: parsed.psbt,
        });
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
  const descriptor = buildAnyDescriptorForParsed(parseDescriptor(wallet.descriptor));
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
  walletDescriptor?: string,
  options?: PendingTxDecodeOptions,
): PendingTxDetail | null {
  try {
    const tx = Transaction.fromPSBT(Buffer.from(psbtB64, "base64"));
    const parsedDescriptor = walletDescriptor ? parseDescriptor(walletDescriptor) : null;

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

    const txState = {
      inputs: Array.from({ length: tx.inputsLength }, (_, index) => ({
        nSequence: tx.getInput(index).sequence ?? 0xffffffff,
      })),
      lockTime: tx.lockTime,
    };
    const miniscriptPlan =
      parsedDescriptor?.kind === "miniscript"
        ? inferMiniscriptSpendingPlan(walletDescriptor!, tx, txState)
        : null;
    const timelockedUntil = getTimelockedUntil(tx, miniscriptPlan, options);
    let requiredCount = miniscriptPlan?.requiredSignatures ?? walletM ?? 0;
    let signedCount = 0;
    const signedXfps = new Set<number>();
    const canAttributeSigners = !(
      parsedDescriptor?.kind === "miniscript" &&
      tx.isFinal &&
      tx.inputsLength > 0 &&
      !tx.getInput(0).partialSig?.length
    );

    let status: string;
    if (parsedDescriptor?.kind === "miniscript" && walletDescriptor && miniscriptPlan) {
      requiredCount = miniscriptPlan.requiredSignatures;
      if (tx.isFinal) {
        signedCount = requiredCount;
        status = "READY_TO_BROADCAST";
      } else {
        const progress = getMiniscriptPlanProgress(tx, walletDescriptor, network, miniscriptPlan);
        signedCount = progress.signedCount;
        for (const fingerprint of progress.signedFingerprints) {
          signedXfps.add(fingerprint);
        }
        if (!progress.ready) {
          status = "PENDING_SIGNATURES";
        } else {
          status = "READY_TO_BROADCAST";
        }
      }
    } else if (tx.isFinal) {
      signedCount = requiredCount;
      status = "READY_TO_BROADCAST";
    } else {
      try {
        const clone = tx.clone();
        clone.finalize();
        status = "READY_TO_BROADCAST";
      } catch {
        status = "PENDING_SIGNATURES";
      }
      if (tx.inputsLength > 0) {
        const inp = tx.getInput(0);
        const partialSig = inp.partialSig as Array<[Uint8Array, Uint8Array]> | undefined;
        const bip32Derivation = inp.bip32Derivation as
          | Array<[Uint8Array, { fingerprint: number; path: number[] }]>
          | undefined;
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
        } else if (status === "READY_TO_BROADCAST") {
          signedCount = requiredCount;
        }
      }
    }

    // Build signers map from wallet signers descriptors
    const signers: Record<string, boolean> = {};
    if (walletSigners && canAttributeSigners) {
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
      miniscriptPath: miniscriptPlan ? buildMiniscriptPathSummary(miniscriptPlan) : undefined,
      timelockedUntil,
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

async function fetchTransactionBatchMap(
  electrum: ElectrumClient,
  txHashes: string[],
): Promise<Map<string, string>> {
  const unique = [...new Set(txHashes)];
  const result = new Map<string, string>();
  if (unique.length === 0) {
    return result;
  }

  try {
    const rawHexes = await electrum.getTransactionBatch(unique);
    for (let i = 0; i < unique.length; i++) {
      result.set(unique[i], rawHexes[i]);
    }
    return result;
  } catch {
    await Promise.all(
      unique.map(async (txHash) => {
        try {
          result.set(txHash, await electrum.getTransaction(txHash));
        } catch {
          // Keep per-transaction failure behavior for history display.
        }
      }),
    );
    return result;
  }
}

async function fetchBlockHeaderBatchMap(
  electrum: ElectrumClient,
  heights: number[],
): Promise<Map<number, string>> {
  const unique = [...new Set(heights.filter((height) => height > 0))];
  const result = new Map<number, string>();
  if (unique.length === 0) {
    return result;
  }

  try {
    const headers = await electrum.getBlockHeaderBatch(unique);
    for (let i = 0; i < unique.length; i++) {
      result.set(unique[i], headers[i]);
    }
    return result;
  } catch {
    await Promise.all(
      unique.map(async (height) => {
        try {
          result.set(height, await electrum.getBlockHeader(height));
        } catch {
          // blocktime stays 0 if a header cannot be resolved
        }
      }),
    );
    return result;
  }
}

function outpointKey(txHash: string, txPos: number): string {
  return `${txHash}:${txPos}`;
}

async function fetchAddressHistoryBatchMap(
  electrum: ElectrumClient,
  addresses: string[],
  network: Network,
): Promise<Map<string, HistoryItem[]>> {
  const unique = [...new Set(addresses)];
  const result = new Map<string, HistoryItem[]>();
  if (unique.length === 0) {
    return result;
  }

  const scripthashes = unique.map((address) => addressToScripthash(address, network));
  try {
    const histories = await electrum.getHistoryBatch(scripthashes);
    for (let i = 0; i < unique.length; i++) {
      result.set(unique[i], histories[i]);
    }
    return result;
  } catch {
    await Promise.all(
      unique.map(async (address, index) => {
        try {
          result.set(address, await electrum.getHistory(scripthashes[index]));
        } catch {
          result.set(address, []);
        }
      }),
    );
    return result;
  }
}

export async function fetchPsbtInputTimelockMetadata(
  psbtB64: string,
  electrum: ElectrumClient,
  network: Network,
): Promise<PendingTxInputTimelockMetadata[]> {
  const metadataByTxId = await fetchPendingTxInputTimelockMetadataBatch(
    [{ txId: "", psbt: psbtB64 }],
    electrum,
    network,
  );
  return metadataByTxId.get("") ?? [];
}

export async function fetchPendingTxInputTimelockMetadataBatch(
  pending: PendingTx[],
  electrum: ElectrumClient,
  network: Network,
): Promise<Map<string, PendingTxInputTimelockMetadata[]>> {
  const outpointsByTxId = new Map<string, PendingTxInputOutpoint[]>();
  const addressByOutpoint = new Map<string, string>();

  for (const pendingTx of pending) {
    let tx: Transaction;
    try {
      tx = Transaction.fromPSBT(Buffer.from(pendingTx.psbt, "base64"));
    } catch {
      continue;
    }

    const outpoints: PendingTxInputOutpoint[] = [];
    for (let inputIndex = 0; inputIndex < tx.inputsLength; inputIndex++) {
      const outpoint = getInputOutpoint(tx, inputIndex);
      if (!outpoint) {
        continue;
      }

      const input = tx.getInput(inputIndex);
      const witnessScript = input.witnessUtxo?.script;
      const address = witnessScript ? getOutputAddress(witnessScript, network) : null;
      outpoints.push({ ...outpoint, inputIndex, height: 0 });
      if (address) {
        addressByOutpoint.set(outpointKey(outpoint.txHash, outpoint.txPos), address);
      }
    }
    outpointsByTxId.set(pendingTx.txId, outpoints);
  }

  if (outpointsByTxId.size === 0) {
    return new Map();
  }

  const missingPrevTxHashes = new Set<string>();
  for (const outpoints of outpointsByTxId.values()) {
    for (const outpoint of outpoints) {
      const key = outpointKey(outpoint.txHash, outpoint.txPos);
      if (!addressByOutpoint.has(key)) {
        missingPrevTxHashes.add(outpoint.txHash);
      }
    }
  }

  if (missingPrevTxHashes.size > 0) {
    const rawTxByHash = await fetchTransactionBatchMap(electrum, [...missingPrevTxHashes]);
    for (const outpoints of outpointsByTxId.values()) {
      for (const outpoint of outpoints) {
        const key = outpointKey(outpoint.txHash, outpoint.txPos);
        if (addressByOutpoint.has(key)) {
          continue;
        }

        const rawHex = rawTxByHash.get(outpoint.txHash);
        if (!rawHex) {
          continue;
        }

        try {
          const prevTx = Transaction.fromRaw(Buffer.from(rawHex, "hex"), {
            allowUnknownOutputs: true,
          });
          const prevOut = prevTx.getOutput(outpoint.txPos);
          const address = prevOut.script ? getOutputAddress(prevOut.script, network) : null;
          if (address) {
            addressByOutpoint.set(key, address);
          }
        } catch {
          // Missing or malformed previous transaction data leaves this input undetermined.
        }
      }
    }
  }

  const historyByAddress = await fetchAddressHistoryBatchMap(
    electrum,
    [...addressByOutpoint.values()],
    network,
  );

  const metadataByTxId = new Map<string, PendingTxInputTimelockMetadata[]>();
  for (const [txId, outpoints] of outpointsByTxId.entries()) {
    metadataByTxId.set(
      txId,
      outpoints.map((outpoint) => {
        const address = addressByOutpoint.get(outpointKey(outpoint.txHash, outpoint.txPos));
        const history = address ? historyByAddress.get(address) : undefined;
        const match = history?.find((item) => item.tx_hash === outpoint.txHash);
        return { txHash: outpoint.txHash, txPos: outpoint.txPos, height: match?.height ?? 0 };
      }),
    );
  }

  const allMetadata = [...metadataByTxId.values()].flat();

  const blockHeadersByHeight = await fetchBlockHeaderBatchMap(
    electrum,
    allMetadata.map((item) => item.height),
  );

  for (const [txId, metadata] of metadataByTxId.entries()) {
    metadataByTxId.set(
      txId,
      metadata.map((item) => {
        const headerHex = blockHeadersByHeight.get(item.height);
        if (!headerHex) {
          return item;
        }
        return { ...item, blocktime: parseBlockTime(headerHex) };
      }),
    );
  }

  return metadataByTxId;
}

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
        const addresses = deriveWalletAddresses(wallet, network, chain, startIndex, batchSize);
        const scripthashes = addresses.map((addr) => addressToScripthash(addr, network));
        const histories = await electrum.getHistoryBatch(scripthashes);
        for (let offset = 0; offset < addresses.length; offset++) {
          const addr = addresses[offset];
          walletAddresses.add(addr);
          const history = histories[offset];
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

    const uniqueTxEntries = [...uniqueTxs.entries()];
    const rawTxByHash = await fetchTransactionBatchMap(
      electrum,
      uniqueTxEntries.map(([txHash]) => txHash),
    );

    const txByHash = new Map<string, Transaction>();
    const prevTxIds = new Set<string>();
    for (const [txHash] of uniqueTxEntries) {
      const rawHex = rawTxByHash.get(txHash);
      if (!rawHex) continue;
      try {
        const tx = Transaction.fromRaw(Buffer.from(rawHex, "hex"), { allowUnknownOutputs: true });
        txByHash.set(txHash, tx);
        for (let i = 0; i < tx.inputsLength; i++) {
          const inp = tx.getInput(i);
          if (inp.txid) {
            prevTxIds.add(Buffer.from(inp.txid).toString("hex"));
          }
        }
      } catch {
        // Keep the fallback row for malformed transaction data.
      }
    }

    const prevRawTxByHash = await fetchTransactionBatchMap(electrum, [...prevTxIds]);
    const blockHeadersByHeight = await fetchBlockHeaderBatchMap(
      electrum,
      uniqueTxEntries.map(([, { height }]) => height),
    );
    const confirmed: ConfirmedTx[] = [];
    for (const [txHash, { height, fee: historyFee }] of uniqueTxEntries) {
      try {
        const tx = txByHash.get(txHash);
        if (!tx) {
          throw new Error("Transaction not found");
        }

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
              const prevHex = prevRawTxByHash.get(prevTxId);
              if (!prevHex) {
                continue;
              }
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
          const headerHex = blockHeadersByHeight.get(height);
          if (headerHex) {
            blocktime = parseBlockTime(headerHex);
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
