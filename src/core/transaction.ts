// Transaction operations for group wallets
// Reference: libnunchuk nunchukimpl.cpp, groupservice.cpp

import { Transaction, bip32Path, NETWORK, TEST_NETWORK } from "@scure/btc-signer";
import { RawPSBTV0, TaprootControlBlock } from "@scure/btc-signer/psbt.js";
import { base58 } from "@scure/base";
import { DEFAULT_FEE_LEVEL, getElectrumServer } from "./config.js";
import type { FeeLevel, Network } from "./config.js";
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
  descriptorHasTaprootScriptPath,
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
import {
  descriptorHasMusig2Path,
  PSBT_IN_MUSIG2_PARTIAL_SIG,
  PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
  PSBT_IN_MUSIG2_PUB_NONCE,
} from "./musig.js";
import { combinationIndices } from "./utils.js";
import { formatBtc, formatSats, getOutputAddress } from "./format.js";
import { estimateFeeRate } from "./fees.js";
import { timelockFromK, type TimelockBased } from "./miniscript.js";
import { toXOnlyPubkey } from "./taproot.js";
import type { AddressType } from "./address-type.js";
import {
  CFeeRate,
  makeCOutput,
  selectCoins,
  type COutput,
  type CoinInput,
  type SelectionError,
  type SelectionRng,
} from "./coin-selection.js";
import {
  CryptoRng,
  buildCoinSelectionParams,
  computeTxNoinputsSize,
  getDustThreshold,
} from "./coin-selection-params.js";
import {
  buildMiniscriptDummyWitness,
  buildTaprootMultisigDummyWitness,
  estimateInputVBytes,
  getChangeDust,
  getChangeOutputSize,
  getChangeScriptLen,
} from "./coin-input-size.js";

const GAP_LIMIT = 20;
const MAX_BIP125_RBF_SEQUENCE = 0xfffffffd;
// Metadata gives exact output paths when available; fallback scans should match wallet discovery.
const OUTPUT_CLASSIFICATION_SCAN_LIMIT = GAP_LIMIT;
const OUTPUT_DERIVATION_CANDIDATE_LIMIT = GAP_LIMIT;

type PsbtUnknownEntry = [{ type: number; key: Uint8Array }, Uint8Array];
type PsbtBip32Derivation = Array<[Uint8Array, { fingerprint: number; path: number[] }]>;
type PsbtTapBip32Derivation = Array<
  [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]
>;
type PsbtOutput = ReturnType<Transaction["getOutput"]>;

export interface WalletOutputClassification {
  isWalletOutput: boolean;
  isChange: boolean;
}

export interface WalletOutputClassifier {
  addKnownAddress(address: string, chain: 0 | 1): void;
  classify(address: string | null, output?: PsbtOutput | null): WalletOutputClassification;
}

export type PendingTransactionStatus =
  | "PENDING_NONCE"
  | "PENDING_SIGNATURES"
  | "READY_TO_BROADCAST";
export type TaprootMusig2KeysetType = "key-path" | "script-path";

interface ExpectedTaprootMusig2Keyset {
  index: number;
  type: TaprootMusig2KeysetType;
  signers: string[];
}

interface InputMusig2Progress {
  participantsByAggregate: Map<string, string[]>;
  noncesByKeyset: Map<string, Set<string>>;
  partialSigsByKeyset: Map<string, Set<string>>;
  keysetIds: Set<string>;
}

interface InputMusig2KeysetProgress {
  nonceSigners: Set<string>;
  signatureSigners: Set<string>;
}

function bytesHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function xfpHex(fingerprint: number): string {
  return fingerprint.toString(16).padStart(8, "0");
}

function sortedXfps(xfps: Iterable<string>): string[] {
  return [...xfps].map((xfp) => xfp.toLowerCase()).sort();
}

function sameXfpSet(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((xfp, index) => xfp === b[index]);
}

function recordFromSigners(signers: string[], completed: Set<string>): Record<string, boolean> {
  const progress: Record<string, boolean> = {};
  for (const xfp of signers) {
    progress[xfp] = completed.has(xfp);
  }
  return progress;
}

function getInputMusig2PartialSignerPubkeys(
  input: ReturnType<Transaction["getInput"]>,
): Uint8Array[] {
  const unknown = (input.unknown as PsbtUnknownEntry[] | undefined) ?? [];
  const pubkeys = new Map<string, Uint8Array>();
  for (const [key, value] of unknown) {
    if (key.type !== PSBT_IN_MUSIG2_PARTIAL_SIG || value.length !== 32) {
      continue;
    }
    if (key.key.length !== 66 && key.key.length !== 98) {
      continue;
    }
    const pubkey = key.key.subarray(0, 33);
    pubkeys.set(bytesHex(pubkey), pubkey);
  }
  return [...pubkeys.values()];
}

function getInputMusig2Progress(input: ReturnType<Transaction["getInput"]>): InputMusig2Progress {
  const unknown = (input.unknown as PsbtUnknownEntry[] | undefined) ?? [];
  const tapBip32Derivation = input.tapBip32Derivation as PsbtTapBip32Derivation | undefined;
  const fingerprintByXOnlyPubkey = new Map<string, string>();
  for (const [pubkey, { der }] of tapBip32Derivation ?? []) {
    fingerprintByXOnlyPubkey.set(
      bytesHex(pubkey.length === 32 ? pubkey : toXOnlyPubkey(pubkey)),
      xfpHex(der.fingerprint),
    );
  }

  const participantsByAggregate = new Map<string, string[]>();
  const noncesByKeyset = new Map<string, Set<string>>();
  const partialSigsByKeyset = new Map<string, Set<string>>();
  const keysetIds = new Set<string>();

  const addSigner = (target: Map<string, Set<string>>, keysetId: string, signerXfp: string) => {
    const signers = target.get(keysetId) ?? new Set<string>();
    signers.add(signerXfp);
    target.set(keysetId, signers);
    keysetIds.add(keysetId);
  };

  for (const [key, value] of unknown) {
    if (key.type !== PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS) {
      continue;
    }
    if (key.key.length !== 33 || value.length === 0 || value.length % 33 !== 0) {
      continue;
    }

    const aggregateKeysetId = bytesHex(key.key);
    const participantXfps = new Set<string>();
    let fullyMapped = true;
    for (let offset = 0; offset < value.length; offset += 33) {
      const pubkey = value.subarray(offset, offset + 33);
      const xfp = fingerprintByXOnlyPubkey.get(bytesHex(toXOnlyPubkey(pubkey)));
      if (xfp === undefined) {
        fullyMapped = false;
        break;
      }
      participantXfps.add(xfp);
    }

    if (fullyMapped && participantXfps.size > 0) {
      participantsByAggregate.set(aggregateKeysetId, sortedXfps(participantXfps));
      keysetIds.add(aggregateKeysetId);
    }
  }

  for (const [key] of unknown) {
    if (key.type !== PSBT_IN_MUSIG2_PUB_NONCE) {
      continue;
    }
    const parsed = parseMusig2SignerFieldKey(key.key);
    if (!parsed) {
      continue;
    }
    const fingerprint = fingerprintByXOnlyPubkey.get(
      bytesHex(toXOnlyPubkey(key.key.subarray(0, 33))),
    );
    if (fingerprint !== undefined) {
      addSigner(noncesByKeyset, parsed.keysetId, fingerprint);
    }
  }

  for (const [key] of unknown) {
    if (key.type !== PSBT_IN_MUSIG2_PARTIAL_SIG) {
      continue;
    }
    const parsed = parseMusig2SignerFieldKey(key.key);
    if (!parsed) {
      continue;
    }
    const fingerprint = fingerprintByXOnlyPubkey.get(
      bytesHex(toXOnlyPubkey(key.key.subarray(0, 33))),
    );
    if (fingerprint !== undefined) {
      addSigner(partialSigsByKeyset, parsed.keysetId, fingerprint);
    }
  }

  return {
    participantsByAggregate,
    noncesByKeyset,
    partialSigsByKeyset,
    keysetIds,
  };
}

function getInputMusig2NonceSignerFingerprints(
  input: ReturnType<Transaction["getInput"]>,
): Set<number> {
  const progress = getInputMusig2Progress(input);
  const fingerprints = new Set<number>();
  for (const nonces of progress.noncesByKeyset.values()) {
    for (const xfp of nonces) {
      fingerprints.add(parseInt(xfp, 16));
    }
  }
  return fingerprints;
}

function getTaprootMusig2NonceFingerprints(
  tx: Transaction,
  parsedDescriptor: ReturnType<typeof parseDescriptor> | null,
): Set<number> {
  const fingerprints = new Set<number>();
  if (!parsedDescriptor || !descriptorHasMusig2Path(parsedDescriptor)) {
    return fingerprints;
  }

  for (let inputIndex = 0; inputIndex < tx.inputsLength; inputIndex++) {
    for (const fingerprint of getInputMusig2NonceSignerFingerprints(tx.getInput(inputIndex))) {
      fingerprints.add(fingerprint);
    }
  }
  return fingerprints;
}

function parseMusig2SignerFieldKey(key: Uint8Array): {
  keysetId: string;
} | null {
  if (key.length !== 66 && key.length !== 98) {
    return null;
  }

  return {
    keysetId: bytesHex(key.subarray(33)),
  };
}

function taprootOutputKeyFromScriptHex(script: Uint8Array | undefined): string | null {
  if (!script || script.length !== 34 || script[0] !== 0x51 || script[1] !== 0x20) {
    return null;
  }
  return bytesHex(script.subarray(2));
}

function compressedKeyXOnlyHex(compressedKeyHex: string): string | null {
  return compressedKeyHex.length === 66 ? compressedKeyHex.slice(2) : null;
}

function getInputMusig2NonceStatus(
  input: ReturnType<Transaction["getInput"]>,
): Extract<PendingTransactionStatus, "PENDING_NONCE" | "PENDING_SIGNATURES"> | null {
  const progress = getInputMusig2Progress(input);

  let hasKnownKeyset = false;
  let hasNonceCompleteKeyset = false;
  let hasNonceIncompleteKeyset = false;

  for (const keysetId of progress.keysetIds) {
    const aggregateKeysetId = keysetId.slice(0, 66);
    const participants = progress.participantsByAggregate.get(aggregateKeysetId);
    if (!participants || participants.length === 0) {
      continue;
    }

    hasKnownKeyset = true;

    const partialSigCount = progress.partialSigsByKeyset.get(keysetId)?.size ?? 0;
    if (partialSigCount >= participants.length) {
      hasNonceCompleteKeyset = true;
      continue;
    }

    const nonceCount = progress.noncesByKeyset.get(keysetId)?.size ?? 0;
    if (nonceCount >= participants.length) {
      hasNonceCompleteKeyset = true;
    } else {
      hasNonceIncompleteKeyset = true;
    }
  }

  if (hasNonceCompleteKeyset) {
    return "PENDING_SIGNATURES";
  }
  if (hasNonceIncompleteKeyset || hasKnownKeyset) {
    return "PENDING_NONCE";
  }
  return null;
}

function getTaprootMusig2Status(
  tx: Transaction,
  parsedDescriptor: ReturnType<typeof parseDescriptor> | null,
  keysets: PendingTxKeysetDetail[] = [],
): Extract<PendingTransactionStatus, "PENDING_NONCE" | "PENDING_SIGNATURES"> | null {
  if (!parsedDescriptor || !descriptorHasMusig2Path(parsedDescriptor)) {
    return null;
  }

  if (keysets.length > 0) {
    return keysets.some((keyset) => keyset.status !== "PENDING_NONCE")
      ? "PENDING_SIGNATURES"
      : "PENDING_NONCE";
  }

  let hasNonceCompleteInputs = tx.inputsLength > 0;
  let hasNonceIncompleteInput = false;
  for (let inputIndex = 0; inputIndex < tx.inputsLength; inputIndex++) {
    const status = getInputMusig2NonceStatus(tx.getInput(inputIndex));
    if (status !== "PENDING_SIGNATURES") {
      hasNonceCompleteInputs = false;
      hasNonceIncompleteInput = true;
    }
  }

  if (hasNonceCompleteInputs) {
    return "PENDING_SIGNATURES";
  }
  return hasNonceIncompleteInput || tx.inputsLength > 0 ? "PENDING_NONCE" : null;
}

function getExpectedTaprootMusig2Keysets(
  parsedDescriptor: ReturnType<typeof parseDescriptor> | null,
): ExpectedTaprootMusig2Keyset[] {
  if (
    !parsedDescriptor ||
    parsedDescriptor.kind !== "multisig" ||
    parsedDescriptor.addressType !== "TAPROOT" ||
    !descriptorHasMusig2Path(parsedDescriptor)
  ) {
    return [];
  }

  const signerXfps = parsedDescriptor.signers.map((signer) =>
    parseSignerDescriptor(signer).masterFingerprint.toLowerCase(),
  );
  const combinations = combinationIndices(signerXfps.length, parsedDescriptor.m);
  const disableKeyPath = parsedDescriptor.taprootWalletTemplate === "DISABLE_KEY_PATH";
  const hasScriptPathMusig = parsedDescriptor.n <= 5 || parsedDescriptor.n === parsedDescriptor.m;
  const keysets = disableKeyPath || hasScriptPathMusig ? combinations : combinations.slice(0, 1);

  return keysets.map((indices, index) => ({
    index,
    type: !disableKeyPath && index === 0 ? "key-path" : "script-path",
    signers: sortedXfps(indices.map((signerIndex) => signerXfps[signerIndex])),
  }));
}

function keysetIdMatchesType(keysetId: string, type: TaprootMusig2KeysetType): boolean {
  return type === "key-path" ? keysetId.length === 66 : keysetId.length > 66;
}

function addProgressForMatchingKeysets(
  target: Set<string>,
  progressByKeyset: Map<string, Set<string>>,
  aggregateId: string,
  expected: ExpectedTaprootMusig2Keyset,
  input: ReturnType<Transaction["getInput"]>,
): void {
  const taprootOutputKey = taprootOutputKeyFromScriptHex(input.witnessUtxo?.script);
  for (const [keysetId, signers] of progressByKeyset) {
    if (!keysetIdMatchesType(keysetId, expected.type)) {
      continue;
    }

    const matchesInternalAggregate = keysetId.startsWith(aggregateId);
    const matchesTaprootOutputKey =
      expected.type === "key-path" &&
      taprootOutputKey !== null &&
      compressedKeyXOnlyHex(keysetId) === taprootOutputKey;
    if (!matchesInternalAggregate && !matchesTaprootOutputKey) {
      continue;
    }

    for (const signer of signers) {
      if (expected.signers.includes(signer)) {
        target.add(signer);
      }
    }
  }
}

function getInputMusig2KeysetProgress(
  input: ReturnType<Transaction["getInput"]>,
  inputProgress: InputMusig2Progress,
  expected: ExpectedTaprootMusig2Keyset,
): InputMusig2KeysetProgress {
  const nonceSigners = new Set<string>();
  const signatureSigners = new Set<string>();

  for (const [aggregateId, signers] of inputProgress.participantsByAggregate) {
    if (!sameXfpSet(signers, expected.signers)) {
      continue;
    }
    addProgressForMatchingKeysets(
      nonceSigners,
      inputProgress.noncesByKeyset,
      aggregateId,
      expected,
      input,
    );
    addProgressForMatchingKeysets(
      signatureSigners,
      inputProgress.partialSigsByKeyset,
      aggregateId,
      expected,
      input,
    );
  }

  return { nonceSigners, signatureSigners };
}

function getTaprootMusig2KeysetStatuses(
  tx: Transaction,
  parsedDescriptor: ReturnType<typeof parseDescriptor> | null,
): PendingTxKeysetDetail[] {
  const expectedKeysets = getExpectedTaprootMusig2Keysets(parsedDescriptor);
  if (expectedKeysets.length === 0 || tx.inputsLength === 0) {
    return [];
  }

  const inputProgresses = Array.from({ length: tx.inputsLength }, (_, inputIndex) => ({
    input: tx.getInput(inputIndex),
    progress: getInputMusig2Progress(tx.getInput(inputIndex)),
  }));

  return expectedKeysets.map((expected) => {
    const perInputProgress = inputProgresses.map((inputProgress) =>
      getInputMusig2KeysetProgress(inputProgress.input, inputProgress.progress, expected),
    );
    const nonceCompleteSigners = new Set(
      expected.signers.filter((xfp) =>
        perInputProgress.every((progress) => progress.nonceSigners.has(xfp)),
      ),
    );
    const signatureCompleteSigners = new Set(
      expected.signers.filter((xfp) =>
        perInputProgress.every((progress) => progress.signatureSigners.has(xfp)),
      ),
    );

    const status = expected.signers.every((xfp) => signatureCompleteSigners.has(xfp))
      ? "READY_TO_BROADCAST"
      : expected.signers.every((xfp) => nonceCompleteSigners.has(xfp))
        ? "PENDING_SIGNATURES"
        : "PENDING_NONCE";

    return {
      index: expected.index,
      type: expected.type,
      status,
      signers: expected.signers,
      nonces: recordFromSigners(expected.signers, nonceCompleteSigners),
      signatures: recordFromSigners(expected.signers, signatureCompleteSigners),
    };
  });
}

function deriveWalletAddresses(
  wallet: WalletData,
  network: Network,
  chain: 0 | 1,
  startIndex: number,
  count: number,
): string[] {
  return deriveDescriptorAddresses(wallet.descriptor, network, chain, startIndex, count);
}

function outputPathCandidate(path: number[] | undefined): { chain: 0 | 1; index: number } | null {
  if (!path || path.length < 2) {
    return null;
  }

  const chain = path[path.length - 2];
  const index = path[path.length - 1];
  if (chain !== 0 && chain !== 1) {
    return null;
  }
  if (!Number.isInteger(index) || index < 0 || index >= 0x80000000) {
    return null;
  }
  return { chain, index };
}

function outputDerivationCandidates(output: PsbtOutput): Array<{ chain: 0 | 1; index: number }> {
  const candidates: Array<{ chain: 0 | 1; index: number }> = [];
  const seen = new Set<string>();
  const addCandidate = (candidate: { chain: 0 | 1; index: number } | null) => {
    if (!candidate) {
      return;
    }
    const key = `${candidate.chain}:${candidate.index}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    candidates.push(candidate);
  };

  const bip32 = output.bip32Derivation as PsbtBip32Derivation | undefined;
  for (const [, { path }] of bip32 ?? []) {
    addCandidate(outputPathCandidate(path));
  }

  const tapBip32 = output.tapBip32Derivation as PsbtTapBip32Derivation | undefined;
  for (const [, { der }] of tapBip32 ?? []) {
    addCandidate(outputPathCandidate(der.path));
  }

  return candidates;
}

export function createWalletOutputClassifier(
  network: Network,
  walletDescriptor?: string,
  scanLimit = OUTPUT_CLASSIFICATION_SCAN_LIMIT,
): WalletOutputClassifier {
  const byAddress = new Map<string, WalletOutputClassification>();
  const derivedCandidateAddresses = new Map<string, string>();
  const scannedAddresses = new Map<0 | 1, Set<string>>();

  const nonWallet = (): WalletOutputClassification => ({
    isWalletOutput: false,
    isChange: false,
  });
  const walletOutput = (chain: 0 | 1): WalletOutputClassification => ({
    isWalletOutput: true,
    isChange: chain === 1,
  });
  const pathKey = (chain: 0 | 1, index: number): string => `${chain}:${index}`;

  const deriveCandidateAddress = (chain: 0 | 1, index: number): string => {
    const key = pathKey(chain, index);
    const existing = derivedCandidateAddresses.get(key);
    if (existing) {
      return existing;
    }

    const address = deriveDescriptorPayment(walletDescriptor!, network, chain, index).address;
    derivedCandidateAddresses.set(key, address);
    return address;
  };

  const scanChain = (chain: 0 | 1): Set<string> => {
    const existing = scannedAddresses.get(chain);
    if (existing) {
      return existing;
    }

    const addresses = new Set(
      deriveDescriptorAddresses(walletDescriptor!, network, chain, 0, scanLimit),
    );
    scannedAddresses.set(chain, addresses);
    for (const address of addresses) {
      byAddress.set(address, walletOutput(chain));
    }
    return addresses;
  };

  const addKnownAddress = (address: string, chain: 0 | 1): void => {
    byAddress.set(address, walletOutput(chain));
  };

  return {
    addKnownAddress,
    classify(address: string | null, output?: PsbtOutput | null): WalletOutputClassification {
      if (!address) {
        return nonWallet();
      }

      const cached = byAddress.get(address);
      if (cached) {
        return cached;
      }
      if (!walletDescriptor) {
        return nonWallet();
      }

      try {
        if (output) {
          const candidates = outputDerivationCandidates(output);
          // Older libnunchuk builds can attach hundreds of unrelated taproot derivations.
          // Treat those as polluted metadata and use the bounded address scan instead.
          if (candidates.length > 0 && candidates.length <= OUTPUT_DERIVATION_CANDIDATE_LIMIT) {
            for (const { chain, index } of candidates) {
              if (deriveCandidateAddress(chain, index) === address) {
                const classification = walletOutput(chain);
                byAddress.set(address, classification);
                return classification;
              }
            }
            const classification = nonWallet();
            byAddress.set(address, classification);
            return classification;
          }
        }

        for (const chain of [0, 1] as const) {
          if (scanChain(chain).has(address)) {
            const classification = walletOutput(chain);
            byAddress.set(address, classification);
            return classification;
          }
        }
      } catch {
        return nonWallet();
      }

      const classification = nonWallet();
      byAddress.set(address, classification);
      return classification;
    },
  };
}

export function classifyWalletOutput(
  address: string | null,
  output: PsbtOutput | null,
  network: Network,
  walletDescriptor?: string,
  scanLimit = OUTPUT_CLASSIFICATION_SCAN_LIMIT,
): WalletOutputClassification {
  return createWalletOutputClassifier(network, walletDescriptor, scanLimit).classify(
    address,
    output,
  );
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

export interface PendingTxKeysetDetail {
  index: number;
  type: TaprootMusig2KeysetType;
  status: PendingTransactionStatus;
  signers: string[];
  nonces: Record<string, boolean>;
  signatures: Record<string, boolean>;
}

export interface MiniscriptPathSummary {
  index: number;
  lockTime: number;
  preimageRequirements: MiniscriptPreimageRequirement[];
  requiredSignatures: number;
  sequence: number;
  signerNames: string[];
}

export interface PendingTxMiniscriptPathDetail extends MiniscriptPathSummary {
  signedCount: number;
  status: "compatible" | "satisfied";
}

export interface PendingTxDetail {
  txId: string;
  status: PendingTransactionStatus;
  signedCount: number;
  requiredCount: number;
  miniscriptPath?: MiniscriptPathSummary;
  miniscriptPaths?: PendingTxMiniscriptPathDetail[];
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
  keysets?: PendingTxKeysetDetail[];
  nonces?: Record<string, boolean>;
  signers: Record<string, boolean>;
}

export interface PendingTxDecodeOptions {
  currentHeight?: number;
  currentUnixTime?: number;
  inputUtxos?: PendingTxInputTimelockMetadata[];
  outputClassifier?: WalletOutputClassifier;
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
  taprootKeyPath?: boolean;
  taprootScriptPath?: boolean;
  preimages?: string[];
  // Manual fee rate in sat/kvB (Bitcoin Core's CFeeRate unit; e.g. 1.5 sat/vB =
  // 1500). When > 0 it overrides the auto-estimate; otherwise the rate is
  // estimated.
  feeRateSatPerKvB?: bigint;
  // Fee level for the auto-estimate path (priority / standard / economy).
  // Ignored when a manual `feeRateSatPerKvB` is supplied. Defaults to economy.
  feeLevel?: FeeLevel;
  // Pin nLockTime to the current block height to deter fee sniping. A spending
  // path's own absolute locktime (an `after` / OP_CHECKLOCKTIMEVERIFY
  // condition) always takes precedence.
  antiFeeSniping?: boolean;
  // Subtract the network fee from the recipient amount instead of adding it on
  // top, so the recipient receives `amount - fee`. The wallet's total spend
  // stays at `amount`.
  subtractFeeFromAmount?: boolean;
  // Sweep the entire wallet balance to the recipient. Overrides `amount` (set to
  // the full balance) and forces `subtractFeeFromAmount` on, so the recipient
  // receives `balance - fee` with no change. libnunchuk has no send-all
  // primitive — this mirrors the app (amount = balance + subtract_fee).
  // Combined with `presetCoins`, sweeps only the preset coins.
  sendAll?: boolean;
  // Manual coin selection: spend exactly these outpoints. Every preset coin is
  // spent — no subset optimization, no automatic top-up.
  presetCoins?: Array<{ txid: string; vout: number }>;
  // "<txid>:<vout>" keys of locked coins. Automatic selection (and --send-all)
  // skips them; an explicit preset spends a locked coin anyway.
  lockedOutpoints?: Set<string>;
  // Coin-control reconciliation hook, called with the scanned coins right
  // after the UTXO scan (change-tag intents and collection rules can tag or
  // lock a coin the moment it is first seen). Its returned locked set replaces
  // `lockedOutpoints`, so this very transaction already respects rule-applied
  // locks.
  reconcileScan?: (
    scanned: Array<{ txid: string; vout: number; address: string; amountSats: bigint }>,
  ) => {
    lockedOutpoints: Set<string>;
    // Fresh membership sets, resolved after reconciliation. When present they
    // replace the fromTag/fromCollection outpoints, so a coin tagged or
    // collected by this very scan's rules is already in the candidate pool.
    fromTagOutpoints?: Set<string>;
    fromCollectionOutpoints?: Set<string>;
  };
  // Restrict automatic selection (and --send-all) to the coins carrying this
  // tag. Cannot be combined with presetCoins.
  fromTag?: { name: string; outpoints: Set<string> };
  // Restrict automatic selection (and --send-all) to the collection's member
  // coins. Cannot be combined with presetCoins; combined with fromTag the
  // filters intersect.
  fromCollection?: { name: string; outpoints: Set<string> };
  // Randomness for selection shuffles, change target, input order, and change
  // position. Defaults to crypto-random; tests inject a seeded RNG.
  rng?: SelectionRng;
}

export interface CreateTransactionResult {
  psbtB64: string;
  txId: string;
  fee: bigint;
  // Effective fee rate in sat/kvB (CFeeRate unit). Display as sat/vB by /1000.
  feeRateSatPerKvB: bigint;
  // The fee level used for the auto-estimate, or undefined when a manual rate
  // was supplied. Lets the command label output (e.g. "3 sat/vB (economy)").
  feeLevel?: FeeLevel;
  // The transaction's nLockTime (0 when none was applied). Reflects a spending
  // path's absolute locktime or the anti-fee-sniping chain-tip height.
  lockTime: number;
  // True when the fee was subtracted from the recipient amount.
  subtractFee: boolean;
  // The amount actually sent to the recipient. Equals the requested amount
  // unless the fee was subtracted from it, in which case it is reduced by the fee.
  recipientAmount: bigint;
  changeAddress: string | null;
  // The change output value in sats (0 when there is no change output).
  changeAmount: bigint;
  // The UTXOs selected as inputs, in selection order (before any shuffle).
  selectedInputs: Array<{ txid: string; vout: number; value: bigint }>;
  miniscriptPath?: MiniscriptPathSummary;
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

function normalizePendingTxPayload(parsed: PendingTxPayload): PendingTx | null {
  const txId = parsed.txId || parsed.tx_id || "";
  const psbt = parsed.psbt || "";
  if (!txId || !psbt) {
    return null;
  }
  return { txId, psbt };
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

function buildPaymentPsbtMetadata(
  payment: ReturnType<typeof deriveDescriptorPayment>,
  target: "input" | "output",
  options: { taprootKeyPath?: boolean } = {},
): Record<string, unknown> {
  const update: Record<string, unknown> = {};
  if (payment.bip32Derivation.length > 0) update.bip32Derivation = payment.bip32Derivation;
  if (payment.witnessScript) update.witnessScript = payment.witnessScript;
  if (payment.redeemScript) update.redeemScript = payment.redeemScript;
  if (payment.tapInternalKey) update.tapInternalKey = payment.tapInternalKey;
  if (payment.tapBip32Derivation) {
    update.tapBip32Derivation = options.taprootKeyPath
      ? (payment.tapKeyBip32Derivation ??
        payment.tapBip32Derivation
          .filter(([, { hashes }]) => hashes.length === 0)
          .map(([pubkey, { der }]) => [pubkey, { hashes: [], der }]))
      : payment.tapBip32Derivation;
  }
  if (target === "input") {
    if (payment.tapMerkleRoot) {
      update.tapMerkleRoot = payment.tapMerkleRoot;
    }
    if (!options.taprootKeyPath && payment.tapLeafScript) {
      update.tapLeafScript = payment.tapLeafScript;
    }
  }
  return update;
}

function buildMiniscriptPathSummary(plan: MiniscriptSpendingPlan): MiniscriptPathSummary {
  return {
    index: plan.index,
    lockTime: plan.lockTime,
    preimageRequirements: plan.preimageRequirements,
    requiredSignatures: plan.requiredSignatures,
    sequence: plan.sequence,
    signerNames: plan.signerNames,
  };
}

function signerFingerprints(signers: string[]): Set<number> {
  const fingerprints = new Set<number>();
  for (const signer of signers) {
    try {
      fingerprints.add(parseInt(parseSignerDescriptor(signer).masterFingerprint, 16));
    } catch {
      // Bare miniscript placeholders cannot be mapped to wallet fingerprints.
    }
  }
  return fingerprints;
}

function taprootKeyPathDerivationFingerprints(tx: Transaction): Set<number> {
  const fingerprints = new Set<number>();
  for (let inputIndex = 0; inputIndex < tx.inputsLength; inputIndex++) {
    const tapBip32Derivation = tx.getInput(inputIndex).tapBip32Derivation as
      | Array<[Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]>
      | undefined;
    for (const [, { hashes, der }] of tapBip32Derivation ?? []) {
      if (hashes.length === 0) {
        fingerprints.add(der.fingerprint);
      }
    }
  }
  return fingerprints;
}

function filterSignerDescriptorsByFingerprint(
  signers: string[],
  fingerprints: Set<number>,
): string[] {
  if (fingerprints.size === 0) {
    return [];
  }
  return signers.filter((signer) =>
    fingerprints.has(parseInt(parseSignerDescriptor(signer).masterFingerprint, 16)),
  );
}

function getDisplaySignerDescriptors(
  tx: Transaction,
  parsedDescriptor: ReturnType<typeof parseDescriptor> | null,
  walletSigners: string[] | undefined,
  miniscriptPlan: MiniscriptSpendingPlan | null,
): string[] | undefined {
  if (!walletSigners || parsedDescriptor?.kind !== "miniscript") {
    return walletSigners;
  }

  if (parsedDescriptor.addressType !== "TAPROOT") {
    return walletSigners;
  }

  if (miniscriptPlan) {
    const filtered = filterSignerDescriptorsByFingerprint(
      walletSigners,
      signerFingerprints(miniscriptPlan.signerNames),
    );
    return filtered.length > 0 ? filtered : walletSigners;
  }

  const psbtKeyPathSigners = filterSignerDescriptorsByFingerprint(
    walletSigners,
    taprootKeyPathDerivationFingerprints(tx),
  );
  if (psbtKeyPathSigners.length > 0) {
    return psbtKeyPathSigners;
  }

  const descriptorKeyPathSigners = filterSignerDescriptorsByFingerprint(
    walletSigners,
    signerFingerprints(parsedDescriptor.signers.slice(0, parsedDescriptor.m)),
  );
  return descriptorKeyPathSigners.length > 0 ? descriptorKeyPathSigners : walletSigners;
}

function canSpendTaprootKeyPath(parsed: ReturnType<typeof parseDescriptor>): boolean {
  if (parsed.addressType !== "TAPROOT" || parsed.m <= 0) {
    return false;
  }
  if (parsed.kind === "miniscript") {
    return true;
  }
  return parsed.kind === "multisig" && parsed.taprootWalletTemplate === "DEFAULT";
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
    const tapBip32Derivation = input.tapBip32Derivation as
      | Array<[Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]>
      | undefined;
    const path = bip32Derivation?.[0]?.[1].path ?? tapBip32Derivation?.[0]?.[1].der.path;
    if (!path) {
      return { chain: 0 as const, index: 0 };
    }
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
    byPubkey.set(Buffer.from(toXOnlyPubkey(info.pubkey)).toString("hex"), {
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
  const tapScriptSig = input.tapScriptSig as
    | Array<[{ pubKey: Uint8Array; leafHash: Uint8Array }, Uint8Array]>
    | undefined;
  for (const [{ pubKey }] of tapScriptSig ?? []) {
    const match = byPubkey.get(Buffer.from(pubKey).toString("hex"));
    if (!match) {
      continue;
    }
    signedFingerprints.add(match.fingerprint);
    signedKeyExpressions.add(match.keyExpression);
  }

  return { signedFingerprints, signedKeyExpressions };
}

function canInferMiniscriptSpendingPlan(
  parsed: ReturnType<typeof parseDescriptor>,
  tx: Transaction,
): boolean {
  return !(
    parsed.addressType === "TAPROOT" &&
    !Array.from({ length: tx.inputsLength }, (_, index) => tx.getInput(index)).some(
      (input) => (input.tapLeafScript as unknown[] | undefined)?.length,
    )
  );
}

function getCompatibleMiniscriptSpendingPlans(
  descriptor: string,
  tx: Transaction,
  txState: { inputs: Array<{ nSequence: number }>; lockTime: number },
): MiniscriptSpendingPlan[] {
  const parsed = parseDescriptor(descriptor);
  if (parsed.kind !== "miniscript" || !parsed.miniscript) {
    return [];
  }
  if (!canInferMiniscriptSpendingPlan(parsed, tx)) {
    return [];
  }

  return getMiniscriptSpendingPlans(parsed.miniscript)
    .filter((plan) => plan.supported && isMiniscriptPlanSatisfied(plan, txState))
    .sort((left, right) => left.index - right.index);
}

function chooseMiniscriptSpendingPlan(
  plans: MiniscriptSpendingPlan[],
  progressByIndex: Map<number, MiniscriptPlanProgress>,
  tx: Transaction,
  txState: { inputs: Array<{ nSequence: number }>; lockTime: number },
): MiniscriptSpendingPlan | null {
  const satisfied = plans
    .filter((plan) => progressByIndex.get(plan.index)?.ready)
    .sort((left, right) => left.index - right.index);
  if (satisfied.length > 0) {
    return satisfied[0];
  }

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

  return plans[0] ?? null;
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

// m-of-n P2WSH / P2SH-P2WSH multisig dummy witness: OP_0 + m × 72-byte sig + script.
function buildMultisigP2WSHDummyWitness(m: number, witnessScript: Uint8Array): Uint8Array[] {
  const stack: Uint8Array[] = [new Uint8Array()];
  for (let i = 0; i < m; i++) stack.push(new Uint8Array(72));
  stack.push(witnessScript);
  return stack;
}

// scriptSig bytes for a bare P2SH (LEGACY) m-of-n multisig spend:
//   OP_0 OP_PUSHBYTES_72 <sig_1> ... OP_PUSHBYTES_72 <sig_m> push(redeemScript)
function buildLegacyMultisigScriptSig(m: number, redeemScript: Uint8Array): Uint8Array {
  const parts: number[] = [0x00]; // OP_0
  for (let i = 0; i < m; i++) {
    parts.push(0x48); // OP_PUSHBYTES_72
    for (let j = 0; j < 72; j++) parts.push(0x00);
  }
  if (redeemScript.length <= 75) {
    parts.push(redeemScript.length);
  } else if (redeemScript.length <= 255) {
    parts.push(0x4c, redeemScript.length); // OP_PUSHDATA1
  } else {
    parts.push(0x4d, redeemScript.length & 0xff, (redeemScript.length >> 8) & 0xff); // OP_PUSHDATA2
  }
  for (const b of redeemScript) parts.push(b);
  return new Uint8Array(parts);
}

function applyMultisigDummyInput(
  tx: Transaction,
  inputIndex: number,
  addressType: AddressType,
  m: number,
  n: number,
  payment: PreparedWalletInput["payment"],
): void {
  if (addressType === "NATIVE_SEGWIT" || addressType === "NESTED_SEGWIT") {
    if (!payment.witnessScript) throw new Error("Multisig input missing witnessScript");
    tx.updateInput(
      inputIndex,
      { finalScriptWitness: buildMultisigP2WSHDummyWitness(m, payment.witnessScript) },
      true,
    );
    return;
  }
  if (addressType === "LEGACY") {
    if (!payment.redeemScript) throw new Error("Legacy multisig input missing redeemScript");
    tx.updateInput(
      inputIndex,
      { finalScriptSig: buildLegacyMultisigScriptSig(m, payment.redeemScript) },
      true,
    );
    return;
  }
  if (addressType === "TAPROOT") {
    const tapLeaf = payment.tapLeafScript?.[0];
    if (!tapLeaf) throw new Error("Taproot multisig input missing tapLeafScript");
    const [controlBlock, scriptWithVersion] = tapLeaf;
    tx.updateInput(
      inputIndex,
      {
        finalScriptWitness: buildTaprootMultisigDummyWitness(
          m,
          n,
          scriptWithVersion.slice(0, -1),
          TaprootControlBlock.encode(controlBlock),
        ),
      },
      true,
    );
    return;
  }
  throw new Error(`Unsupported address type for multisig: ${addressType}`);
}

// Build a dummy transaction mirroring the fully-signed PSBT and measure its
// vsize, used to settle the post-selection fee. Handles every wallet type:
// taproot key-path (single 64-byte Schnorr sig), miniscript v0 / taproot
// script-path (control block + leaf), and m-of-n multisig.
function estimateSignedTxVsize(args: {
  selected: PreparedWalletInput[];
  wallet: WalletData;
  network: Network;
  toAddress: string;
  amount: bigint;
  changeAddress: string | null;
  changeAmount: bigint;
  txLockTime: number;
  miniscriptPlan: MiniscriptSpendingPlan | null;
  taprootKeyPath: boolean;
}): number {
  const btcNet = args.network === "mainnet" ? NETWORK : TEST_NETWORK;
  const tx = new Transaction({
    lockTime: args.txLockTime,
    allowUnknownInputs: true,
    disableScriptCheck: true,
  });

  for (const prepared of args.selected) tx.addInput(prepared.input);
  tx.addOutputAddress(args.toAddress, args.amount, btcNet);
  if (args.changeAddress && args.changeAmount > 0n) {
    tx.addOutputAddress(args.changeAddress, args.changeAmount, btcNet);
  }

  for (let i = 0; i < args.selected.length; i++) {
    const prepared = args.selected[i];
    if (args.taprootKeyPath) {
      tx.updateInput(i, { finalScriptWitness: [new Uint8Array(64)] }, true);
      continue;
    }
    if (args.miniscriptPlan) {
      if (prepared.payment.witnessScript) {
        tx.updateInput(
          i,
          {
            finalScriptWitness: buildMiniscriptDummyWitness(
              args.miniscriptPlan,
              prepared.payment.witnessScript,
            ),
          },
          true,
        );
        continue;
      }
      const tapLeaf = prepared.payment.tapLeafScript?.[0];
      if (!tapLeaf) {
        throw new Error("Miniscript wallet input is missing witnessScript or tapLeafScript");
      }
      const [controlBlock, scriptWithVersion] = tapLeaf;
      tx.updateInput(
        i,
        {
          finalScriptWitness: buildMiniscriptDummyWitness(
            args.miniscriptPlan,
            scriptWithVersion.slice(0, -1),
            TaprootControlBlock.encode(controlBlock),
          ),
        },
        true,
      );
      continue;
    }
    applyMultisigDummyInput(
      tx,
      i,
      args.wallet.addressType,
      args.wallet.m,
      args.wallet.signers.length,
      prepared.payment,
    );
  }

  return Math.ceil(tx.weight / 4);
}

// Build the unsigned PSBT-ready transaction from the selected inputs, attaching
// taproot-aware BIP-174 change-output metadata for every wallet type.
function buildUnifiedTransaction(args: {
  selected: PreparedWalletInput[];
  parsed: ReturnType<typeof parseDescriptor>;
  wallet: WalletData;
  network: Network;
  toAddress: string;
  amount: bigint;
  changeAddress: string | null;
  changeAmount: bigint;
  changeIndex: number;
  txLockTime: number;
  taprootKeyPath: boolean;
  rng: SelectionRng;
}): Transaction {
  const { parsed } = args;
  const btcNet = args.network === "mainnet" ? NETWORK : TEST_NETWORK;
  const tx = new Transaction({
    lockTime: args.txLockTime,
    allowUnknownInputs: true,
    disableScriptCheck: true,
  });

  // Recipients first, then insert change at a random position so it isn't a
  // fixed-index fingerprint (rng.randrange(n + 1)). libnunchuk draws the change
  // position before shuffling inputs, so keep that RNG order here.
  const outputs: Array<{ address: string; amount: bigint; isChange: boolean }> = [
    { address: args.toAddress, amount: args.amount, isChange: false },
  ];
  if (args.changeAddress && args.changeAmount > 0n) {
    const pos = Number(args.rng.randrange(BigInt(outputs.length + 1)));
    outputs.splice(pos, 0, {
      address: args.changeAddress,
      amount: args.changeAmount,
      isChange: true,
    });
  }

  // Shuffle the final input order so it doesn't leak the selection algorithm
  // (GetShuffledInputVector). A single input is a no-op.
  const shuffledInputs = [...args.selected];
  args.rng.shuffle(shuffledInputs);
  for (const prepared of shuffledInputs) tx.addInput(prepared.input);

  let changeOutputIndex = -1;
  outputs.forEach((out, i) => {
    tx.addOutputAddress(out.address, out.amount, btcNet);
    if (out.isChange) changeOutputIndex = i;
  });

  if (changeOutputIndex >= 0) {
    const changePayment =
      parsed.kind === "multisig"
        ? deriveMultisigPayment(
            parsed.signers,
            parsed.m,
            parsed.addressType,
            args.network,
            1,
            args.changeIndex,
            parsed.taprootWalletTemplate,
          )
        : deriveDescriptorPayment(args.wallet.descriptor, args.network, 1, args.changeIndex);
    tx.updateOutput(
      changeOutputIndex,
      buildPaymentPsbtMetadata(changePayment, "output", { taprootKeyPath: args.taprootKeyPath }),
    );
  }

  return tx;
}

// Output script for a recipient address — used to size the recipient output
// when computing the selection target's tx_noinputs_size.
function getOutputScriptForAddress(address: string, btcNet: typeof NETWORK): Uint8Array {
  const tx = new Transaction({ allowUnknownInputs: true, disableScriptCheck: true });
  tx.addOutputAddress(address, 1n, btcNet);
  const script = tx.getOutput(0).script;
  if (!script) throw new Error("Unable to derive script for recipient address");
  return script;
}

// BIP141 witness-program shape for an arbitrary scriptPubKey: a 1-byte version
// opcode (OP_0, or OP_1..OP_16) followed by a single push of 2..40 bytes. Used
// to apply the witness discount in the recipient dust threshold.
function isWitnessProgramScript(script: Uint8Array): boolean {
  if (script.length < 4 || script.length > 42) return false;
  const version = script[0];
  if (version !== 0x00 && (version < 0x51 || version > 0x60)) return false;
  return script[1] === script.length - 2;
}

// Dust threshold for a recipient output paying `script`, at the discard feerate.
// Mirrors Bitcoin Core's IsDust(txout, m_discard_feerate) (spender.cpp CreateTransaction).
function getRecipientDust(script: Uint8Array, discardFeerate: CFeeRate): bigint {
  return getDustThreshold(
    getChangeOutputSize(script.length),
    isWitnessProgramScript(script),
    discardFeerate,
  );
}

// Candidate coins for automatic selection, mirroring spender.cpp AvailableCoins
// + the remain_target gate in CreateTransaction.
//
// Coins are always sorted oldest-confirmed-first (unconfirmed last). For a
// relative-timelock (CSV) spend the input sequence is custom (not the RBF
// sentinel, not 0), so libnunchuk caps the set to the oldest coins whose
// cumulative effective value covers the selection target — biasing toward coins
// that have aged into the timelock. For a normal RBF spend every coin stays
// available (remain_target = MAX_MONEY).
export function availableCandidates(
  coOutputs: COutput[],
  sequence: number,
  selectionTarget: bigint,
  subtractFeeOutputs: boolean,
): COutput[] {
  const sorted = [...coOutputs].sort((a, b) => {
    const ha = a.coin.height <= 0 ? Number.POSITIVE_INFINITY : a.coin.height;
    const hb = b.coin.height <= 0 ? Number.POSITIVE_INFINITY : b.coin.height;
    return ha - hb;
  });
  if (sequence === MAX_BIP125_RBF_SEQUENCE || sequence === 0) {
    return sorted; // no relative timelock — every coin is a candidate
  }
  // No manually pre-selected coins yet, so remain_target == selection_target.
  // (When coin control lands, subtract the pre-selected inputs' total here.)
  const capped: COutput[] = [];
  let total = 0n;
  for (const co of sorted) {
    if (total >= selectionTarget) break;
    capped.push(co);
    total += subtractFeeOutputs ? co.coin.value : co.effectiveValue;
  }
  return capped;
}

function humanizeSelectionError(error: SelectionError): Error {
  if (error === "max_weight") {
    return new Error(
      "Coin selection failed: the selected inputs would exceed the maximum transaction weight.",
    );
  }
  return new Error("Insufficient funds to cover amount + fee.");
}

// Create a transaction PSBT with all metadata matching libnunchuk's FillPsbt
// Flow: scan UTXOs → coin selection → build PSBT → add nonWitnessUtxo,
//       bip32Derivation (inputs + outputs), witnessScript, global xpubs
export async function createTransaction(
  params: CreateTransactionParams,
): Promise<CreateTransactionResult> {
  const {
    wallet,
    network,
    electrum,
    toAddress,
    amount: requestedAmount,
    miniscriptPath,
    taprootKeyPath: requestedTaprootKeyPath,
    taprootScriptPath = false,
    preimages = [],
    feeRateSatPerKvB,
    feeLevel = DEFAULT_FEE_LEVEL,
    antiFeeSniping = false,
    subtractFeeFromAmount: requestedSubtractFee = false,
    sendAll = false,
    presetCoins = [],
    lockedOutpoints,
    reconcileScan,
    fromTag,
    fromCollection,
    rng = new CryptoRng(),
  } = params;
  if (fromTag && presetCoins.length > 0) {
    throw new Error(
      "--from-tag cannot be combined with --coin (manual selection spends exactly the chosen coins).",
    );
  }
  if (fromCollection && presetCoins.length > 0) {
    throw new Error(
      "--from-collection cannot be combined with --coin (manual selection spends exactly the chosen coins).",
    );
  }
  const parsed = parseDescriptor(wallet.descriptor);
  if (parsed.kind !== "miniscript" && miniscriptPath != null) {
    throw new Error("Miniscript signing path selection is only supported for miniscript wallets");
  }
  if (parsed.kind !== "miniscript" && preimages.length > 0) {
    throw new Error("Miniscript preimages are only supported for miniscript wallets");
  }
  if (requestedTaprootKeyPath && taprootScriptPath) {
    throw new Error("Taproot key-path and script-path spending options cannot be combined");
  }
  if (taprootScriptPath && parsed.addressType !== "TAPROOT") {
    throw new Error("Taproot script-path spending requires a taproot wallet");
  }
  if (taprootScriptPath && !descriptorHasTaprootScriptPath(wallet.descriptor)) {
    throw new Error(
      "Taproot script-path spending requires a taproot wallet with script-path spending enabled",
    );
  }
  const taprootKeyPath =
    requestedTaprootKeyPath ??
    (!taprootScriptPath &&
      miniscriptPath == null &&
      preimages.length === 0 &&
      canSpendTaprootKeyPath(parsed));
  if (taprootKeyPath && miniscriptPath != null) {
    throw new Error("Taproot key-path spending cannot be combined with miniscript path selection");
  }
  if (taprootKeyPath && preimages.length > 0) {
    throw new Error("Taproot key-path spending cannot use miniscript preimages");
  }
  if (taprootKeyPath && !canSpendTaprootKeyPath(parsed)) {
    throw new Error(
      "Taproot key-path spending requires a taproot wallet with key-path spending enabled",
    );
  }
  const btcNet = network === "mainnet" ? NETWORK : TEST_NETWORK;
  const miniscriptPlan =
    parsed.kind === "miniscript" && !taprootKeyPath
      ? selectMiniscriptSpendingPlan(parsed.miniscript!, undefined, miniscriptPath)
      : null;
  const inputSequence = miniscriptPlan?.sequence || MAX_BIP125_RBF_SEQUENCE;
  // Anti-fee sniping: pin nLockTime to the current block height so this
  // transaction has no fee-sniping advantage over a competitor at the same
  // height. A spending path's own absolute locktime (an `after` /
  // OP_CHECKLOCKTIMEVERIFY condition) takes precedence; we only fill in a tip
  // height when the locktime would otherwise be 0. The default input sequence
  // (MAX_BIP125_RBF_SEQUENCE) is < 0xFFFFFFFF, so the locktime is enforced.
  // Reference: nunchukimpl.cpp CreateTransaction (`locktime == 0 && anti_fee_sniping`).
  let txLockTime = miniscriptPlan?.lockTime || 0;
  if (txLockTime === 0 && antiFeeSniping) {
    txLockTime = (await electrum.headersSubscribe()).height;
  }

  // Step 1: Scan UTXOs
  const { utxos: scannedUtxos, nextChangeIndex } = await scanUtxos(wallet, network, electrum);
  if (scannedUtxos.length === 0) {
    throw new Error("No UTXOs found. Wallet has no funds.");
  }
  const reconciled = reconcileScan
    ? reconcileScan(
        scannedUtxos.map((u) => ({
          txid: u.txHash,
          vout: u.txPos,
          address: u.address,
          amountSats: u.value,
        })),
      )
    : undefined;
  const effectiveLocked = reconciled ? reconciled.lockedOutpoints : lockedOutpoints;

  // Manual coin selection: validate the preset outpoints and restrict the
  // working set to exactly those coins.
  let utxos = scannedUtxos;
  if (presetCoins.length > 0) {
    const presetKeys = new Set<string>();
    for (const p of presetCoins) {
      const key = `${p.txid}:${p.vout}`;
      if (presetKeys.has(key)) {
        throw new Error(`Duplicate coin ${key}.`);
      }
      presetKeys.add(key);
      if (!scannedUtxos.some((u) => u.txHash === p.txid && u.txPos === p.vout)) {
        throw new Error(`Coin ${key} is not a spendable UTXO of this wallet.`);
      }
    }
    utxos = scannedUtxos.filter((u) => presetKeys.has(`${u.txHash}:${u.txPos}`));
  } else {
    if (effectiveLocked && effectiveLocked.size > 0) {
      // Locked coins never enter automatic selection; explicit presets bypass.
      utxos = utxos.filter((u) => !effectiveLocked.has(`${u.txHash}:${u.txPos}`));
      if (utxos.length === 0) {
        throw new Error(
          "All coins are locked. Unlock coins with `coin unlock` or select them explicitly with --coin.",
        );
      }
    }
    if (fromTag) {
      const outpoints = reconciled?.fromTagOutpoints ?? fromTag.outpoints;
      utxos = utxos.filter((u) => outpoints.has(`${u.txHash}:${u.txPos}`));
      if (utxos.length === 0) {
        throw new Error(`No spendable coins carry tag #${fromTag.name}.`);
      }
    }
    if (fromCollection) {
      const outpoints = reconciled?.fromCollectionOutpoints ?? fromCollection.outpoints;
      utxos = utxos.filter((u) => outpoints.has(`${u.txHash}:${u.txPos}`));
      if (utxos.length === 0) {
        throw new Error(
          fromTag
            ? `No spendable coins carry tag #${fromTag.name} and are in collection "${fromCollection.name}".`
            : `No spendable coins are in collection "${fromCollection.name}".`,
        );
      }
    }
  }

  // Send all funds (sweep): spend every available coin to the recipient with the
  // fee taken out of the amount, so the recipient receives balance - fee and
  // there is no change. libnunchuk has no send-all primitive — the app does it as
  // amount = wallet balance + subtract_fee_from_amount. Selecting all coins makes
  // the timelock oldest-first cap a no-op (the target equals the full balance).
  // With preset coins the working set is already restricted, so the sweep covers
  // only the chosen coins (app behavior: select coins → send max).
  const totalBalance = utxos.reduce((sum, utxo) => sum + utxo.value, 0n);
  const subtractFeeFromAmount = sendAll ? true : requestedSubtractFee;
  const amount = sendAll ? totalBalance : requestedAmount;

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
            parsed.signers,
            parsed.m,
            parsed.addressType,
            network,
            utxo.chain,
            utxo.index,
            parsed.taprootWalletTemplate,
          )
        : deriveDescriptorPayment(wallet.descriptor, network, utxo.chain, utxo.index);
    const input: Record<string, unknown> = {
      txid: utxo.txHash,
      index: utxo.txPos,
      nonWitnessUtxo: prevTxCache.get(utxo.txHash),
      witnessUtxo: { script: payment.script, amount: utxo.value },
      sequence: inputSequence,
      ...buildPaymentPsbtMetadata(payment, "input", { taprootKeyPath }),
    };
    return { input, payment, utxo };
  });

  // Step 4: Determine change address (first unused internal address)
  // Reference: nunchukimpl.cpp:2449-2456 GetAddresses(wallet_id, false, true)
  const changeAddrs =
    parsed.kind === "multisig"
      ? deriveAddresses(
          parsed.signers,
          parsed.m,
          parsed.addressType,
          network,
          1,
          nextChangeIndex,
          1,
          parsed.taprootWalletTemplate,
        )
      : deriveDescriptorAddresses(wallet.descriptor, network, 1, nextChangeIndex, 1);
  const changeAddress = changeAddrs[0];

  // Step 5: Fee rate in sat/kvB — a manual rate (> 0) overrides; otherwise
  // estimate from the Nunchuk API (hourFee) with Electrum fallback.
  // Reference: nunchukimpl.cpp CreateTransaction (`if (fee_rate <= 0) fee_rate = EstimateFee()`).
  const usingManualFeeRate = feeRateSatPerKvB != null && feeRateSatPerKvB > 0n;
  const feeRate = usingManualFeeRate
    ? feeRateSatPerKvB
    : await estimateFeeRate(network, electrum, feeLevel);

  // Step 6: Coin selection (BnB / Knapsack / SRD) + transaction building.
  // Reference: libnunchuk wallet::CreateTransaction (spender.cpp),
  // selector.cpp (run BnB + Knapsack + SRD, choose least waste), coinselection.cpp.
  const inputVBytes = estimateInputVBytes(wallet, network, { miniscriptPlan, taprootKeyPath });
  const coinInputs: CoinInput[] = preparedInputs.map(({ utxo }) => ({
    txid: utxo.txHash,
    vout: utxo.txPos,
    value: utxo.value,
    inputVBytes,
    height: utxo.height,
    blocktime: utxo.blocktime,
    isChange: utxo.chain === 1,
  }));

  const changeOutputSize = getChangeOutputSize(
    getChangeScriptLen(wallet, network, nextChangeIndex),
  );
  const recipientScript = getOutputScriptForAddress(toAddress, btcNet);
  const txNoinputsSize = computeTxNoinputsSize([recipientScript.length]);

  // Reject a recipient output that is below the dust threshold, before selecting
  // coins. Reference: spender.cpp CreateTransaction (IsDust → "Transaction amount too small").
  const discardFeerate = new CFeeRate(3_000n);
  if (amount < getRecipientDust(recipientScript, discardFeerate)) {
    throw new Error("Transaction amount too small.");
  }

  const selectionParams = buildCoinSelectionParams({
    feeRateSatPerKvB: feeRate,
    changeOutputSize,
    changeOutputDust: getChangeDust(wallet, network, nextChangeIndex, discardFeerate),
    txNoinputsSize,
    paymentValue: amount,
    subtractFeeOutputs: subtractFeeFromAmount,
    rng,
  });

  // All wallet coins are our own (from_me) and the eligibility ladder only needs
  // conf_mine >= 1, so a sentinel depth is sufficient; unconfirmed maps to 0.
  const coOutputs = coinInputs.map((c) =>
    makeCOutput(c, {
      effectiveFeerate: selectionParams.effectiveFeerate,
      longTermFeerate: selectionParams.longTermFeerate,
      currentHeight: c.height > 0 ? c.height + 1000 : 0,
    }),
  );

  // When the fee is subtracted from the recipient amount, inputs only need to
  // cover the amount itself — the fee comes out of the recipient output, so the
  // not-input fees drop out of the selection target (spender.cpp: not_input_fees
  // = getFee(subtract_fee_outputs ? 0 : tx_noinputs_size)).
  const notInputFees = selectionParams.effectiveFeerate.getFee(
    subtractFeeFromAmount ? 0 : txNoinputsSize,
  );
  const selectionTarget = amount + notInputFees;
  // Manual path: no automatic pool. The timelock oldest-first cap only shapes
  // the automatic pool, so it does not apply.
  const candidateOutputs =
    presetCoins.length > 0
      ? []
      : availableCandidates(
          coOutputs,
          inputSequence,
          selectionTarget,
          selectionParams.subtractFeeOutputs,
        );
  const sel = selectCoins(
    candidateOutputs,
    selectionTarget,
    selectionParams,
    presetCoins.length > 0 ? coOutputs : [],
  );
  if (!("result" in sel)) throw humanizeSelectionError(sel.error);

  const selected: PreparedWalletInput[] = sel.result.inputs.map((co) => {
    const match = preparedInputs.find(
      (p) => p.utxo.txHash === co.coin.txid && p.utxo.txPos === co.coin.vout,
    );
    if (!match) throw new Error("Internal: selection picked an unknown UTXO");
    return match;
  });

  // Step 7: Settle change + fee against the actual signed vsize (spender.cpp CreateTransaction).
  const totalIn = selected.reduce((s, p) => s + p.utxo.value, 0n);
  // Amount placed in the recipient output. Differs from the requested `amount`
  // only when the fee is subtracted from it, where the recipient absorbs the fee.
  let recipientOutputAmount = amount;
  let txChangeAddress: string | null;
  let changeAmount: bigint;
  let fee: bigint;

  if (subtractFeeFromAmount) {
    // The recipient pays the fee. Inputs only covered the recipient amount, so
    // change = totalIn - amount (independent of the fee), and the recipient
    // output is then reduced by the fee. Reference: spender.cpp CreateTransaction
    // (reduce output values for subtract-fee-from-amount).
    const rawChange = totalIn - amount;
    if (rawChange >= selectionParams.minViableChange) {
      txChangeAddress = changeAddress;
      changeAmount = rawChange;
    } else {
      txChangeAddress = null;
      changeAmount = 0n;
    }
    const vsize = estimateSignedTxVsize({
      selected,
      wallet,
      network,
      toAddress,
      amount,
      changeAddress: txChangeAddress,
      changeAmount,
      txLockTime,
      miniscriptPlan: miniscriptPlan ?? null,
      taprootKeyPath,
    });
    fee = selectionParams.effectiveFeerate.getFee(vsize);
    // The recipient receives everything not going to change or fees. With change
    // this is amount - fee; without change the would-be change folds in.
    recipientOutputAmount = totalIn - changeAmount - fee;
    if (recipientOutputAmount < 0n) {
      throw new Error("The transaction amount is too small to pay the fee.");
    }
    if (recipientOutputAmount < getRecipientDust(recipientScript, discardFeerate)) {
      throw new Error(
        "The transaction amount is too small to send after the fee has been deducted.",
      );
    }
  } else {
    // Default path: the sender adds the fee on top. Recompute the signed vsize
    // and adjust the change output to absorb any fee overpayment.
    txChangeAddress =
      sel.result.getChange(selectionParams.minViableChange, selectionParams.changeFee) > 0n
        ? changeAddress
        : null;
    changeAmount =
      txChangeAddress != null
        ? totalIn -
          amount -
          selectionParams.effectiveFeerate.getFee(
            estimateSignedTxVsize({
              selected,
              wallet,
              network,
              toAddress,
              amount,
              changeAddress,
              changeAmount: sel.result.getChange(
                selectionParams.minViableChange,
                selectionParams.changeFee,
              ),
              txLockTime,
              miniscriptPlan: miniscriptPlan ?? null,
              taprootKeyPath,
            }),
          )
        : 0n;

    if (txChangeAddress != null && changeAmount < selectionParams.minViableChange) {
      // Change fell below the dust/viability threshold after the fee adjustment.
      txChangeAddress = null;
      changeAmount = 0n;
    }

    if (txChangeAddress != null) {
      fee = totalIn - amount - changeAmount;
    } else {
      const vsizeNoChange = estimateSignedTxVsize({
        selected,
        wallet,
        network,
        toAddress,
        amount,
        changeAddress: null,
        changeAmount: 0n,
        txLockTime,
        miniscriptPlan: miniscriptPlan ?? null,
        taprootKeyPath,
      });
      if (totalIn < amount + selectionParams.effectiveFeerate.getFee(vsizeNoChange)) {
        throw new Error("Insufficient funds to cover amount + fee.");
      }
      fee = totalIn - amount;
    }
  }

  const tx: Transaction = buildUnifiedTransaction({
    selected,
    parsed,
    wallet,
    network,
    toAddress,
    amount: recipientOutputAmount,
    changeAddress: txChangeAddress,
    changeAmount,
    changeIndex: nextChangeIndex,
    txLockTime,
    taprootKeyPath,
    rng,
  });

  // Step 8: Add global xpubs
  // Reference: FillPsbt stores signer xpubs in PSBT (walletdb.cpp:1101-1119)
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
    feeRateSatPerKvB: feeRate,
    feeLevel: usingManualFeeRate ? undefined : feeLevel,
    lockTime: txLockTime,
    subtractFee: subtractFeeFromAmount,
    recipientAmount: recipientOutputAmount,
    changeAddress: txChangeAddress,
    changeAmount,
    selectedInputs: selected.map((p) => ({
      txid: p.utxo.txHash,
      vout: p.utxo.txPos,
      value: p.utxo.value,
    })),
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

  const pending = normalizePendingTxPayload(decryptWalletPayload<PendingTxPayload>(wallet, event));
  if (!pending) {
    throw new Error("Transaction not found on server");
  }
  return pending;
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
    const pending = new Map<string, PendingTx>();
    const deletedTxIds = new Set<string>();

    for (const event of events as ServerTxEvent[]) {
      try {
        const parsed = decryptWalletPayload<PendingTxPayload>(wallet, event);
        const txId = parsed.txId || parsed.tx_id || "";
        if (!txId) {
          continue;
        }
        if (!parsed.psbt) {
          deletedTxIds.add(txId);
          pending.delete(txId);
          continue;
        }
        if (!deletedTxIds.has(txId) && !pending.has(txId)) {
          pending.set(txId, { txId, psbt: parsed.psbt });
        }
      } catch {
        // skip events we can't decrypt
      }
    }
    return [...pending.values()];
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
  const currentTx = Transaction.fromPSBT(Buffer.from(currentPsbtB64, "base64"), {
    allowUnknown: true,
  });
  const currentCanonical = Buffer.from(currentTx.toPSBT());

  try {
    currentTx.combine(
      Transaction.fromPSBT(Buffer.from(nextPsbtB64, "base64"), {
        allowUnknown: true,
      }),
    );
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
    const tx = Transaction.fromPSBT(Buffer.from(psbtB64, "base64"), { allowUnknown: true });
    const parsedDescriptor = walletDescriptor ? parseDescriptor(walletDescriptor) : null;
    const outputClassifier =
      options?.outputClassifier ?? createWalletOutputClassifier(network, walletDescriptor);
    const musig2Keysets = getTaprootMusig2KeysetStatuses(tx, parsedDescriptor);
    const musig2Status = getTaprootMusig2Status(tx, parsedDescriptor, musig2Keysets);
    const nonceXfps = getTaprootMusig2NonceFingerprints(tx, parsedDescriptor);

    // Reference: libnunchuk FillSendReceiveData checks wallet ownership by address.
    // Taproot PSBT output metadata from older libnunchuk builds can contain extra
    // derivations, so verify metadata against the descriptor before trusting it.
    const outputs: PendingTxDetail["outputs"] = [];
    let subAmount = 0n;
    for (let i = 0; i < tx.outputsLength; i++) {
      const out = tx.getOutput(i);
      const addr = out.script ? getOutputAddress(out.script, network) : null;
      const amt = out.amount ?? 0n;
      const classification = outputClassifier.classify(addr, out);
      if (!classification.isWalletOutput) {
        subAmount += amt;
      }
      outputs.push({
        address: addr,
        amount: formatSats(amt),
        amountBtc: formatBtc(amt),
        isChange: classification.isChange,
      });
    }

    const txState = {
      inputs: Array.from({ length: tx.inputsLength }, (_, index) => ({
        nSequence: tx.getInput(index).sequence ?? 0xffffffff,
      })),
      lockTime: tx.lockTime,
    };
    const compatibleMiniscriptPlans =
      parsedDescriptor?.kind === "miniscript" && walletDescriptor
        ? getCompatibleMiniscriptSpendingPlans(walletDescriptor, tx, txState)
        : [];
    const miniscriptProgressByIndex = new Map<number, MiniscriptPlanProgress>();
    if (parsedDescriptor?.kind === "miniscript" && walletDescriptor && !tx.isFinal) {
      for (const plan of compatibleMiniscriptPlans) {
        miniscriptProgressByIndex.set(
          plan.index,
          getMiniscriptPlanProgress(tx, walletDescriptor, network, plan),
        );
      }
    }
    const miniscriptPlan =
      parsedDescriptor?.kind === "miniscript"
        ? chooseMiniscriptSpendingPlan(
            compatibleMiniscriptPlans,
            miniscriptProgressByIndex,
            tx,
            txState,
          )
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

    let status: PendingTransactionStatus;
    if (parsedDescriptor?.kind === "miniscript" && walletDescriptor && miniscriptPlan) {
      requiredCount = miniscriptPlan.requiredSignatures;
      if (tx.isFinal) {
        signedCount = requiredCount;
        status = "READY_TO_BROADCAST";
      } else {
        const progress =
          miniscriptProgressByIndex.get(miniscriptPlan.index) ??
          getMiniscriptPlanProgress(tx, walletDescriptor, network, miniscriptPlan);
        signedCount = progress.signedCount;
        for (const fingerprint of progress.signedFingerprints) {
          signedXfps.add(fingerprint);
        }
        if (!progress.ready) {
          status = musig2Status ?? "PENDING_SIGNATURES";
        } else {
          status = "READY_TO_BROADCAST";
        }
      }
    } else if (tx.isFinal) {
      signedCount = requiredCount;
      status = "READY_TO_BROADCAST";
    } else {
      status = "PENDING_SIGNATURES";
      if (tx.inputsLength > 0) {
        const inp = tx.getInput(0);
        const tapKeySig = inp.tapKeySig as Uint8Array | undefined;
        const tapBip32Derivation = inp.tapBip32Derivation as
          | Array<
              [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }]
            >
          | undefined;
        if (tapKeySig) {
          signedCount = Math.max(signedCount, requiredCount || 1);
          if (tapBip32Derivation && tapBip32Derivation.length > 0) {
            for (const [, { der }] of tapBip32Derivation.slice(0, requiredCount || 1)) {
              signedXfps.add(der.fingerprint);
            }
          }
        }

        const tapScriptSig = inp.tapScriptSig as
          | Array<[{ pubKey: Uint8Array; leafHash: Uint8Array }, Uint8Array]>
          | undefined;
        if (tapScriptSig && tapBip32Derivation) {
          const xfpByPubkey = new Map<string, number>();
          for (const [pubkey, { der }] of tapBip32Derivation) {
            xfpByPubkey.set(bytesHex(pubkey), der.fingerprint);
          }

          const signedTaprootPubkeys = new Set<string>();
          for (const [{ pubKey }] of tapScriptSig) {
            const pubkeyHex = bytesHex(pubKey);
            const fingerprint = xfpByPubkey.get(pubkeyHex);
            if (fingerprint === undefined || signedTaprootPubkeys.has(pubkeyHex)) {
              continue;
            }
            signedTaprootPubkeys.add(pubkeyHex);
            signedXfps.add(fingerprint);
          }
          signedCount = Math.max(signedCount, signedTaprootPubkeys.size);
        }

        const musig2PartialSignerPubkeys = getInputMusig2PartialSignerPubkeys(inp);
        if (musig2PartialSignerPubkeys.length > 0) {
          signedCount = Math.max(
            signedCount,
            Math.min(
              musig2PartialSignerPubkeys.length,
              requiredCount || musig2PartialSignerPubkeys.length,
            ),
          );
          if (tapBip32Derivation) {
            const xfpByXonlyPubkey = new Map<string, number>();
            for (const [pubkey, { der }] of tapBip32Derivation) {
              xfpByXonlyPubkey.set(bytesHex(pubkey), der.fingerprint);
            }
            for (const pubkey of musig2PartialSignerPubkeys) {
              const fingerprint = xfpByXonlyPubkey.get(bytesHex(toXOnlyPubkey(pubkey)));
              if (fingerprint !== undefined) {
                signedXfps.add(fingerprint);
              }
            }
          }
        }

        const partialSig = inp.partialSig as Array<[Uint8Array, Uint8Array]> | undefined;
        const bip32Derivation = inp.bip32Derivation as
          | Array<[Uint8Array, { fingerprint: number; path: number[] }]>
          | undefined;
        signedCount = Math.max(signedCount, partialSig?.length ?? 0);
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

      if (requiredCount > 0 && signedCount >= requiredCount) {
        try {
          const clone = tx.clone();
          clone.finalize();
          status = "READY_TO_BROADCAST";
        } catch {
          status = "PENDING_SIGNATURES";
        }
      } else if (musig2Status) {
        status = musig2Status;
      }
    }

    const displaySignerDescriptors = getDisplaySignerDescriptors(
      tx,
      parsedDescriptor,
      walletSigners,
      miniscriptPlan,
    );

    // Build signers map from descriptors relevant to the selected PSBT spend path.
    const signers: Record<string, boolean> = {};
    const nonces: Record<string, boolean> = {};
    if (displaySignerDescriptors && canAttributeSigners) {
      for (const desc of displaySignerDescriptors) {
        const xfp = parseSignerDescriptor(desc).masterFingerprint;
        signers[xfp] = signedXfps.has(parseInt(xfp, 16));
      }
    }
    if (displaySignerDescriptors && parsedDescriptor && descriptorHasMusig2Path(parsedDescriptor)) {
      for (const desc of displaySignerDescriptors) {
        const xfp = parseSignerDescriptor(desc).masterFingerprint;
        nonces[xfp] = nonceXfps.has(parseInt(xfp, 16));
      }
    }

    const miniscriptPaths =
      compatibleMiniscriptPlans.length > 0
        ? compatibleMiniscriptPlans.map((plan): PendingTxMiniscriptPathDetail => {
            const progress = miniscriptProgressByIndex.get(plan.index);
            const satisfied = tx.isFinal
              ? miniscriptPlan?.index === plan.index
              : Boolean(progress?.ready);
            return {
              ...buildMiniscriptPathSummary(plan),
              signedCount:
                tx.isFinal && satisfied ? plan.requiredSignatures : (progress?.signedCount ?? 0),
              status: satisfied ? "satisfied" : "compatible",
            };
          })
        : undefined;

    return {
      txId: "",
      status,
      signedCount,
      requiredCount,
      miniscriptPath: miniscriptPlan ? buildMiniscriptPathSummary(miniscriptPlan) : undefined,
      miniscriptPaths,
      timelockedUntil,
      fee: formatSats(tx.fee),
      feeBtc: formatBtc(tx.fee),
      outputs,
      subAmount: formatSats(subAmount),
      subAmountBtc: formatBtc(subAmount),
      keysets: musig2Keysets.length > 0 ? musig2Keysets : undefined,
      nonces: Object.keys(nonces).length > 0 ? nonces : undefined,
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

export async function fetchBlockHeaderBatchMap(
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
      tx = Transaction.fromPSBT(Buffer.from(pendingTx.psbt, "base64"), {
        allowUnknown: true,
      });
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
  outputClassifier?: WalletOutputClassifier,
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
          outputClassifier?.addKnownAddress(addr, chain);
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
