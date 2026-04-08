import { sha256 } from "@noble/hashes/sha2.js";
import { Transaction, NETWORK, TEST_NETWORK } from "@scure/btc-signer";
import type { ApiClient } from "./api-client.js";
import type { Network } from "./config.js";
import type { WalletData } from "./storage.js";
import { encryptWalletPayload, decryptWalletPayload } from "./wallet-keys.js";
import { deriveMultisigPayment } from "./address.js";
import { parseSignerDescriptor } from "./descriptor.js";

export type SpendingLimitInterval = "DAILY" | "WEEKLY" | "MONTHLY" | "YEARLY";

export interface SpendingLimit {
  interval: SpendingLimitInterval;
  amount: string;
  currency: string;
}

export interface PlatformKeyPolicy {
  autoBroadcastTransaction: boolean;
  signingDelaySeconds: number;
  spendingLimit?: SpendingLimit | null;
}

export interface SignerPolicy {
  masterFingerprint: string;
  autoBroadcastTransaction: boolean;
  signingDelaySeconds: number;
  spendingLimit?: SpendingLimit | null;
}

export interface PlatformKeyPolicies {
  global?: PlatformKeyPolicy | null;
  signers?: SignerPolicy[] | null;
}

export interface PlatformKeyConfig {
  policies: PlatformKeyPolicies;
}

const VALID_INTERVALS: SpendingLimitInterval[] = ["DAILY", "WEEKLY", "MONTHLY", "YEARLY"];
const VALID_CURRENCIES = ["USD", "BTC", "sat"] as const;

export function parseSigningDelayInput(input: string): number {
  const value = input.trim();
  const match = value.match(/^(\d+)([smhdSMHD])?$/);
  if (!match) {
    throw new Error("Invalid signing delay. Use seconds or a duration like 30s, 15m, 24h, or 7d");
  }

  const amount = Number.parseInt(match[1], 10);
  const unit = match[2]?.toLowerCase() ?? "s";

  switch (unit) {
    case "s":
      return amount;
    case "m":
      return amount * 60;
    case "h":
      return amount * 3600;
    case "d":
      return amount * 86400;
    default:
      throw new Error("Invalid signing delay unit");
  }
}

function normalizeCurrency(input: string): string {
  const lower = input.toLowerCase();
  if (lower === "usd") return "USD";
  if (lower === "btc") return "BTC";
  if (lower === "sat") return "sat";
  throw new Error(`Invalid currency: ${input}. Use: ${VALID_CURRENCIES.join(", ")}`);
}

export function validatePolicies(policies: PlatformKeyPolicies): void {
  const hasGlobal = policies.global != null;
  const hasSigners = Array.isArray(policies.signers) && policies.signers.length > 0;

  if (hasGlobal && hasSigners) {
    throw new Error("Global and signer policies must not coexist");
  }

  if (hasGlobal) {
    validatePolicy(policies.global!);
  }

  if (hasSigners) {
    for (const signer of policies.signers!) {
      if (!signer.masterFingerprint || !/^[0-9a-fA-F]{8}$/.test(signer.masterFingerprint)) {
        throw new Error(`Invalid master fingerprint: ${signer.masterFingerprint}`);
      }
      validatePolicy(signer);
    }
  }
}

function validatePolicy(policy: {
  autoBroadcastTransaction: boolean;
  signingDelaySeconds: number;
  spendingLimit?: SpendingLimit | null;
}): void {
  if (typeof policy.autoBroadcastTransaction !== "boolean") {
    throw new Error("autoBroadcastTransaction must be a boolean");
  }
  if (typeof policy.signingDelaySeconds !== "number" || policy.signingDelaySeconds < 0) {
    throw new Error("signingDelaySeconds must be a non-negative number");
  }
  if (policy.spendingLimit != null) {
    if (!VALID_INTERVALS.includes(policy.spendingLimit.interval)) {
      throw new Error(
        `Invalid spending limit interval: ${policy.spendingLimit.interval}. Use: ${VALID_INTERVALS.join(", ")}`,
      );
    }
    if (!policy.spendingLimit.amount) {
      throw new Error("Spending limit amount is required");
    }
    if (!policy.spendingLimit.currency) {
      throw new Error("Spending limit currency is required");
    }
    const currencyLower = policy.spendingLimit.currency.toLowerCase();
    if (!["usd", "btc", "sat"].includes(currencyLower)) {
      throw new Error(
        `Invalid currency: ${policy.spendingLimit.currency}. Use: ${VALID_CURRENCIES.join(", ")}`,
      );
    }
  }
}

export interface PolicyFlagOptions {
  autoBroadcast?: boolean;
  signingDelay?: number;
  limitAmount?: string;
  limitCurrency?: string;
  limitInterval?: string;
}

export function buildGlobalPolicyFromFlags(opts: PolicyFlagOptions): PlatformKeyPolicies {
  return { global: buildPolicyFromFlags(opts) };
}

export function buildSignerPolicyFromFlags(
  xfp: string,
  opts: PolicyFlagOptions,
): PlatformKeyPolicies {
  const policy = buildPolicyFromFlags(opts);
  return {
    signers: [
      {
        masterFingerprint: xfp.toLowerCase(),
        autoBroadcastTransaction: policy.autoBroadcastTransaction,
        signingDelaySeconds: policy.signingDelaySeconds,
        spendingLimit: policy.spendingLimit,
      },
    ],
  };
}

function buildPolicyFromFlags(opts: PolicyFlagOptions): PlatformKeyPolicy {
  const policy: PlatformKeyPolicy = {
    autoBroadcastTransaction: opts.autoBroadcast ?? false,
    signingDelaySeconds: opts.signingDelay ?? 0,
  };

  const hasAny =
    opts.limitAmount != null || opts.limitCurrency != null || opts.limitInterval != null;

  if (hasAny) {
    if (!opts.limitAmount || !opts.limitCurrency || !opts.limitInterval) {
      throw new Error(
        "All spending limit fields are required: --limit-amount, --limit-currency, --limit-interval",
      );
    }
    const interval = opts.limitInterval.toUpperCase() as SpendingLimitInterval;
    if (!VALID_INTERVALS.includes(interval)) {
      throw new Error(
        `Invalid spending limit interval: ${opts.limitInterval}. Use: ${VALID_INTERVALS.join(", ")}`,
      );
    }
    policy.spendingLimit = {
      interval,
      amount: opts.limitAmount,
      currency: normalizeCurrency(opts.limitCurrency),
    };
  }

  return policy;
}

export function mergePolicies(
  existing: PlatformKeyPolicies | undefined,
  incoming: PlatformKeyPolicies,
  signerXfp?: string,
): PlatformKeyPolicies {
  // Without --signer flag: full replacement
  if (!signerXfp) {
    return incoming;
  }

  // With --signer flag + existing is per-signer: merge (update/add targeted signer, keep others)
  const existingIsPerSigner =
    existing?.signers && existing.signers.length > 0 && existing.global == null;

  if (existingIsPerSigner) {
    const kept = existing!.signers!.filter(
      (s) => s.masterFingerprint.toLowerCase() !== signerXfp.toLowerCase(),
    );
    if (incoming.signers) {
      kept.push(...incoming.signers);
    }
    return { signers: kept };
  }

  // Switching from global/empty to per-signer
  return incoming;
}

export function parsePolicyJson(json: string): PlatformKeyPolicies {
  let parsed: PlatformKeyPolicies;
  try {
    parsed = JSON.parse(json) as PlatformKeyPolicies;
  } catch {
    throw new Error("Invalid policy JSON");
  }
  validatePolicies(parsed);
  return parsed;
}

export function validateWalletPolicies(
  policies: PlatformKeyPolicies,
  signerDescriptors: string[],
  platformKeyFingerprint?: string | null,
): void {
  validatePolicies(policies);

  if (!policies.signers || policies.signers.length === 0) {
    return;
  }

  const excluded = platformKeyFingerprint?.toLowerCase();
  const signerFingerprints = new Set(
    signerDescriptors
      .map((desc) => parseSignerDescriptor(desc).masterFingerprint.toLowerCase())
      .filter((xfp) => xfp !== excluded),
  );

  const policyFingerprints = new Set<string>();
  for (const signer of policies.signers) {
    const fingerprint = signer.masterFingerprint.toLowerCase();
    if (!signerFingerprints.has(fingerprint)) {
      throw new Error("Master fingerprint not found in wallet");
    }
    policyFingerprints.add(fingerprint);
  }

  for (const fingerprint of signerFingerprints) {
    if (!policyFingerprints.has(fingerprint)) {
      throw new Error("Missing signer policy");
    }
  }
}

// Format policies for human-readable output
function formatSpendingLimit(limit?: SpendingLimit | null): string {
  if (!limit) return "Unlimited";
  return `${limit.amount} ${limit.currency} / ${limit.interval}`;
}

function formatSigningDelay(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;
  const parts: string[] = [];

  if (hours > 0) {
    parts.push(`${hours}h`);
  }

  if (minutes > 0) {
    parts.push(`${minutes}m`);
  }

  if (remainingSeconds > 0 || parts.length === 0) {
    parts.push(`${remainingSeconds}s`);
  }

  return parts.join(" ");
}

function formatPolicy(policy: PlatformKeyPolicy, indent = ""): string[] {
  return [
    `${indent}Auto Broadcast:  ${policy.autoBroadcastTransaction}`,
    `${indent}Signing Delay:   ${formatSigningDelay(policy.signingDelaySeconds)}`,
    `${indent}Spending Limit:  ${formatSpendingLimit(policy.spendingLimit)}`,
  ];
}

export function formatPoliciesText(policies: PlatformKeyPolicies): string[] {
  const lines: string[] = [];
  const hasGlobal = policies.global != null;
  const hasSigners = Array.isArray(policies.signers) && policies.signers.length > 0;

  if (!hasGlobal && !hasSigners) {
    lines.push("Policy Type:     None");
    return lines;
  }

  if (hasGlobal) {
    lines.push("Policy Type:     Global");
    lines.push(...formatPolicy(policies.global!));
  }

  if (hasSigners) {
    lines.push("Policy Type:     Per-signer");
    for (const signer of policies.signers!) {
      lines.push("");
      lines.push(`Signer ${signer.masterFingerprint}:`);
      lines.push(...formatPolicy(signer, "  "));
    }
  }

  return lines;
}

// Fetch Nunchuk backend's ephemeral public key for platform key operations
export async function fetchBackendPubkey(client: ApiClient): Promise<string> {
  const response = await client.get<unknown>("/v1.1/shared-wallets/pubkey");
  if (typeof response === "string") return response;
  if (typeof response === "object" && response !== null) {
    const obj = response as Record<string, unknown>;
    if (typeof obj.pubkey === "string") return obj.pubkey;
    if (typeof obj.public_key === "string") return obj.public_key;
  }
  throw new Error("Invalid backend pubkey response");
}

// -- Phase 2: Dummy PSBT creation and signing --

// BIP125 RBF max sequence (matches Bitcoin Core's createpsbt with replaceable=true)
const MAX_BIP125_RBF_SEQUENCE = 0xfffffffd;

// Create a dummy PSBT for dummy transaction signing.
// Reference: GetHealthCheckDummyTx (nunchukutils.cpp:733-781)
//
// Flow:
// 1. SHA256(requestBody JSON) → 64-char hex hash (fake txid for Tx1 input)
// 2. Build Tx1: input=hash, output=10150 sats to address[1] → compute Tx1's txid
// 3. Build Tx2: input=Tx1's txid, output=10000 sats to address[2]
// 4. Populate Tx2 PSBT with bip32Derivation, witnessScript for signing
export function createDummyPsbt(
  wallet: WalletData,
  requestBody: string,
  network: Network,
): Transaction {
  const btcNet = network === "mainnet" ? NETWORK : TEST_NETWORK;

  // Step 1: SHA256(requestBody) → fake txid for Tx1's input
  const bodyBytes = new TextEncoder().encode(requestBody);
  const hashBytes = sha256(bodyBytes);
  const bodyHash = Buffer.from(hashBytes).toString("hex");

  // Step 2: Derive multisig payments at index 1 (Tx1 output / Tx2 input) and index 2 (Tx2 output)
  const payment1 = deriveMultisigPayment(
    wallet.signers,
    wallet.m,
    wallet.addressType,
    network,
    0,
    1,
  );
  const payment2 = deriveMultisigPayment(
    wallet.signers,
    wallet.m,
    wallet.addressType,
    network,
    0,
    2,
  );

  // Step 3: Build Tx1 (fake previous transaction) to compute its txid
  // Uses RBF sequence (0xfffffffd) to match lib's CoreUtils::CreatePsbt(replaceable=true)
  const prevTx = new Transaction();
  prevTx.addInput({ txid: bodyHash, index: 0, sequence: MAX_BIP125_RBF_SEQUENCE });
  prevTx.addOutputAddress(payment1.address, 10150n, btcNet);
  const prevTxId = prevTx.id;

  // Step 4: Build Tx2 (the dummy transaction to be signed)
  const dummyTx = new Transaction();

  const input: Record<string, unknown> = {
    txid: prevTxId,
    index: 0,
    witnessUtxo: { script: payment1.script, amount: 10150n },
    bip32Derivation: payment1.bip32Derivation,
    sequence: MAX_BIP125_RBF_SEQUENCE,
  };
  if (payment1.witnessScript) input.witnessScript = payment1.witnessScript;
  if (payment1.redeemScript) input.redeemScript = payment1.redeemScript;
  dummyTx.addInput(input);

  // Output: 10000 sats to address at index 2
  dummyTx.addOutputAddress(payment2.address, 10000n, btcNet);

  return dummyTx;
}

// Extract partial signature from a signed PSBT input matching a given fingerprint.
// Reference: GetPartialSignature (txutils.hpp:592-633)
// Returns DER-encoded signature hex string (with sighash byte).
export function extractPartialSignature(tx: Transaction, xfp: number): string {
  for (let i = 0; i < tx.inputsLength; i++) {
    const inp = tx.getInput(i);
    const partialSig = inp.partialSig as Array<[Uint8Array, Uint8Array]> | undefined;

    if (!partialSig) continue;

    const bip32Derivation = inp.bip32Derivation as
      | Array<[Uint8Array, { fingerprint: number; path: number[] }]>
      | undefined;

    if (!bip32Derivation) continue;

    // Find pubkeys belonging to this signer
    const signerPubkeys = new Set<string>();
    for (const [pubkey, { fingerprint }] of bip32Derivation) {
      if (fingerprint === xfp) {
        signerPubkeys.add(Buffer.from(pubkey).toString("hex"));
      }
    }

    // Match partial signature against signer pubkeys
    for (const [pubkey, sig] of partialSig) {
      if (signerPubkeys.has(Buffer.from(pubkey).toString("hex"))) {
        return Buffer.from(sig).toString("hex");
      }
    }
  }

  throw new Error("No partial signature found for this signer");
}

// -- Phase 2: Wallet platform key types and operations --

export type DummyTxType = "UPDATE_PLATFORM_KEY_POLICIES";
export type DummyTxStatus = "PENDING_SIGNATURES" | "CONFIRMED";

export interface DummyTxSignature {
  masterFingerprint: string;
  signature: string;
}

export interface DummyTxPayload {
  oldPolicies: PlatformKeyPolicies;
  newPolicies: PlatformKeyPolicies;
}

export interface GroupDummyTransaction {
  id: string;
  walletId: string;
  type: DummyTxType;
  status: DummyTxStatus;
  payload?: DummyTxPayload | null;
  requiredSignatures: number;
  pendingSignatures: number;
  requestBody: string;
  signatures: DummyTxSignature[];
  createdAt: number;
}

export interface PlatformKeyPolicyUpdateRequirement {
  success: boolean;
  requiresDummyTransaction: boolean;
  delayApplyInSeconds: number;
  dummyTransaction?: GroupDummyTransaction | null;
}

export interface WalletPlatformKeyConfig {
  platformKey?: PlatformKeyConfig | null;
  platformKeyFingerprint?: string | null;
}

// Fetch wallet platform key config (not encrypted)
// Reference: GroupService::GetWalletConfig (groupservice.cpp:1225-1241)
export async function getWalletPlatformKeyConfig(
  client: ApiClient,
  wallet: WalletData,
): Promise<WalletPlatformKeyConfig> {
  const data = await client.get<Record<string, unknown>>(
    `/v1.1/shared-wallets/wallets/${wallet.gid}`,
  );
  const walletData = (data?.wallet ?? data) as Record<string, unknown>;
  return {
    platformKey: (walletData?.platformKey ??
      walletData?.platform_key ??
      null) as PlatformKeyConfig | null,
    platformKeyFingerprint: (walletData?.platformKeyFingerprint ??
      walletData?.platform_key_fingerprint ??
      null) as string | null,
  };
}

// Fetch all dummy transactions (response is encrypted)
// Reference: GroupService::GetDummyTransactions (groupservice.cpp:1314-1330)
export async function fetchDummyTransactions(
  client: ApiClient,
  wallet: WalletData,
): Promise<GroupDummyTransaction[]> {
  const data = await client.get<unknown>(
    `/v1.1/shared-wallets/wallets/${wallet.gid}/dummy-transactions`,
  );
  const decrypted = decryptWalletPayload<Record<string, unknown[]>>(wallet, data);
  const txs = decrypted.dummyTransactions ?? decrypted.dummy_transactions ?? [];
  return txs.map(normalizeDummyTx);
}

// Fetch a single dummy transaction (response is encrypted)
// Reference: GroupService::GetDummyTransaction (groupservice.cpp:1332-1345)
export async function fetchDummyTransaction(
  client: ApiClient,
  wallet: WalletData,
  dummyTxId: string,
): Promise<GroupDummyTransaction> {
  const data = await client.get<unknown>(
    `/v1.1/shared-wallets/wallets/${wallet.gid}/dummy-transactions/${dummyTxId}`,
  );
  const decrypted = decryptWalletPayload<Record<string, unknown>>(wallet, data);
  const tx = (decrypted.dummyTransaction ?? decrypted) as Record<string, unknown>;
  return normalizeDummyTx(tx);
}

// Sign a dummy transaction
// Reference: GroupService::SignDummyTransaction (groupservice.cpp:1347-1364)
// signatures: array of request tokens in "xfp.base64sig" format
export async function signDummyTransaction(
  client: ApiClient,
  wallet: WalletData,
  dummyTxId: string,
  signatures: string[],
): Promise<void> {
  const payload = await encryptWalletPayload(wallet, { signatures });
  await client.post(
    `/v1.1/shared-wallets/wallets/${wallet.gid}/dummy-transactions/${dummyTxId}`,
    JSON.stringify(payload),
  );
}

// Cancel a dummy transaction
// Reference: GroupService::CancelDummyTransaction (groupservice.cpp:1366-1375)
export async function cancelDummyTransaction(
  client: ApiClient,
  wallet: WalletData,
  dummyTxId: string,
): Promise<void> {
  const payload = await encryptWalletPayload(wallet, {
    ts: Math.floor(Date.now() / 1000),
  });
  await client.del(
    `/v1.1/shared-wallets/wallets/${wallet.gid}/dummy-transactions/${dummyTxId}`,
    JSON.stringify(payload),
  );
}

export async function requestPlatformKeyPolicyUpdate(
  client: ApiClient,
  wallet: WalletData,
  policies: PlatformKeyPolicies,
): Promise<PlatformKeyPolicyUpdateRequirement> {
  const payload = await encryptWalletPayload(wallet, { policies });
  const data = await client.post<unknown>(
    `/v1.1/shared-wallets/wallets/${wallet.gid}/platform-key/policies`,
    JSON.stringify(payload),
  );
  const decrypted = decryptWalletPayload<Record<string, unknown>>(wallet, data);
  const requirement = (decrypted.requirement ?? decrypted) as Record<string, unknown>;
  return normalizePolicyUpdateRequirement(requirement, wallet.walletId);
}

// Normalize server response to GroupDummyTransaction
function normalizeDummyTx(raw: unknown): GroupDummyTransaction {
  const obj = raw as Record<string, unknown>;
  return {
    id: (obj.id ?? obj.dummy_transaction_id) as string,
    walletId: (obj.wallet_id ?? obj.walletId) as string,
    type: (obj.type ?? "UPDATE_PLATFORM_KEY_POLICIES") as DummyTxType,
    status: (obj.status ?? "PENDING_SIGNATURES") as DummyTxStatus,
    payload: (obj.payload ?? null) as DummyTxPayload | null,
    requiredSignatures: (obj.required_signatures ?? obj.requiredSignatures ?? 0) as number,
    pendingSignatures: (obj.pending_signatures ?? obj.pendingSignatures ?? 0) as number,
    requestBody: (obj.request_body ?? obj.requestBody ?? "") as string,
    signatures: normalizeSignatures(obj.signatures),
    createdAt: (obj.created_at ?? obj.createdAt ?? 0) as number,
  };
}

function normalizeSignatures(raw: unknown): DummyTxSignature[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((s: unknown) => {
    const obj = s as Record<string, unknown>;
    return {
      masterFingerprint: (obj.master_fingerprint ?? obj.masterFingerprint ?? "") as string,
      signature: (obj.signature ?? "") as string,
    };
  });
}

function normalizePolicyUpdateRequirement(
  raw: Record<string, unknown>,
  walletId: string,
): PlatformKeyPolicyUpdateRequirement {
  return {
    success: (raw.success ?? true) as boolean,
    requiresDummyTransaction: (raw.requiresDummyTransaction ?? false) as boolean,
    delayApplyInSeconds: (raw.delayApplyInSeconds ?? 0) as number,
    dummyTransaction: raw.dummyTransaction
      ? normalizeDummyTx({
          ...((raw.dummyTransaction as Record<string, unknown>) ?? {}),
          walletId,
        })
      : null,
  };
}
