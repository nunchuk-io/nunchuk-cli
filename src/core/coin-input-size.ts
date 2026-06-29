// Per-coin signed input vsize estimation + change-output size / dust helpers.
// Feeds CoinInput.inputVBytes for the coin-selection port, mirroring
// libnunchuk's spender.cpp MaxInputWeight / GetVirtualTransactionInputSize.

import { TaprootControlBlock } from "@scure/btc-signer/psbt.js";
import { CFeeRate } from "./coin-selection.js";
import { compactSizeBytes, getDustThreshold } from "./coin-selection-params.js";
import type { AddressType } from "./address-type.js";
import type { Network } from "./config.js";
import type { WalletData } from "./storage.js";
import { deriveDescriptorPayment, deriveMultisigPayment } from "./address.js";
import { parseDescriptor } from "./descriptor.js";
import type { MiniscriptSpendingPlan } from "./miniscript-spend.js";

// Bitcoin Core spend.cpp uses can_grind_r=false, so ECDSA signatures are 72
// bytes. Taproot (BIP340) Schnorr signatures are 64 bytes (SIGHASH_DEFAULT).
const ECDSA_SIG_BYTES = 72;
const SCHNORR_SIG_BYTES = 64;

// Build the witness items for a script-path spend of `witnessScript` along
// `plan`. Used by both fee estimation and input-size estimation. Mirrors
// libnunchuk spender.cpp GetStackAndWitnessSize.
//
// When `controlBlock` is provided the spend is a taproot script-path: signatures
// are 64-byte Schnorr and the control block is pushed as the final witness item
// (after the leaf script). Otherwise it is a v0 segwit miniscript spend with
// 72-byte ECDSA signatures.
export function buildMiniscriptDummyWitness(
  plan: MiniscriptSpendingPlan,
  witnessScript: Uint8Array,
  controlBlock?: Uint8Array,
): Uint8Array[] {
  const isTaproot = controlBlock != null;
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
  for (let i = 0; i < multisigLeafCount; i++) stack.push(new Uint8Array());
  for (let i = 0; i < plan.requiredSignatures; i++) {
    stack.push(new Uint8Array(isTaproot ? SCHNORR_SIG_BYTES : ECDSA_SIG_BYTES));
  }
  stack.push(witnessScript);
  if (controlBlock) stack.push(controlBlock);
  return stack;
}

// -- Taproot key-path --
// A key-path spend (taproot single-sig, or taproot multisig with the DEFAULT
// musig2 template) carries a single 64-byte Schnorr signature and no script.
export function estimateTaprootKeyPathInputVBytes(): number {
  // witness: stack item count (1) + sig length (1) + 64-byte Schnorr sig
  const witnessSize = compactSizeBytes(1) + compactSizeBytes(SCHNORR_SIG_BYTES) + SCHNORR_SIG_BYTES;
  // base tx input: prevout (32+4) + empty scriptSig (compactSize(0)) + sequence (4)
  const nonWitness = 32 + 4 + compactSizeBytes(0) + 0 + 4;
  return Math.ceil((nonWitness * 4 + witnessSize) / 4);
}

// -- Multisig --
// m-of-n CHECKMULTISIG. Witness/scriptSig layout depends on addressType.
export function estimateMultisigInputVBytes(
  m: number,
  n: number,
  addressType: AddressType,
): number {
  const witnessScriptLen = 3 + 34 * n; // OP_M + n × (push opcode + 33-byte pubkey) + OP_N + OP_CHECKMULTISIG

  if (addressType === "NATIVE_SEGWIT" || addressType === "NESTED_SEGWIT") {
    let witness = compactSizeBytes(m + 2);
    witness += compactSizeBytes(0); // empty item for the CHECKMULTISIG dummy
    for (let i = 0; i < m; i++) {
      witness += compactSizeBytes(ECDSA_SIG_BYTES) + ECDSA_SIG_BYTES;
    }
    witness += compactSizeBytes(witnessScriptLen) + witnessScriptLen;

    let nonWitness: number;
    if (addressType === "NATIVE_SEGWIT") {
      nonWitness = 32 + 4 + compactSizeBytes(0) + 0 + 4; // empty scriptSig
    } else {
      // P2SH-P2WSH: scriptSig pushes the 34-byte witness program redeemScript.
      const scriptSig = 1 + 34;
      nonWitness = 32 + 4 + compactSizeBytes(scriptSig) + scriptSig + 4;
    }
    return Math.ceil((nonWitness * 4 + witness) / 4);
  }

  if (addressType === "LEGACY") {
    // Bare P2SH multisig: scriptSig = OP_0 + m × push(sig) + push(redeemScript)
    let scriptSig = 1; // OP_0
    for (let i = 0; i < m; i++) scriptSig += 1 + ECDSA_SIG_BYTES; // OP_PUSHBYTES_72 + 72 = 73
    if (witnessScriptLen <= 75) {
      scriptSig += 1 + witnessScriptLen;
    } else if (witnessScriptLen <= 255) {
      scriptSig += 2 + witnessScriptLen; // OP_PUSHDATA1 (1) + len (1) + data
    } else {
      scriptSig += 3 + witnessScriptLen; // OP_PUSHDATA2 (1) + len (2) + data
    }
    const nonWitness = 32 + 4 + compactSizeBytes(scriptSig) + scriptSig + 4;
    return Math.ceil((nonWitness * 4) / 4);
  }

  throw new Error(`Unsupported address type for multisig input estimation: ${addressType}`);
}

// Witness stack for a taproot multisig (multi_a) spend: one item per key
// (m 64-byte Schnorr sigs + (n-m) empty), then the leaf script and control block.
export function buildTaprootMultisigDummyWitness(
  m: number,
  n: number,
  leafScript: Uint8Array,
  controlBlock: Uint8Array,
): Uint8Array[] {
  const stack: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    stack.push(i < m ? new Uint8Array(SCHNORR_SIG_BYTES) : new Uint8Array());
  }
  stack.push(leafScript);
  stack.push(controlBlock);
  return stack;
}

// Taproot multisig spends via a multi_a tapscript leaf (DISABLE_KEY_PATH).
export function estimateTaprootMultisigInputVBytes(wallet: WalletData, network: Network): number {
  const payment = deriveMultisigPayment(
    wallet.signers,
    wallet.m,
    wallet.addressType,
    network,
    0,
    0,
  );
  const tapLeaf = payment.tapLeafScript?.[0];
  if (!tapLeaf) {
    throw new Error("Taproot multisig payment is missing tapLeafScript");
  }
  const [controlBlock, scriptWithVersion] = tapLeaf;
  const witness = buildTaprootMultisigDummyWitness(
    wallet.m,
    wallet.signers.length,
    scriptWithVersion.slice(0, -1), // leaf script (drop version byte)
    TaprootControlBlock.encode(controlBlock),
  );

  let witnessSize = compactSizeBytes(witness.length);
  for (const item of witness) witnessSize += compactSizeBytes(item.length) + item.length;
  const nonWitness = 32 + 4 + compactSizeBytes(0) + 0 + 4; // empty scriptSig (taproot)
  return Math.ceil((nonWitness * 4 + witnessSize) / 4);
}

// -- Miniscript / taproot script-path --
// Builds a 1-input dummy witness via buildMiniscriptDummyWitness and measures
// the resulting per-input weight.
export function estimateMiniscriptInputVBytes(
  wallet: WalletData,
  network: Network,
  plan: MiniscriptSpendingPlan,
): number {
  const payment = deriveDescriptorPayment(wallet.descriptor, network, 0, 0);
  let witness: Uint8Array[];
  if (payment.witnessScript) {
    // v0 segwit miniscript: witnessScript + ECDSA signatures.
    witness = buildMiniscriptDummyWitness(plan, payment.witnessScript);
  } else if (payment.tapLeafScript?.[0]) {
    // Taproot script-path: [satisfaction..., leaf script, control block], with
    // 64-byte Schnorr signatures. tapLeafScript[0] = [controlBlock, scriptWithVersion].
    const [controlBlock, scriptWithVersion] = payment.tapLeafScript[0];
    witness = buildMiniscriptDummyWitness(
      plan,
      scriptWithVersion.slice(0, -1), // drop the trailing leaf-version byte
      TaprootControlBlock.encode(controlBlock),
    );
  } else {
    throw new Error("Miniscript wallet payment is missing witnessScript or tapLeafScript");
  }

  let witnessSize = compactSizeBytes(witness.length);
  for (const item of witness) {
    witnessSize += compactSizeBytes(item.length) + item.length;
  }

  let nonWitness: number;
  if (wallet.addressType === "NATIVE_SEGWIT" || wallet.addressType === "TAPROOT") {
    nonWitness = 32 + 4 + compactSizeBytes(0) + 0 + 4;
  } else if (wallet.addressType === "NESTED_SEGWIT") {
    const scriptSig = 1 + 34;
    nonWitness = 32 + 4 + compactSizeBytes(scriptSig) + scriptSig + 4;
  } else {
    throw new Error(`Unsupported address type for miniscript: ${wallet.addressType}`);
  }

  return Math.ceil((nonWitness * 4 + witnessSize) / 4);
}

// Dispatcher used by createTransaction to populate CoinInput.inputVBytes.
// `taprootKeyPath` short-circuits to a single 64-byte Schnorr sig (taproot
// single-sig, or taproot multisig with the DEFAULT musig2 template);
// `miniscriptPlan` drives v0 / taproot script-path sizing.
export function estimateInputVBytes(
  wallet: WalletData,
  network: Network,
  opts: { miniscriptPlan?: MiniscriptSpendingPlan | null; taprootKeyPath?: boolean } = {},
): number {
  if (opts.taprootKeyPath) {
    return estimateTaprootKeyPathInputVBytes();
  }
  const parsed = parseDescriptor(wallet.descriptor);
  if (parsed.kind === "multisig") {
    if (wallet.addressType === "TAPROOT") {
      return estimateTaprootMultisigInputVBytes(wallet, network);
    }
    return estimateMultisigInputVBytes(wallet.m, wallet.signers.length, wallet.addressType);
  }
  if (parsed.kind === "miniscript") {
    if (!opts.miniscriptPlan) {
      throw new Error(
        "estimateInputVBytes requires a miniscript spending plan for miniscript wallets",
      );
    }
    return estimateMiniscriptInputVBytes(wallet, network, opts.miniscriptPlan);
  }
  throw new Error(`Unsupported wallet kind: ${parsed.kind}`);
}

// -- Change output helpers --

// Whether the wallet's change scriptPubKey is a witness program. Used for the
// 75% witness discount inside getDustThreshold.
export function isWalletWitnessOutput(addressType: AddressType): boolean {
  return addressType === "NATIVE_SEGWIT" || addressType === "TAPROOT";
}

// Serialized size of a CTxOut = 8 (value) + compactSize(scriptLen) + scriptLen.
export function getChangeOutputSize(scriptLen: number): number {
  return 8 + compactSizeBytes(scriptLen) + scriptLen;
}

// Resolve the wallet's change scriptPubKey length (depends on descriptor + addressType).
export function getChangeScriptLen(
  wallet: WalletData,
  network: Network,
  changeIndex: number,
): number {
  const parsed = parseDescriptor(wallet.descriptor);
  if (parsed.kind === "multisig") {
    const p = deriveMultisigPayment(
      wallet.signers,
      wallet.m,
      wallet.addressType,
      network,
      1,
      changeIndex,
    );
    return p.script.length;
  }
  const p = deriveDescriptorPayment(wallet.descriptor, network, 1, changeIndex);
  return p.script.length;
}

// Dust threshold for the wallet's change output, at the given discard feerate.
export function getChangeDust(
  wallet: WalletData,
  network: Network,
  changeIndex: number,
  discardFeerate: CFeeRate,
): bigint {
  const scriptLen = getChangeScriptLen(wallet, network, changeIndex);
  return getDustThreshold(
    getChangeOutputSize(scriptLen),
    isWalletWitnessOutput(wallet.addressType),
    discardFeerate,
  );
}
