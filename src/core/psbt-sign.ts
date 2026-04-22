import { HDKey } from "@scure/bip32";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Script } from "@scure/btc-signer/script.js";
import { SignatureHash, Transaction, getPrevOut } from "@scure/btc-signer/transaction.js";
import { signECDSA } from "@scure/btc-signer/utils.js";
import { parseDescriptor } from "./descriptor.js";

type Bip32DerivationEntry = [Uint8Array, { fingerprint: number; path: number[] }];

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }

  return true;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;

  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function scriptContainsPubkeyReference(script: Uint8Array, pubkey: Uint8Array): boolean {
  const pubkeyHash = hash160(pubkey);
  return Script.decode(script).some(
    (item) =>
      item instanceof Uint8Array && (bytesEqual(item, pubkey) || bytesEqual(item, pubkeyHash)),
  );
}

function signMiniscriptInput(
  tx: Transaction,
  inputIndex: number,
  privateKey: Uint8Array,
  pubkey: Uint8Array,
): boolean {
  const input = tx.getInput(inputIndex);
  const existing = input.partialSig as Array<[Uint8Array, Uint8Array]> | undefined;
  if (existing?.some(([existingPubkey]) => bytesEqual(existingPubkey, pubkey))) {
    return false;
  }

  const witnessScript = input.witnessScript;
  if (!witnessScript) {
    throw new Error("Miniscript PSBT input is missing witnessScript");
  }
  if (!scriptContainsPubkeyReference(witnessScript, pubkey)) {
    throw new Error("Input script does not reference the derived signer key");
  }

  const prevOut = getPrevOut(input);
  const sighash = input.sighashType ?? SignatureHash.ALL;
  const preimageWitnessV0 = (
    tx as unknown as {
      preimageWitnessV0?: (
        idx: number,
        script: Uint8Array,
        sighash: number,
        amount: bigint,
      ) => Uint8Array;
    }
  ).preimageWitnessV0;
  if (typeof preimageWitnessV0 !== "function") {
    throw new Error("PSBT signer does not expose segwit v0 preimage generation");
  }

  const digest = preimageWitnessV0.call(tx, inputIndex, witnessScript, sighash, prevOut.amount);
  const signature = signECDSA(digest, privateKey, tx.opts.lowR);
  const inputs = (
    tx as unknown as {
      inputs?: Array<{
        partialSig?: Array<[Uint8Array, Uint8Array]>;
      }>;
    }
  ).inputs;
  if (!inputs?.[inputIndex]) {
    throw new Error("PSBT signer cannot access the target input");
  }

  const signatureWithHashType = concatBytes([signature, new Uint8Array([sighash])]);
  if (!inputs[inputIndex].partialSig) {
    inputs[inputIndex].partialSig = [];
  }
  inputs[inputIndex].partialSig!.push([pubkey, signatureWithHashType]);
  return true;
}

function deriveSignerChildKey(
  signerKey: HDKey,
  path: number[],
  expectedPubkey: Uint8Array,
): HDKey | null {
  if (path.length < signerKey.depth) {
    return null;
  }

  let current = signerKey;
  for (const child of path.slice(signerKey.depth)) {
    current = current.deriveChild(child);
  }

  if (!current.publicKey || !bytesEqual(current.publicKey, expectedPubkey)) {
    return null;
  }

  return current;
}

export function signWalletPsbtWithKey(
  tx: Transaction,
  signerKey: HDKey,
  xfpInt: number,
  walletDescriptor?: string,
): number {
  const isMiniscript = walletDescriptor
    ? parseDescriptor(walletDescriptor).kind === "miniscript"
    : false;

  let signed = 0;
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    const bip32Derivation = input.bip32Derivation as Bip32DerivationEntry[] | undefined;

    if (!bip32Derivation) {
      continue;
    }

    for (const [pubkey, { fingerprint, path }] of bip32Derivation) {
      if (fingerprint !== xfpInt) {
        continue;
      }

      const childKey = deriveSignerChildKey(signerKey, path, pubkey);
      if (!childKey) {
        continue;
      }
      if (!childKey.privateKey || !childKey.publicKey) {
        break;
      }

      try {
        tx.signIdx(childKey.privateKey, i);
      } catch (err) {
        if (!isMiniscript) {
          throw err;
        }

        const didSign = signMiniscriptInput(tx, i, childKey.privateKey, pubkey);
        if (!didSign) {
          break;
        }
      }

      signed++;
      break;
    }
  }

  return signed;
}
