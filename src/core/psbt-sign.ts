import crypto from "node:crypto";
import { HDKey } from "@scure/bip32";
import { p2tr_pk } from "@scure/btc-signer";
import * as musig2 from "@scure/btc-signer/musig2.js";
import { tapLeafHash } from "@scure/btc-signer/payment.js";
import { Script } from "@scure/btc-signer/script.js";
import {
  SignatureHash,
  Transaction,
  bip32Path,
  getPrevOut,
} from "@scure/btc-signer/transaction.js";
import { signECDSA, tapTweak, taprootTweakPubkey } from "@scure/btc-signer/utils.js";
import {
  MAINNET_VERSIONS,
  TESTNET_VERSIONS,
  deriveDescriptorMiniscriptKeys,
  deriveDescriptorPayment,
} from "./address.js";
import { parseDescriptor, parseSignerDescriptor, type ParsedDescriptor } from "./descriptor.js";
import type { Network } from "./config.js";
import {
  isValidMusigTemplate,
  parseMusigTemplateKeys,
  parseTapscriptTemplate,
} from "./miniscript.js";
import {
  descriptorHasMusig2Path,
  PSBT_IN_MUSIG2_PARTIAL_SIG,
  PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
  PSBT_IN_MUSIG2_PUB_NONCE,
} from "./musig.js";
import { loadMusigNonce, removeMusigNonce, saveMusigNonce } from "./storage.js";
import { aggregateMusigCompressedPubkey, aggregateMusigPubkey, toXOnlyPubkey } from "./taproot.js";
import { bytesEqual, combinationIndices, compareBytes, concatBytes, hash160 } from "./utils.js";

type Bip32DerivationEntry = [Uint8Array, { fingerprint: number; path: number[] }];
type TapBip32DerivationEntry = [
  Uint8Array,
  { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } },
];
type TapScriptSigEntry = [{ pubKey: Uint8Array; leafHash: Uint8Array }, Uint8Array];
type PsbtUnknownEntry = [{ type: number; key: Uint8Array }, Uint8Array];

export interface MuSig2SigningContext {
  email: string;
  network: Network;
  walletId: string;
  txId: string;
  consumedNonceIds?: string[];
  maxPathScan?: number;
  now?: () => Date;
}

interface InputDerivationPath {
  chain: 0 | 1;
  index: number;
}

interface MusigParticipant {
  fingerprint?: number;
  path?: number[];
  pubkey: Uint8Array;
  xOnlyPubkey: Uint8Array;
}

interface MusigLeafCandidate {
  aggregatePubkey: Uint8Array;
  aggregateCompressedPubkey: Uint8Array;
  leafHash: Uint8Array;
  participants: MusigParticipant[];
  script: Uint8Array;
  version: number;
}

interface MusigKeypathCandidate {
  aggregateCompressedPubkey: Uint8Array;
  internalPubkey: Uint8Array;
  outputCompressedPubkey: Uint8Array;
  outputPubkey: Uint8Array;
  participants: MusigParticipant[];
  tweak: Uint8Array;
}

function toHex(data: Uint8Array): string {
  return Buffer.from(data).toString("hex");
}

function fromBase64(data: string): Uint8Array {
  return new Uint8Array(Buffer.from(data, "base64"));
}

function toBase64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

function numberToBytes32(value: bigint): Uint8Array {
  const result = new Uint8Array(32);
  let remaining = value;
  for (let i = 31; i >= 0; i--) {
    result[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) {
    throw new Error("Integer does not fit in 32 bytes");
  }
  return result;
}

function taprootKeypathTweak(internalPubkey: Uint8Array, merkleRoot?: Uint8Array): Uint8Array {
  return numberToBytes32(tapTweak(internalPubkey, merkleRoot ?? new Uint8Array()));
}

function compressedPubkeyFromXOnly(xOnlyPubkey: Uint8Array, parity: number): Uint8Array {
  return concatBytes([new Uint8Array([parity === 0 ? 0x02 : 0x03]), xOnlyPubkey]);
}

function inputTapLeaves(input: ReturnType<Transaction["getInput"]>): Array<{
  hash: Uint8Array;
  script: Uint8Array;
  version: number;
}> {
  const tapLeafScript = input.tapLeafScript as Array<[unknown, Uint8Array]> | undefined;
  if (!tapLeafScript) {
    return [];
  }

  return tapLeafScript.map(([, scriptWithVersion]) => {
    const script = scriptWithVersion.subarray(0, -1);
    const version = scriptWithVersion[scriptWithVersion.length - 1];
    return { hash: tapLeafHash(script, version), script, version };
  });
}

function inputPathCandidate(path: number[] | undefined): InputDerivationPath | null {
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

function inputDerivationPathCandidates(
  input: ReturnType<Transaction["getInput"]>,
): InputDerivationPath[] {
  const candidates: InputDerivationPath[] = [];
  const seen = new Set<string>();
  const addCandidate = (candidate: InputDerivationPath | null) => {
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

  const bip32Derivation = input.bip32Derivation as Bip32DerivationEntry[] | undefined;
  for (const [, { path }] of bip32Derivation ?? []) {
    addCandidate(inputPathCandidate(path));
  }

  const tapBip32Derivation = input.tapBip32Derivation as TapBip32DerivationEntry[] | undefined;
  for (const [, { der }] of tapBip32Derivation ?? []) {
    addCandidate(inputPathCandidate(der.path));
  }

  return candidates.sort((a, b) => a.chain - b.chain || a.index - b.index);
}

function getInputDerivationPath(
  input: ReturnType<Transaction["getInput"]>,
  descriptor: string,
  network: Network,
  maxScan = 1000,
): InputDerivationPath | null {
  const script = input.witnessUtxo?.script;
  const candidates = inputDerivationPathCandidates(input);
  if (!script) {
    return candidates.length === 1 ? candidates[0] : null;
  }

  const scriptHex = toHex(script);
  for (const { chain, index } of candidates) {
    try {
      const payment = deriveDescriptorPayment(descriptor, network, chain, index);
      if (toHex(payment.script) === scriptHex) {
        return { chain, index };
      }
    } catch {
      return null;
    }
  }

  for (const chain of [0, 1] as const) {
    for (let index = 0; index <= maxScan; index++) {
      try {
        const payment = deriveDescriptorPayment(descriptor, network, chain, index);
        if (toHex(payment.script) === scriptHex) {
          return { chain, index };
        }
      } catch {
        return null;
      }
    }
  }

  return null;
}

function deriveMultisigParticipants(
  signers: string[],
  network: Network,
  chain: 0 | 1,
  index: number,
): MusigParticipant[] {
  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  return signers.map((signer) => {
    const parsed = parseSignerDescriptor(signer);
    const child = HDKey.fromExtendedKey(parsed.xpub, versions)
      .deriveChild(chain)
      .deriveChild(index);
    if (!child.publicKey) {
      throw new Error("Failed to derive taproot MuSig participant key");
    }
    return {
      fingerprint: parseInt(parsed.masterFingerprint, 16),
      path: bip32Path(`m${parsed.derivationPath}/${chain}/${index}`),
      pubkey: child.publicKey,
      xOnlyPubkey: toXOnlyPubkey(child.publicKey),
    };
  });
}

function matchTapLeafCandidate(
  input: ReturnType<Transaction["getInput"]>,
  participants: MusigParticipant[],
): MusigLeafCandidate[] {
  const sorted = [...participants].sort((a, b) => compareBytes(a.pubkey, b.pubkey));
  const participantPubkeys = sorted.map((participant) => participant.pubkey);
  const aggregatePubkey = aggregateMusigPubkey(participantPubkeys);
  const aggregateCompressedPubkey = aggregateMusigCompressedPubkey(participantPubkeys);
  const script = p2tr_pk(aggregatePubkey).script;
  return inputTapLeaves(input)
    .filter((leaf) => bytesEqual(leaf.script, script))
    .map((leaf) => ({
      aggregatePubkey,
      aggregateCompressedPubkey,
      leafHash: leaf.hash,
      participants: sorted,
      script,
      version: leaf.version,
    }));
}

function taprootOutputKeyFromScript(script: Uint8Array): Uint8Array | null {
  if (script.length !== 34 || script[0] !== 0x51 || script[1] !== 0x20) {
    return null;
  }
  return script.subarray(2);
}

function matchKeypathCandidate(
  input: ReturnType<Transaction["getInput"]>,
  participants: MusigParticipant[],
): MusigKeypathCandidate[] {
  if (!input.tapInternalKey) {
    return [];
  }

  const sorted = [...participants].sort((a, b) => compareBytes(a.pubkey, b.pubkey));
  const participantPubkeys = sorted.map((participant) => participant.pubkey);
  const internalPubkey = aggregateMusigPubkey(participantPubkeys);
  const aggregateCompressedPubkey = aggregateMusigCompressedPubkey(participantPubkeys);
  if (!bytesEqual(internalPubkey, input.tapInternalKey)) {
    return [];
  }

  const merkleRoot = input.tapMerkleRoot ?? new Uint8Array();
  const tweak = taprootKeypathTweak(internalPubkey, merkleRoot);
  const [outputPubkey, outputParity] = taprootTweakPubkey(internalPubkey, merkleRoot);
  const outputCompressedPubkey = compressedPubkeyFromXOnly(outputPubkey, outputParity);
  const scriptOutputKey = input.witnessUtxo?.script
    ? taprootOutputKeyFromScript(input.witnessUtxo.script)
    : null;
  if (scriptOutputKey && !bytesEqual(scriptOutputKey, outputPubkey)) {
    return [];
  }

  return [
    {
      aggregateCompressedPubkey,
      internalPubkey,
      outputCompressedPubkey,
      outputPubkey,
      participants: sorted,
      tweak,
    },
  ];
}

function enumerateMultisigMusigCandidates(
  input: ReturnType<Transaction["getInput"]>,
  parsed: ParsedDescriptor,
  network: Network,
  path: InputDerivationPath,
): MusigLeafCandidate[] {
  if (parsed.kind !== "multisig" || parsed.addressType !== "TAPROOT") {
    return [];
  }

  const useMusigLeaves = parsed.n <= 5 || parsed.n === parsed.m;
  if (!useMusigLeaves) {
    return [];
  }

  const participants = deriveMultisigParticipants(parsed.signers, network, path.chain, path.index);
  return combinationIndices(participants.length, parsed.m).flatMap((indices) =>
    matchTapLeafCandidate(
      input,
      indices.map((index) => participants[index]),
    ),
  );
}

function enumerateMultisigKeypathCandidates(
  input: ReturnType<Transaction["getInput"]>,
  parsed: ParsedDescriptor,
  network: Network,
  path: InputDerivationPath,
): MusigKeypathCandidate[] {
  if (
    parsed.kind !== "multisig" ||
    parsed.addressType !== "TAPROOT" ||
    parsed.taprootWalletTemplate !== "DEFAULT"
  ) {
    return [];
  }

  const participants = deriveMultisigParticipants(parsed.signers, network, path.chain, path.index);
  const keypathIndices = combinationIndices(participants.length, parsed.m)[0];
  if (!keypathIndices) {
    return [];
  }
  return matchKeypathCandidate(
    input,
    keypathIndices.map((index) => participants[index]),
  );
}

function deriveMiniscriptKeypathParticipants(
  parsed: ParsedDescriptor,
  network: Network,
  chain: 0 | 1,
  index: number,
): MusigParticipant[] {
  if (parsed.kind !== "miniscript" || parsed.addressType !== "TAPROOT" || parsed.m <= 1) {
    return [];
  }

  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  return parsed.signers.slice(0, parsed.m).map((signer) => {
    const parsedSigner = parseSignerDescriptor(signer);
    const child = HDKey.fromExtendedKey(parsedSigner.xpub, versions)
      .deriveChild(chain)
      .deriveChild(index);
    if (!child.publicKey) {
      throw new Error("Failed to derive taproot miniscript MuSig keypath participant key");
    }
    return {
      fingerprint: parseInt(parsedSigner.masterFingerprint, 16),
      path: bip32Path(`m${parsedSigner.derivationPath}/${chain}/${index}`),
      pubkey: child.publicKey,
      xOnlyPubkey: toXOnlyPubkey(child.publicKey),
    };
  });
}

function enumerateMiniscriptKeypathCandidates(
  input: ReturnType<Transaction["getInput"]>,
  parsed: ParsedDescriptor,
  network: Network,
  path: InputDerivationPath,
): MusigKeypathCandidate[] {
  const participants = deriveMiniscriptKeypathParticipants(parsed, network, path.chain, path.index);
  return participants.length > 0 ? matchKeypathCandidate(input, participants) : [];
}

function enumerateMiniscriptMusigCandidates(
  input: ReturnType<Transaction["getInput"]>,
  descriptor: string,
  parsed: ParsedDescriptor,
  network: Network,
  path: InputDerivationPath,
): MusigLeafCandidate[] {
  if (parsed.kind !== "miniscript" || parsed.addressType !== "TAPROOT" || !parsed.miniscript) {
    return [];
  }

  const keyInfos = deriveDescriptorMiniscriptKeys(descriptor, network, path.chain, path.index);
  const keysByExpression = new Map(keyInfos.map((info) => [info.keyExpression, info]));
  const parsedTapscript = parseTapscriptTemplate(parsed.miniscript);
  const candidates: MusigLeafCandidate[] = [];

  for (const leaf of parsedTapscript.subscripts) {
    if (!isValidMusigTemplate(leaf)) {
      continue;
    }

    const participants: MusigParticipant[] = [];
    for (const keyExpression of parseMusigTemplateKeys(leaf)) {
      const info = keysByExpression.get(keyExpression);
      if (!info) {
        participants.length = 0;
        break;
      }
      participants.push({
        fingerprint: info.bip32?.fingerprint,
        path: info.bip32?.path,
        pubkey: info.pubkey,
        xOnlyPubkey: toXOnlyPubkey(info.pubkey),
      });
    }
    if (participants.length === 0) {
      continue;
    }

    candidates.push(...matchTapLeafCandidate(input, participants));
  }

  return candidates;
}

function enumerateKeypathCandidates(
  input: ReturnType<Transaction["getInput"]>,
  parsed: ParsedDescriptor,
  network: Network,
  path: InputDerivationPath,
): MusigKeypathCandidate[] {
  return [
    ...enumerateMultisigKeypathCandidates(input, parsed, network, path),
    ...enumerateMiniscriptKeypathCandidates(input, parsed, network, path),
  ];
}

function mutableInput(tx: Transaction, inputIndex: number): ReturnType<Transaction["getInput"]> {
  const inputs = (tx as unknown as { inputs?: Array<ReturnType<Transaction["getInput"]>> }).inputs;
  if (!inputs?.[inputIndex]) {
    throw new Error(`PSBT signer cannot access input ${inputIndex}`);
  }
  return inputs[inputIndex];
}

function getUnknownEntries(input: ReturnType<Transaction["getInput"]>): PsbtUnknownEntry[] {
  return (input.unknown as PsbtUnknownEntry[] | undefined) ?? [];
}

function musigParticipantFieldKey(aggregatePubkey: Uint8Array): Uint8Array {
  return aggregatePubkey;
}

function musigSignerFieldKey(
  signerPubkey: Uint8Array,
  aggregatePubkey: Uint8Array,
  leafHash?: Uint8Array,
): Uint8Array {
  return leafHash
    ? concatBytes([signerPubkey, aggregatePubkey, leafHash])
    : concatBytes([signerPubkey, aggregatePubkey]);
}

function addUnknownEntry(
  tx: Transaction,
  inputIndex: number,
  type: number,
  key: Uint8Array,
  value: Uint8Array,
): boolean {
  const input = mutableInput(tx, inputIndex);
  const entries = getUnknownEntries(input);
  for (const [existingKey, existingValue] of entries) {
    if (existingKey.type !== type || !bytesEqual(existingKey.key, key)) {
      continue;
    }
    if (!bytesEqual(existingValue, value)) {
      throw new Error("Conflicting MuSig2 PSBT field");
    }
    return false;
  }

  input.unknown = [...entries, [{ type, key }, value]] as typeof input.unknown;
  return true;
}

function ensureMusigParticipantsField(
  tx: Transaction,
  inputIndex: number,
  aggregatePubkey: Uint8Array,
  participants: MusigParticipant[],
): boolean {
  return addUnknownEntry(
    tx,
    inputIndex,
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    musigParticipantFieldKey(aggregatePubkey),
    concatBytes(participants.map((participant) => participant.pubkey)),
  );
}

function findMusigUnknownValue(
  input: ReturnType<Transaction["getInput"]>,
  type: number,
  aggregatePubkey: Uint8Array,
  signerPubkey: Uint8Array,
  leafHash?: Uint8Array,
): Uint8Array | null {
  const expectedKey = musigSignerFieldKey(signerPubkey, aggregatePubkey, leafHash);
  for (const [key, value] of getUnknownEntries(input)) {
    if (key.type === type && bytesEqual(key.key, expectedKey)) {
      return value;
    }
  }
  return null;
}

function hasAggregateTapScriptSig(
  input: ReturnType<Transaction["getInput"]>,
  leafHash: Uint8Array,
  aggregatePubkey: Uint8Array,
): boolean {
  const tapScriptSig = input.tapScriptSig as TapScriptSigEntry[] | undefined;
  return (
    tapScriptSig?.some(
      ([{ pubKey, leafHash: sigLeafHash }]) =>
        bytesEqual(pubKey, aggregatePubkey) && bytesEqual(sigLeafHash, leafHash),
    ) ?? false
  );
}

function addTapScriptSig(
  tx: Transaction,
  inputIndex: number,
  leafHash: Uint8Array,
  aggregatePubkey: Uint8Array,
  signature: Uint8Array,
): boolean {
  const input = mutableInput(tx, inputIndex);
  const existing = (input.tapScriptSig as TapScriptSigEntry[] | undefined) ?? [];
  for (const [key, value] of existing) {
    if (!bytesEqual(key.pubKey, aggregatePubkey) || !bytesEqual(key.leafHash, leafHash)) {
      continue;
    }
    if (!bytesEqual(value, signature)) {
      throw new Error("Conflicting MuSig2 aggregate taproot signature");
    }
    return false;
  }

  input.tapScriptSig = [...existing, [{ pubKey: aggregatePubkey, leafHash }, signature]];
  return true;
}

function appendTaprootSighash(signature: Uint8Array, sighash: number): Uint8Array {
  return sighash === SignatureHash.DEFAULT
    ? signature
    : concatBytes([signature, new Uint8Array([sighash])]);
}

function taprootScriptPathMessage(
  tx: Transaction,
  inputIndex: number,
  script: Uint8Array,
  version: number,
): { msg: Uint8Array; sighash: number } {
  const input = tx.getInput(inputIndex);
  const sighash = input.sighashType ?? SignatureHash.DEFAULT;
  const prevOuts = Array.from({ length: tx.inputsLength }, (_, index) =>
    getPrevOut(tx.getInput(index)),
  );
  const msg = tx.preimageWitnessV1(
    inputIndex,
    prevOuts.map((prevOut) => prevOut.script),
    sighash,
    prevOuts.map((prevOut) => prevOut.amount),
    undefined,
    script,
    version,
  );
  return { msg, sighash };
}

function buildNonceId(
  context: MuSig2SigningContext,
  inputIndex: number,
  leafHash: Uint8Array,
  signerPubkey: Uint8Array,
  msg: Uint8Array,
): string {
  return crypto
    .createHash("sha256")
    .update(context.walletId)
    .update("\0")
    .update(context.txId)
    .update("\0")
    .update(String(inputIndex))
    .update("\0")
    .update(leafHash)
    .update(signerPubkey)
    .update(msg)
    .digest("hex");
}

function buildNonceExtraInput(
  context: MuSig2SigningContext,
  inputIndex: number,
  leafHash: Uint8Array,
  signerPubkey: Uint8Array,
): Uint8Array {
  return Buffer.from(
    `${context.walletId}:${context.txId}:${inputIndex}:${toHex(leafHash)}:${toHex(signerPubkey)}`,
    "utf8",
  );
}

function consumeMusigNonce(context: MuSig2SigningContext, nonceId: string): void {
  if (context.consumedNonceIds) {
    context.consumedNonceIds.push(nonceId);
    return;
  }
  removeMusigNonce(context.email, context.network, nonceId);
}

function getCandidatePublicNonces(
  input: ReturnType<Transaction["getInput"]>,
  aggregatePubkey: Uint8Array,
  participants: MusigParticipant[],
  leafHash?: Uint8Array,
): Uint8Array[] | null {
  const nonces: Uint8Array[] = [];
  for (const participant of participants) {
    const nonce = findMusigUnknownValue(
      input,
      PSBT_IN_MUSIG2_PUB_NONCE,
      aggregatePubkey,
      participant.pubkey,
      leafHash,
    );
    if (!nonce) {
      return null;
    }
    nonces.push(nonce);
  }
  return nonces;
}

function getCandidatePartialSignatures(
  input: ReturnType<Transaction["getInput"]>,
  aggregatePubkey: Uint8Array,
  participants: MusigParticipant[],
  leafHash?: Uint8Array,
): Uint8Array[] | null {
  const partialSigs: Uint8Array[] = [];
  for (const participant of participants) {
    const partialSig = findMusigUnknownValue(
      input,
      PSBT_IN_MUSIG2_PARTIAL_SIG,
      aggregatePubkey,
      participant.pubkey,
      leafHash,
    );
    if (!partialSig) {
      return null;
    }
    partialSigs.push(partialSig);
  }
  return partialSigs;
}

function findSignerParticipant(
  candidate: MusigLeafCandidate,
  signerKey: HDKey,
  xfpInt: number,
): {
  childKey: HDKey;
  index: number;
  participant: MusigParticipant;
  privateKey: Uint8Array;
} | null {
  for (let index = 0; index < candidate.participants.length; index++) {
    const participant = candidate.participants[index];
    if (participant.fingerprint !== xfpInt || !participant.path) {
      continue;
    }

    const childKey = deriveSignerChildKey(signerKey, participant.path, participant.pubkey);
    if (childKey?.privateKey && childKey.publicKey) {
      return { childKey, index, participant, privateKey: childKey.privateKey };
    }
  }
  return null;
}

function aggregateMuSigIfReady(
  tx: Transaction,
  inputIndex: number,
  candidate: MusigLeafCandidate,
  msg: Uint8Array,
  sighash: number,
): boolean {
  const input = tx.getInput(inputIndex);
  if (hasAggregateTapScriptSig(input, candidate.leafHash, candidate.aggregatePubkey)) {
    return false;
  }

  const publicNonces = getCandidatePublicNonces(
    input,
    candidate.aggregateCompressedPubkey,
    candidate.participants,
    candidate.leafHash,
  );
  const partialSigs = getCandidatePartialSignatures(
    input,
    candidate.aggregateCompressedPubkey,
    candidate.participants,
    candidate.leafHash,
  );
  if (!publicNonces || !partialSigs) {
    return false;
  }

  const aggregateNonce = musig2.nonceAggregate(publicNonces);
  const session = new musig2.Session(
    aggregateNonce,
    candidate.participants.map((participant) => participant.pubkey),
    msg,
  );
  partialSigs.forEach((partialSig, index) => {
    if (!session.partialSigVerify(partialSig, publicNonces, index)) {
      throw new Error(`Invalid MuSig2 partial signature for participant ${index}`);
    }
  });

  const finalSig = appendTaprootSighash(session.partialSigAgg(partialSigs), sighash);
  return addTapScriptSig(tx, inputIndex, candidate.leafHash, candidate.aggregatePubkey, finalSig);
}

function addTapKeySig(tx: Transaction, inputIndex: number, signature: Uint8Array): boolean {
  const input = mutableInput(tx, inputIndex);
  if (input.tapKeySig) {
    if (!bytesEqual(input.tapKeySig, signature)) {
      throw new Error("Conflicting MuSig2 aggregate taproot key-path signature");
    }
    return false;
  }

  input.tapKeySig = signature;
  return true;
}

function taprootKeypathMessage(
  tx: Transaction,
  inputIndex: number,
): { msg: Uint8Array; sighash: number } {
  const input = tx.getInput(inputIndex);
  const sighash = input.sighashType ?? SignatureHash.DEFAULT;
  const prevOuts = Array.from({ length: tx.inputsLength }, (_, index) =>
    getPrevOut(tx.getInput(index)),
  );
  const msg = tx.preimageWitnessV1(
    inputIndex,
    prevOuts.map((prevOut) => prevOut.script),
    sighash,
    prevOuts.map((prevOut) => prevOut.amount),
  );
  return { msg, sighash };
}

function aggregateKeypathMuSigIfReady(
  tx: Transaction,
  inputIndex: number,
  candidate: MusigKeypathCandidate,
  msg: Uint8Array,
  sighash: number,
): boolean {
  const input = tx.getInput(inputIndex);
  if (input.tapKeySig) {
    return false;
  }

  const publicNonces = getCandidatePublicNonces(
    input,
    candidate.outputCompressedPubkey,
    candidate.participants,
  );
  const partialSigs = getCandidatePartialSignatures(
    input,
    candidate.outputCompressedPubkey,
    candidate.participants,
  );
  if (!publicNonces || !partialSigs) {
    return false;
  }

  const aggregateNonce = musig2.nonceAggregate(publicNonces);
  const session = new musig2.Session(
    aggregateNonce,
    candidate.participants.map((participant) => participant.pubkey),
    msg,
    [candidate.tweak],
    [true],
  );
  partialSigs.forEach((partialSig, index) => {
    if (!session.partialSigVerify(partialSig, publicNonces, index)) {
      throw new Error(`Invalid MuSig2 key-path partial signature for participant ${index}`);
    }
  });

  const finalSig = appendTaprootSighash(session.partialSigAgg(partialSigs), sighash);
  return addTapKeySig(tx, inputIndex, finalSig);
}

function signTaprootKeypathMusigCandidate(
  tx: Transaction,
  inputIndex: number,
  candidate: MusigKeypathCandidate,
  signerKey: HDKey,
  xfpInt: number,
  context: MuSig2SigningContext,
): boolean {
  const keypathLeafHash = new Uint8Array();
  const signer = findSignerParticipant(
    {
      aggregatePubkey: candidate.internalPubkey,
      aggregateCompressedPubkey: candidate.aggregateCompressedPubkey,
      leafHash: keypathLeafHash,
      participants: candidate.participants,
      script: new Uint8Array(),
      version: 0xc0,
    },
    signerKey,
    xfpInt,
  );
  const { msg, sighash } = taprootKeypathMessage(tx, inputIndex);

  if (aggregateKeypathMuSigIfReady(tx, inputIndex, candidate, msg, sighash)) {
    return true;
  }
  if (!signer) {
    return false;
  }

  const nonceId = buildNonceId(
    context,
    inputIndex,
    keypathLeafHash,
    signer.participant.pubkey,
    msg,
  );
  const existingInput = tx.getInput(inputIndex);
  const existingPublicNonce = findMusigUnknownValue(
    existingInput,
    PSBT_IN_MUSIG2_PUB_NONCE,
    candidate.outputCompressedPubkey,
    signer.participant.pubkey,
  );

  if (!existingPublicNonce) {
    const nonces = musig2.nonceGen(
      signer.participant.pubkey,
      signer.privateKey,
      candidate.internalPubkey,
      msg,
      buildNonceExtraInput(context, inputIndex, keypathLeafHash, signer.participant.pubkey),
    );
    const createdAt = (context.now?.() ?? new Date()).toISOString();
    saveMusigNonce(context.email, context.network, {
      nonceId,
      walletId: context.walletId,
      txId: context.txId,
      inputIndex,
      leafHash: toHex(keypathLeafHash),
      signerPubkey: toHex(signer.participant.pubkey),
      signerFingerprint: xfpInt.toString(16).padStart(8, "0"),
      msg: toHex(msg),
      publicNonce: toBase64(nonces.public),
      secretNonce: toBase64(nonces.secret),
      createdAt,
    });

    const didAddParticipants = ensureMusigParticipantsField(
      tx,
      inputIndex,
      candidate.aggregateCompressedPubkey,
      candidate.participants,
    );
    const didAddNonce = addUnknownEntry(
      tx,
      inputIndex,
      PSBT_IN_MUSIG2_PUB_NONCE,
      musigSignerFieldKey(signer.participant.pubkey, candidate.outputCompressedPubkey),
      nonces.public,
    );
    return didAddParticipants || didAddNonce;
  }

  const refreshedInput = tx.getInput(inputIndex);
  const publicNonces = getCandidatePublicNonces(
    refreshedInput,
    candidate.outputCompressedPubkey,
    candidate.participants,
  );
  if (!publicNonces) {
    return false;
  }

  const existingPartialSig = findMusigUnknownValue(
    refreshedInput,
    PSBT_IN_MUSIG2_PARTIAL_SIG,
    candidate.outputCompressedPubkey,
    signer.participant.pubkey,
  );
  if (!existingPartialSig) {
    const stored = loadMusigNonce(context.email, context.network, nonceId);
    if (!stored) {
      throw new Error(
        "Missing local MuSig2 secret nonce. Recreate this transaction or sign from the device that published the nonce.",
      );
    }
    if (
      stored.msg !== toHex(msg) ||
      stored.leafHash !== toHex(keypathLeafHash) ||
      stored.signerPubkey !== toHex(signer.participant.pubkey) ||
      !bytesEqual(fromBase64(stored.publicNonce), existingPublicNonce)
    ) {
      removeMusigNonce(context.email, context.network, nonceId);
      throw new Error(
        "Local MuSig2 nonce does not match this PSBT. Recreate the transaction to avoid nonce reuse.",
      );
    }

    const aggregateNonce = musig2.nonceAggregate(publicNonces);
    const session = new musig2.Session(
      aggregateNonce,
      candidate.participants.map((participant) => participant.pubkey),
      msg,
      [candidate.tweak],
      [true],
    );
    const partialSig = session.sign(
      new Uint8Array(fromBase64(stored.secretNonce)),
      signer.privateKey,
    );
    if (!session.partialSigVerify(partialSig, publicNonces, signer.index)) {
      throw new Error("Generated MuSig2 key-path partial signature failed verification");
    }

    consumeMusigNonce(context, nonceId);
    const didAddParticipants = ensureMusigParticipantsField(
      tx,
      inputIndex,
      candidate.aggregateCompressedPubkey,
      candidate.participants,
    );
    const didAddPartialSig = addUnknownEntry(
      tx,
      inputIndex,
      PSBT_IN_MUSIG2_PARTIAL_SIG,
      musigSignerFieldKey(signer.participant.pubkey, candidate.outputCompressedPubkey),
      partialSig,
    );
    const didAggregate = aggregateKeypathMuSigIfReady(tx, inputIndex, candidate, msg, sighash);
    return didAddParticipants || didAddPartialSig || didAggregate;
  }

  return aggregateKeypathMuSigIfReady(tx, inputIndex, candidate, msg, sighash);
}

function signTaprootMusigCandidate(
  tx: Transaction,
  inputIndex: number,
  candidate: MusigLeafCandidate,
  signerKey: HDKey,
  xfpInt: number,
  context: MuSig2SigningContext,
): boolean {
  const signer = findSignerParticipant(candidate, signerKey, xfpInt);
  const { msg, sighash } = taprootScriptPathMessage(
    tx,
    inputIndex,
    candidate.script,
    candidate.version,
  );

  if (aggregateMuSigIfReady(tx, inputIndex, candidate, msg, sighash)) {
    return true;
  }
  if (!signer) {
    return false;
  }

  const nonceId = buildNonceId(
    context,
    inputIndex,
    candidate.leafHash,
    signer.participant.pubkey,
    msg,
  );
  const existingInput = tx.getInput(inputIndex);
  const existingPublicNonce = findMusigUnknownValue(
    existingInput,
    PSBT_IN_MUSIG2_PUB_NONCE,
    candidate.aggregateCompressedPubkey,
    signer.participant.pubkey,
    candidate.leafHash,
  );

  if (!existingPublicNonce) {
    const nonces = musig2.nonceGen(
      signer.participant.pubkey,
      signer.privateKey,
      candidate.aggregatePubkey,
      msg,
      buildNonceExtraInput(context, inputIndex, candidate.leafHash, signer.participant.pubkey),
    );
    const createdAt = (context.now?.() ?? new Date()).toISOString();
    saveMusigNonce(context.email, context.network, {
      nonceId,
      walletId: context.walletId,
      txId: context.txId,
      inputIndex,
      leafHash: toHex(candidate.leafHash),
      signerPubkey: toHex(signer.participant.pubkey),
      signerFingerprint: xfpInt.toString(16).padStart(8, "0"),
      msg: toHex(msg),
      publicNonce: toBase64(nonces.public),
      secretNonce: toBase64(nonces.secret),
      createdAt,
    });

    const didAddParticipants = ensureMusigParticipantsField(
      tx,
      inputIndex,
      candidate.aggregateCompressedPubkey,
      candidate.participants,
    );
    const didAddNonce = addUnknownEntry(
      tx,
      inputIndex,
      PSBT_IN_MUSIG2_PUB_NONCE,
      musigSignerFieldKey(
        signer.participant.pubkey,
        candidate.aggregateCompressedPubkey,
        candidate.leafHash,
      ),
      nonces.public,
    );
    return didAddParticipants || didAddNonce;
  }

  const refreshedInput = tx.getInput(inputIndex);
  const publicNonces = getCandidatePublicNonces(
    refreshedInput,
    candidate.aggregateCompressedPubkey,
    candidate.participants,
    candidate.leafHash,
  );
  if (!publicNonces) {
    return false;
  }

  const existingPartialSig = findMusigUnknownValue(
    refreshedInput,
    PSBT_IN_MUSIG2_PARTIAL_SIG,
    candidate.aggregateCompressedPubkey,
    signer.participant.pubkey,
    candidate.leafHash,
  );
  if (!existingPartialSig) {
    const stored = loadMusigNonce(context.email, context.network, nonceId);
    if (!stored) {
      throw new Error(
        "Missing local MuSig2 secret nonce. Recreate this transaction or sign from the device that published the nonce.",
      );
    }
    if (
      stored.msg !== toHex(msg) ||
      stored.leafHash !== toHex(candidate.leafHash) ||
      stored.signerPubkey !== toHex(signer.participant.pubkey) ||
      !bytesEqual(fromBase64(stored.publicNonce), existingPublicNonce)
    ) {
      removeMusigNonce(context.email, context.network, nonceId);
      throw new Error(
        "Local MuSig2 nonce does not match this PSBT. Recreate the transaction to avoid nonce reuse.",
      );
    }

    const aggregateNonce = musig2.nonceAggregate(publicNonces);
    const session = new musig2.Session(
      aggregateNonce,
      candidate.participants.map((participant) => participant.pubkey),
      msg,
    );
    const partialSig = session.sign(
      new Uint8Array(fromBase64(stored.secretNonce)),
      signer.privateKey,
    );
    if (!session.partialSigVerify(partialSig, publicNonces, signer.index)) {
      throw new Error("Generated MuSig2 partial signature failed verification");
    }

    consumeMusigNonce(context, nonceId);
    const didAddParticipants = ensureMusigParticipantsField(
      tx,
      inputIndex,
      candidate.aggregateCompressedPubkey,
      candidate.participants,
    );
    const didAddPartialSig = addUnknownEntry(
      tx,
      inputIndex,
      PSBT_IN_MUSIG2_PARTIAL_SIG,
      musigSignerFieldKey(
        signer.participant.pubkey,
        candidate.aggregateCompressedPubkey,
        candidate.leafHash,
      ),
      partialSig,
    );
    const didAggregate = aggregateMuSigIfReady(tx, inputIndex, candidate, msg, sighash);
    return didAddParticipants || didAddPartialSig || didAggregate;
  }

  return aggregateMuSigIfReady(tx, inputIndex, candidate, msg, sighash);
}

function signTaprootMusigInput(
  tx: Transaction,
  inputIndex: number,
  signerKey: HDKey,
  xfpInt: number,
  descriptor: string,
  parsedDescriptor: ParsedDescriptor,
  context: MuSig2SigningContext | undefined,
): number {
  const input = tx.getInput(inputIndex);
  const isTaprootDescriptor =
    (parsedDescriptor.kind === "multisig" || parsedDescriptor.kind === "miniscript") &&
    parsedDescriptor.addressType === "TAPROOT";
  if (!isTaprootDescriptor) {
    return 0;
  }
  if (!context) {
    if (descriptorHasMusig2Path(parsedDescriptor)) {
      throw new Error("Taproot MuSig signing requires local MuSig2 nonce storage context");
    }
    return 0;
  }

  const path = getInputDerivationPath(input, descriptor, context.network, context.maxPathScan);
  if (!path) {
    return 0;
  }

  let changed = 0;
  for (const candidate of enumerateKeypathCandidates(
    input,
    parsedDescriptor,
    context.network,
    path,
  )) {
    if (signTaprootKeypathMusigCandidate(tx, inputIndex, candidate, signerKey, xfpInt, context)) {
      changed++;
    }
  }

  for (const candidate of [
    ...enumerateMultisigMusigCandidates(input, parsedDescriptor, context.network, path),
    ...enumerateMiniscriptMusigCandidates(
      input,
      descriptor,
      parsedDescriptor,
      context.network,
      path,
    ),
  ]) {
    if (signTaprootMusigCandidate(tx, inputIndex, candidate, signerKey, xfpInt, context)) {
      changed++;
    }
  }
  return changed;
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

function deriveSignerTaprootChildKey(
  signerKey: HDKey,
  path: number[],
  expectedXOnlyPubkey: Uint8Array,
): HDKey | null {
  if (path.length < signerKey.depth) {
    return null;
  }

  let current = signerKey;
  for (const child of path.slice(signerKey.depth)) {
    current = current.deriveChild(child);
  }

  if (!current.publicKey || !bytesEqual(toXOnlyPubkey(current.publicKey), expectedXOnlyPubkey)) {
    return null;
  }

  return current;
}

function candidateHasSignerParticipant(
  candidate: MusigLeafCandidate | MusigKeypathCandidate,
  xfpInt: number,
): MusigParticipant | null {
  return candidate.participants.find((participant) => participant.fingerprint === xfpInt) ?? null;
}

function hasSignerCompletedTaprootMusigPsbt(
  tx: Transaction,
  xfpInt: number,
  descriptor: string,
  parsed: ParsedDescriptor,
  network: Network,
): boolean | null {
  if (!descriptorHasMusig2Path(parsed)) {
    return null;
  }

  let sawRelevantCandidate = false;

  for (let inputIndex = 0; inputIndex < tx.inputsLength; inputIndex++) {
    const input = tx.getInput(inputIndex);
    const path = getInputDerivationPath(input, descriptor, network);
    if (!path) {
      return false;
    }

    for (const candidate of enumerateKeypathCandidates(input, parsed, network, path)) {
      const participant = candidateHasSignerParticipant(candidate, xfpInt);
      if (!participant) {
        continue;
      }

      sawRelevantCandidate = true;
      if (input.tapKeySig) {
        continue;
      }

      const partialSig = findMusigUnknownValue(
        input,
        PSBT_IN_MUSIG2_PARTIAL_SIG,
        candidate.outputCompressedPubkey,
        participant.pubkey,
      );
      if (!partialSig) {
        return false;
      }
    }

    for (const candidate of [
      ...enumerateMultisigMusigCandidates(input, parsed, network, path),
      ...enumerateMiniscriptMusigCandidates(input, descriptor, parsed, network, path),
    ]) {
      const participant = candidateHasSignerParticipant(candidate, xfpInt);
      if (!participant) {
        continue;
      }

      sawRelevantCandidate = true;
      if (hasAggregateTapScriptSig(input, candidate.leafHash, candidate.aggregatePubkey)) {
        continue;
      }

      const partialSig = findMusigUnknownValue(
        input,
        PSBT_IN_MUSIG2_PARTIAL_SIG,
        candidate.aggregateCompressedPubkey,
        participant.pubkey,
        candidate.leafHash,
      );
      if (!partialSig) {
        return false;
      }
    }
  }

  return sawRelevantCandidate ? true : null;
}

export function hasWalletSignerSignedPsbt(
  tx: Transaction,
  xfpInt: number,
  walletDescriptor?: string,
  network?: Network,
): boolean {
  if (tx.inputsLength === 0) {
    return false;
  }

  const input = tx.getInput(0);
  const partialSig = input.partialSig as Array<[Uint8Array, Uint8Array]> | undefined;
  const bip32Derivation = input.bip32Derivation as Bip32DerivationEntry[] | undefined;
  if (partialSig && bip32Derivation) {
    for (const [pubkey] of partialSig) {
      for (const [bip32Pub, { fingerprint }] of bip32Derivation) {
        if (fingerprint === xfpInt && bytesEqual(pubkey, bip32Pub)) {
          return true;
        }
      }
    }
  }

  const parsedDescriptor = walletDescriptor && network ? parseDescriptor(walletDescriptor) : null;
  if (walletDescriptor && network && parsedDescriptor) {
    const musigSigned = hasSignerCompletedTaprootMusigPsbt(
      tx,
      xfpInt,
      walletDescriptor,
      parsedDescriptor,
      network,
    );
    if (musigSigned !== null) {
      return musigSigned;
    }
  }

  const tapBip32Derivation = input.tapBip32Derivation as TapBip32DerivationEntry[] | undefined;
  if (
    input.tapKeySig &&
    tapBip32Derivation?.some(
      ([, { der, hashes }]) => der.fingerprint === xfpInt && hashes.length === 0,
    )
  ) {
    return true;
  }

  const tapScriptSig = input.tapScriptSig as TapScriptSigEntry[] | undefined;
  if (tapScriptSig && tapBip32Derivation) {
    const fingerprintsByPubkey = new Map<string, number>();
    for (const [pubkey, { der }] of tapBip32Derivation) {
      fingerprintsByPubkey.set(toHex(pubkey), der.fingerprint);
    }
    for (const [{ pubKey }] of tapScriptSig) {
      if (fingerprintsByPubkey.get(toHex(pubKey)) === xfpInt) {
        return true;
      }
    }
  }

  if (walletDescriptor && network && parsedDescriptor) {
    const path = getInputDerivationPath(input, walletDescriptor, network);
    if (path) {
      const candidates = [
        ...enumerateMultisigMusigCandidates(input, parsedDescriptor, network, path),
        ...enumerateMiniscriptMusigCandidates(
          input,
          walletDescriptor,
          parsedDescriptor,
          network,
          path,
        ),
      ];
      for (const candidate of candidates) {
        if (
          candidate.participants.some((participant) => participant.fingerprint === xfpInt) &&
          hasAggregateTapScriptSig(input, candidate.leafHash, candidate.aggregatePubkey)
        ) {
          return true;
        }
        const signerParticipant = candidate.participants.find(
          (participant) => participant.fingerprint === xfpInt,
        );
        if (
          signerParticipant &&
          findMusigUnknownValue(
            input,
            PSBT_IN_MUSIG2_PARTIAL_SIG,
            candidate.aggregateCompressedPubkey,
            signerParticipant.pubkey,
            candidate.leafHash,
          )
        ) {
          return true;
        }
      }
    }
  }

  if (walletDescriptor && network && parsedDescriptor) {
    const path = getInputDerivationPath(input, walletDescriptor, network);
    if (path) {
      const candidates = enumerateKeypathCandidates(input, parsedDescriptor, network, path);
      if (
        input.tapKeySig &&
        candidates.some((candidate) =>
          candidate.participants.some((participant) => participant.fingerprint === xfpInt),
        )
      ) {
        return true;
      }
      for (const candidate of candidates) {
        const signerParticipant = candidate.participants.find(
          (participant) => participant.fingerprint === xfpInt,
        );
        if (
          signerParticipant &&
          findMusigUnknownValue(
            input,
            PSBT_IN_MUSIG2_PARTIAL_SIG,
            candidate.outputCompressedPubkey,
            signerParticipant.pubkey,
          )
        ) {
          return true;
        }
      }
    }
  }

  return false;
}

export function signWalletPsbtWithKey(
  tx: Transaction,
  signerKey: HDKey,
  xfpInt: number,
  walletDescriptor?: string,
  musigContext?: MuSig2SigningContext,
): number {
  const parsedDescriptor = walletDescriptor ? parseDescriptor(walletDescriptor) : null;
  const isMiniscript = parsedDescriptor?.kind === "miniscript";
  const isTaprootDescriptor =
    parsedDescriptor?.addressType === "TAPROOT" &&
    (parsedDescriptor.kind === "multisig" || parsedDescriptor.kind === "miniscript");

  let signed = 0;
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    const bip32Derivation = input.bip32Derivation as Bip32DerivationEntry[] | undefined;

    if (bip32Derivation) {
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

    if (walletDescriptor && parsedDescriptor) {
      const musigSigned = signTaprootMusigInput(
        tx,
        i,
        signerKey,
        xfpInt,
        walletDescriptor,
        parsedDescriptor,
        musigContext,
      );
      signed += musigSigned;
      if (musigSigned > 0) {
        continue;
      }
    }

    const tapBip32Derivation = input.tapBip32Derivation as TapBip32DerivationEntry[] | undefined;
    if (!tapBip32Derivation) {
      continue;
    }

    for (const [pubkey, { der }] of tapBip32Derivation) {
      if (der.fingerprint !== xfpInt) {
        continue;
      }

      const childKey = deriveSignerTaprootChildKey(signerKey, der.path, pubkey);
      if (!childKey?.privateKey) {
        continue;
      }

      try {
        tx.signIdx(childKey.privateKey, i);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (isTaprootDescriptor && message === "No taproot scripts signed") {
          continue;
        }
        throw err;
      }
      signed++;
      break;
    }
  }

  return signed;
}
