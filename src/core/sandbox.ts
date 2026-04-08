import { publicBox, publicOpen } from "./crypto.js";
import { buildWalletDescriptor, buildAnyDescriptor, getWalletId } from "./descriptor.js";
import { deriveRootKeyFromDescriptor, deriveSecretboxKey, deriveGID } from "./wallet-keys.js";
import type { Network } from "./config.js";
import type { PlatformKeyPolicies, PlatformKeyConfig } from "./platform-key.js";
import { ADDRESS_TYPE_TO_NUMBER, type AddressType } from "./address-type.js";
import { isRecord } from "./utils.js";

const VERSION = 1;

// Matches libnunchuk's FormalizePath: strip leading "m", replace "h" with "'", ensure leading "/"
function formalizePath(path: string): string {
  let rs = path;
  if (rs.startsWith("m")) rs = rs.slice(1);
  rs = rs.replaceAll("h", "'");
  if (rs.length > 0 && rs[0] !== "/") rs = "/" + rs;
  return rs;
}

// Matches libnunchuk's SingleSigner::get_descriptor: "[xfp/path]xpub"
export function buildSignerDescriptor(
  masterFingerprint: string,
  derivationPath: string,
  xpub: string,
): string {
  return `[${masterFingerprint}${formalizePath(derivationPath)}]${xpub}`;
}

export function buildCreateGroupBody(
  name: string,
  m: number,
  n: number,
  addressType: AddressType,
  ephemeralPub: string,
  ephemeralPriv: string,
): string {
  // Build signers array — "[]" is the empty placeholder matching C++ SingleSigner::get_descriptor()
  const signers: string[] = [];
  for (let i = 0; i < n; i++) {
    signers.push("[]");
  }

  // Encrypt state for our own ephemeral key
  const plaintext = JSON.stringify({ signers });
  const state: Record<string, string> = {};
  state[ephemeralPub] = publicBox(plaintext, ephemeralPub, ephemeralPriv, ephemeralPub);

  const pubstate = {
    m,
    n,
    addressType: ADDRESS_TYPE_TO_NUMBER[addressType],
    walletTemplate: 0,
    miniscriptTemplate: "",
    name,
    occupied: [] as unknown[],
    added: [] as number[],
  };

  const data = {
    version: VERSION,
    stateId: 1,
    state,
    pubstate,
    modified: {},
  };

  const body = {
    group_id: "",
    type: "init",
    data,
  };

  return JSON.stringify(body);
}

// Matches libnunchuk's SendGroupEvent: increment stateId, wrap as event JSON.
// Shared by all init-phase operations (join, add-key, platform-key).
// Does NOT apply to finalize (different type and data structure).
function buildGroupEvent(groupId: string, init: Record<string, unknown>, stateId: number): string {
  init.stateId = stateId + 1;
  return JSON.stringify({ group_id: groupId, type: "init", data: init });
}

function getGroupPhaseData(groupJson: Record<string, unknown>): {
  phase: "init" | "finalize";
  data: Record<string, unknown>;
} {
  const status = groupJson.status;
  const init = groupJson.init;
  const finalize = groupJson.finalize;

  if (status === "ACTIVE") {
    if (!isRecord(finalize)) {
      throw new Error("Invalid group payload: missing finalize data for active group");
    }
    return { phase: "finalize", data: finalize };
  }

  if (isRecord(init)) {
    return { phase: "init", data: init };
  }

  if (isRecord(finalize)) {
    return { phase: "finalize", data: finalize };
  }

  throw new Error("Invalid group payload: missing group state");
}

export function isGroupFinalized(groupJson: Record<string, unknown>): boolean {
  return getGroupPhaseData(groupJson).phase === "finalize";
}

// Matches libnunchuk's GroupService::JoinGroup (groupservice.cpp:579-598).
// Join-specific logic is just adding ephemeral key to state; rest is shared via buildGroupEvent.
export function buildJoinGroupEvent(
  groupId: string,
  groupJson: Record<string, unknown>,
  ephemeralPub: string,
): string {
  const { phase, data: init } = getGroupPhaseData(groupJson);
  if (phase !== "init") {
    throw new Error("Cannot join: group is already finalized");
  }
  const state = init.state as Record<string, string>;
  if (state[ephemeralPub] !== undefined) {
    throw new Error("Already joined this sandbox");
  }
  state[ephemeralPub] = "";
  return buildGroupEvent(groupId, init, init.stateId as number);
}

function decryptSignerSet(ciphertext: string | undefined, ephemeralPriv: string): string[] | null {
  if (!ciphertext) {
    return null;
  }

  try {
    const decrypted = JSON.parse(publicOpen(ciphertext, ephemeralPriv)) as {
      signers?: string[];
    };
    if (!Array.isArray(decrypted.signers)) {
      return null;
    }
    return decrypted.signers.map((signer) => (isEmptySigner(signer) ? "[]" : signer));
  } catch {
    return null;
  }
}

function mergeSigners(base: string[], incoming: string[]): void {
  for (let i = 0; i < base.length; i++) {
    if (isEmptySigner(base[i]) && !isEmptySigner(incoming[i])) {
      base[i] = incoming[i];
    }
  }
}

export interface GroupDisplayState {
  addressType: number;
  added: number[];
  m: number;
  n: number;
  name: string;
  occupied: Array<{ slot: number; ts: number; uid: string }>;
  participants: number;
  signers: string[];
  status: string;
  url: string;
}

export function getGroupDisplayState(
  groupJson: Record<string, unknown>,
  ephemeralPub: string,
  ephemeralPriv: string,
): GroupDisplayState {
  const { data } = getGroupPhaseData(groupJson);
  const pubstate = data.pubstate as Record<string, unknown>;
  const state = (data.state ?? {}) as Record<string, string>;
  const modified = (data.modified ?? {}) as Record<string, Record<string, string>>;
  const n = Number(pubstate.n ?? 0);

  let signers = Array.from({ length: n }, () => "[]");
  const stateSigners = decryptSignerSet(state[ephemeralPub], ephemeralPriv);
  if (stateSigners) {
    signers = stateSigners;
  } else {
    const ownModified = modified[ephemeralPub];
    const modifiedSigners = ownModified
      ? getModifiedSigners(ownModified, ephemeralPub, ephemeralPriv, n)
      : null;
    if (modifiedSigners) {
      signers = modifiedSigners.map((signer) => (isEmptySigner(signer) ? "[]" : signer));
    }
  }

  for (const participantModified of Object.values(modified)) {
    const modifiedCiphertexts = participantModified as Record<string, string>;
    const incoming = decryptSignerSet(modifiedCiphertexts[ephemeralPub], ephemeralPriv);
    if (incoming) {
      mergeSigners(signers, incoming);
    }
  }

  const derivedAdded = signers
    .map((signer, index) => (!isEmptySigner(signer) ? index : -1))
    .filter((index) => index >= 0);
  const fallbackAdded = Array.isArray(pubstate.added)
    ? pubstate.added.filter((item): item is number => typeof item === "number")
    : [];
  const occupied = Array.isArray(pubstate.occupied)
    ? pubstate.occupied.flatMap((item) => {
        if (typeof item !== "object" || item === null) {
          return [];
        }

        const slot = "i" in item ? item.i : undefined;
        const ts = "ts" in item ? item.ts : undefined;
        const uid = "uid" in item ? item.uid : undefined;
        if (typeof slot !== "number" || typeof ts !== "number" || typeof uid !== "string") {
          return [];
        }

        return [{ slot, ts, uid }];
      })
    : [];

  return {
    addressType: Number(pubstate.addressType ?? 0),
    added: derivedAdded.length > 0 ? derivedAdded : fallbackAdded,
    m: Number(pubstate.m ?? 0),
    n,
    name: String(pubstate.name ?? ""),
    occupied,
    participants: Object.keys(state).length,
    signers,
    status: String(groupJson.status ?? ""),
    url: String(groupJson.url ?? ""),
  };
}

// Matches libnunchuk's GroupService::GetModifiedSigners
function getModifiedSigners(
  modified: Record<string, string>,
  ephemeralPub: string,
  ephemeralPriv: string,
  n: number,
): string[] {
  if (modified[ephemeralPub]) {
    const ciphertext = modified[ephemeralPub];
    const decrypted = JSON.parse(publicOpen(ciphertext, ephemeralPriv));
    return decrypted.signers as string[];
  }
  return Array.from({ length: n }, () => "[]");
}

function isEmptySigner(desc: string): boolean {
  return desc === "[]" || desc === "";
}

// Matches libnunchuk's GroupService::UpdateSignersJson
function updateSignersJson(
  currentSigners: string[],
  newDescriptor: string,
  index: number,
  n: number,
): string[] {
  // Normalize empty slots to "[]" (C++ placeholder)
  const signers = currentSigners.map((s) => (isEmptySigner(s) ? "[]" : s));
  for (const desc of signers) {
    if (!isEmptySigner(desc) && desc === newDescriptor) {
      throw new Error("Signer already exists in this sandbox");
    }
  }
  signers[index] = newDescriptor;
  signers.length = n;
  // Fill any undefined slots from resize
  for (let i = 0; i < n; i++) {
    if (!signers[i]) signers[i] = "[]";
  }
  return signers;
}

// Matches libnunchuk's GroupService::UpdateOccupiedJson
function updateOccupiedJson(
  occupied: Array<{ i: number; ts: number; uid: string }>,
  index: number,
): Array<{ i: number; ts: number; uid: string }> {
  return occupied.filter((item) => item.i !== index);
}

// Build the encrypted event body for adding a key to a sandbox slot.
// Matches libnunchuk's GroupService::SetSigner
export function buildAddKeyBody(
  groupId: string,
  groupJson: Record<string, unknown>,
  slot: number,
  descriptor: string,
  ephemeralPub: string,
  ephemeralPriv: string,
): string {
  const { phase, data: init } = getGroupPhaseData(groupJson);
  if (phase !== "init") {
    throw new Error("Cannot add key: group is already finalized");
  }
  const pubstate = init.pubstate as Record<string, unknown>;
  const state = init.state as Record<string, string>;
  const modified = init.modified as Record<string, Record<string, string>>;
  const n = pubstate.n as number;
  const stateId = init.stateId as number;
  const occupied = pubstate.occupied as Array<{ i: number; ts: number; uid: string }>;

  const ciphertext = state[ephemeralPub];

  if (ciphertext) {
    // Path A: we have a state entry — decrypt full signers, merge modified, re-encrypt
    let signers = (JSON.parse(publicOpen(ciphertext, ephemeralPriv)).signers as string[]).map(
      (s) => (isEmptySigner(s) ? "[]" : s),
    ); // normalize

    // Merge modified signers from other participants
    // modified structure: { participantPub: { receiverPub: ciphertext, ... }, ... }
    for (const [, participantModified] of Object.entries(modified)) {
      const msigners = getModifiedSigners(participantModified, ephemeralPub, ephemeralPriv, n);
      for (let i = 0; i < n; i++) {
        if (isEmptySigner(signers[i]) && !isEmptySigner(msigners[i])) {
          signers[i] = msigners[i];
        }
      }
    }
    // Clear modified after merging
    init.modified = {};

    // Update signers with new key
    signers = updateSignersJson(signers, descriptor, slot, n);
    const plaintext = JSON.stringify({ signers });

    // Re-encrypt for all participants
    for (const key of Object.keys(state)) {
      state[key] = publicBox(plaintext, ephemeralPub, ephemeralPriv, key);
    }

    // Update added array
    pubstate.added = signers.map((s, i) => (!isEmptySigner(s) ? i : -1)).filter((i) => i >= 0);
  } else {
    // Path B: we don't have a state entry — work through modified only
    const myModified = modified[ephemeralPub] ?? {};
    let signers = getModifiedSigners(myModified, ephemeralPub, ephemeralPriv, n);

    signers = updateSignersJson(signers, descriptor, slot, n);
    const plaintext = JSON.stringify({ signers });

    // Encrypt for all keys in state
    const newModified: Record<string, string> = {};
    for (const key of Object.keys(state)) {
      newModified[key] = publicBox(plaintext, ephemeralPub, ephemeralPriv, key);
    }
    modified[ephemeralPub] = newModified;
  }

  // Update occupied — remove slot from occupied list
  pubstate.occupied = updateOccupiedJson(occupied, slot);

  return buildGroupEvent(groupId, init, stateId);
}

// Decrypt signers from sandbox state (shared logic for finalize)
export function decryptSigners(
  groupJson: Record<string, unknown>,
  ephemeralPub: string,
  ephemeralPriv: string,
): { signers: string[]; pubstate: Record<string, unknown>; stateId: number } {
  const { phase, data } = getGroupPhaseData(groupJson);
  if (phase !== "init") {
    throw new Error("Cannot finalize: group is already active");
  }
  const pubstate = data.pubstate as Record<string, unknown>;
  const state = data.state as Record<string, string>;
  const modified = data.modified as Record<string, Record<string, string>>;
  const n = pubstate.n as number;
  const stateId = data.stateId as number;

  const ciphertext = state[ephemeralPub];
  if (!ciphertext) {
    throw new Error(
      "Cannot finalize: no state entry for your ephemeral key. You must be the sandbox creator to finalize.",
    );
  }

  // Decrypt full signers
  const signers = (JSON.parse(publicOpen(ciphertext, ephemeralPriv)).signers as string[]).map(
    (s) => (isEmptySigner(s) ? "[]" : s),
  );

  // Merge modified signers from other participants
  for (const [, participantModified] of Object.entries(modified)) {
    const msigners = getModifiedSigners(participantModified, ephemeralPub, ephemeralPriv, n);
    for (let i = 0; i < n; i++) {
      if (isEmptySigner(signers[i]) && !isEmptySigner(msigners[i])) {
        signers[i] = msigners[i];
      }
    }
  }

  // Validate all slots filled
  for (let i = 0; i < n; i++) {
    if (isEmptySigner(signers[i])) {
      throw new Error(`Cannot finalize: slot ${i} is empty`);
    }
  }

  return { signers, pubstate, stateId };
}

interface DecryptedFinalizedGroup {
  signers: string[];
  pubstate: Record<string, unknown>;
  stateId: number;
  gid: string;
  walletId: string;
}

function decryptFinalizedGroup(
  groupJson: Record<string, unknown>,
  ephemeralPub: string,
  ephemeralPriv: string,
): DecryptedFinalizedGroup {
  const { phase, data } = getGroupPhaseData(groupJson);
  if (phase !== "finalize") {
    throw new Error("Cannot recover wallet: group is not finalized");
  }

  const pubstate = data.pubstate as Record<string, unknown>;
  const state = data.state as Record<string, string>;
  const ciphertext = state[ephemeralPub];
  if (!ciphertext) {
    throw new Error("Cannot recover wallet: no finalized state entry for your ephemeral key");
  }

  const plaintext = JSON.parse(publicOpen(ciphertext, ephemeralPriv)) as {
    signers?: string[];
    pubkey?: string;
    walletId?: string;
  };

  if (!Array.isArray(plaintext.signers) || !plaintext.pubkey || !plaintext.walletId) {
    throw new Error("Invalid finalized group payload");
  }

  return {
    signers: plaintext.signers.map((s) => (isEmptySigner(s) ? "[]" : s)),
    pubstate,
    stateId: data.stateId as number,
    gid: plaintext.pubkey,
    walletId: plaintext.walletId,
  };
}

// Build the finalize event body
// Reference: GroupService::FinalizeGroup in groupservice.cpp:749-765
// Reference: GroupToEvent in groupservice.cpp:358-414
export interface FinalizeResult {
  body: string;
  walletId: string;
  gid: string;
  descriptor: string;
  signers: string[];
  secretboxKey: Uint8Array;
  m: number;
  n: number;
  addressType: number;
  name: string;
}

export async function buildFinalizeBody(
  groupId: string,
  groupJson: Record<string, unknown>,
  ephemeralPub: string,
  ephemeralPriv: string,
  network: Network,
): Promise<FinalizeResult> {
  const { signers, pubstate, stateId } = decryptSigners(groupJson, ephemeralPub, ephemeralPriv);

  const m = pubstate.m as number;
  const n = pubstate.n as number;
  const addressType = pubstate.addressType as number;
  const name = pubstate.name as string;

  // Step 2: Build wallet descriptor (<0;1>/* format for storage/display)
  const descriptor = buildWalletDescriptor(signers, m, addressType);

  // Step 3: Derive local wallet ID
  const walletId = getWalletId(signers, m, addressType);

  // Step 4: Derive BIP32 root key from ANY descriptor (/* format for PBKDF2)
  // Must use DescriptorPath::ANY for backward compatibility with SoftwareSigner
  const anyDescriptor = buildAnyDescriptor(signers, m, addressType);
  const rootKey = await deriveRootKeyFromDescriptor(anyDescriptor);

  // Step 5: Derive Secretbox key (BIP85)
  const secretboxKey = deriveSecretboxKey(rootKey);

  // Step 6: Derive GID (server wallet ID)
  const gid = deriveGID(rootKey, network === "mainnet" ? "mainnet" : "testnet");

  // Step 7: Build encrypted finalize event
  const init = groupJson.init as Record<string, unknown>;
  const state = init.state as Record<string, string>;

  // Encrypt plaintext with pubkey and walletId for all participants
  const plaintext = JSON.stringify({ signers, pubkey: gid, walletId });
  const newState: Record<string, string> = {};
  for (const key of Object.keys(state)) {
    newState[key] = publicBox(plaintext, ephemeralPub, ephemeralPriv, key);
  }

  // Build added array (all slots)
  const added = signers.map((_, i) => i);

  const data = {
    version: VERSION,
    stateId: stateId + 1,
    wallet_id: gid,
    state: newState,
    pubstate: {
      m,
      n,
      addressType,
      walletTemplate: 0,
      miniscriptTemplate: "",
      name,
      occupied: [],
      added,
    },
    modified: {},
  };

  const body = {
    group_id: groupId,
    type: "finalize",
    data,
  };

  return {
    body: JSON.stringify(body),
    walletId,
    gid,
    descriptor,
    signers,
    secretboxKey,
    m,
    n,
    addressType,
    name,
  };
}

// -- Platform Key operations --

// Shared helper: decrypt init state, merge modified signers, return mutable references
interface DecryptedInitState {
  plaintext: Record<string, unknown>;
  signers: string[];
  init: Record<string, unknown>;
  state: Record<string, string>;
  pubstate: Record<string, unknown>;
  stateId: number;
  n: number;
  occupied: Array<{ i: number; ts: number; uid: string }>;
}

function decryptInitState(
  groupJson: Record<string, unknown>,
  ephemeralPub: string,
  ephemeralPriv: string,
): DecryptedInitState {
  const { phase, data: init } = getGroupPhaseData(groupJson);
  if (phase !== "init") {
    throw new Error("Group is already finalized");
  }

  const pubstate = init.pubstate as Record<string, unknown>;
  const state = init.state as Record<string, string>;
  const modified = init.modified as Record<string, Record<string, string>>;
  const n = pubstate.n as number;
  const stateId = init.stateId as number;
  const occupied = (pubstate.occupied ?? []) as Array<{ i: number; ts: number; uid: string }>;

  const ciphertext = state[ephemeralPub];
  if (!ciphertext) {
    throw new Error(
      "No state entry for your ephemeral key. Only the sandbox creator can perform this operation.",
    );
  }

  const plaintext = JSON.parse(publicOpen(ciphertext, ephemeralPriv)) as Record<string, unknown>;
  const signers = ((plaintext.signers as string[]) ?? []).map((s) => (isEmptySigner(s) ? "[]" : s));

  // Merge modified signers from other participants
  for (const [, participantModified] of Object.entries(modified)) {
    const msigners = getModifiedSigners(participantModified, ephemeralPub, ephemeralPriv, n);
    for (let i = 0; i < n; i++) {
      if (isEmptySigner(signers[i]) && !isEmptySigner(msigners[i])) {
        signers[i] = msigners[i];
      }
    }
  }
  init.modified = {};

  return { plaintext, signers, init, state, pubstate, stateId, n, occupied };
}

export function buildEnablePlatformKeyBody(
  groupId: string,
  groupJson: Record<string, unknown>,
  backendPubkey: string,
  ephemeralPub: string,
  ephemeralPriv: string,
): string {
  const { plaintext, signers, init, state, pubstate, stateId, n, occupied } = decryptInitState(
    groupJson,
    ephemeralPub,
    ephemeralPriv,
  );

  if (plaintext.platformKey != null) {
    throw new Error("Platform key is already enabled on this sandbox");
  }

  // Clear last signer slot (reserved for platform key in multisig)
  const platformIndex = n - 1;
  signers[platformIndex] = "[]";
  pubstate.occupied = updateOccupiedJson(occupied, platformIndex);

  // Set platform key in plaintext
  plaintext.signers = signers;
  plaintext.platformKey = { policies: {} };

  const plaintextStr = JSON.stringify(plaintext);

  // Re-encrypt for all existing keys
  for (const key of Object.keys(state)) {
    state[key] = publicBox(plaintextStr, ephemeralPub, ephemeralPriv, key);
  }
  // Add backend pubkey to state
  state[backendPubkey] = publicBox(plaintextStr, ephemeralPub, ephemeralPriv, backendPubkey);

  pubstate.added = signers.map((s, i) => (!isEmptySigner(s) ? i : -1)).filter((i) => i >= 0);

  return buildGroupEvent(groupId, init, stateId);
}

export function buildDisablePlatformKeyBody(
  groupId: string,
  groupJson: Record<string, unknown>,
  backendPubkey: string,
  ephemeralPub: string,
  ephemeralPriv: string,
): string {
  const { plaintext, signers, init, state, pubstate, stateId, n, occupied } = decryptInitState(
    groupJson,
    ephemeralPub,
    ephemeralPriv,
  );

  if (plaintext.platformKey == null) {
    throw new Error("Platform key is not enabled on this sandbox");
  }

  // Clear last signer slot
  const platformIndex = n - 1;
  signers[platformIndex] = "[]";
  pubstate.occupied = updateOccupiedJson(occupied, platformIndex);

  // Remove platform key fields
  plaintext.signers = signers;
  delete plaintext.platformKey;
  delete plaintext.platformKeySlots;

  const plaintextStr = JSON.stringify(plaintext);

  // Remove backend pubkey from state
  delete state[backendPubkey];

  // Re-encrypt for remaining keys
  for (const key of Object.keys(state)) {
    state[key] = publicBox(plaintextStr, ephemeralPub, ephemeralPriv, key);
  }

  pubstate.added = signers.map((s, i) => (!isEmptySigner(s) ? i : -1)).filter((i) => i >= 0);

  return buildGroupEvent(groupId, init, stateId);
}

export function buildSetPlatformKeyPolicyBody(
  groupId: string,
  groupJson: Record<string, unknown>,
  policies: PlatformKeyPolicies,
  ephemeralPub: string,
  ephemeralPriv: string,
): string {
  const { plaintext, signers, init, state, pubstate, stateId } = decryptInitState(
    groupJson,
    ephemeralPub,
    ephemeralPriv,
  );

  if (plaintext.platformKey == null) {
    throw new Error(
      "Platform key is not enabled. Enable it first with 'sandbox platform-key enable'",
    );
  }

  // Update policies (full replacement)
  const platformKey = plaintext.platformKey as { policies: PlatformKeyPolicies };
  platformKey.policies = policies;
  plaintext.platformKey = platformKey;
  plaintext.signers = signers;

  const plaintextStr = JSON.stringify(plaintext);

  for (const key of Object.keys(state)) {
    state[key] = publicBox(plaintextStr, ephemeralPub, ephemeralPriv, key);
  }

  pubstate.added = signers.map((s, i) => (!isEmptySigner(s) ? i : -1)).filter((i) => i >= 0);

  return buildGroupEvent(groupId, init, stateId);
}

// Get platform key config from sandbox state (for display and merge)
export function getGroupPlatformKeyState(
  groupJson: Record<string, unknown>,
  ephemeralPub: string,
  ephemeralPriv: string,
): PlatformKeyConfig | null {
  try {
    const { data } = getGroupPhaseData(groupJson);
    const state = (data.state ?? {}) as Record<string, string>;
    const ciphertext = state[ephemeralPub];
    if (!ciphertext) return null;

    const plaintext = JSON.parse(publicOpen(ciphertext, ephemeralPriv)) as {
      platformKey?: PlatformKeyConfig;
    };
    return plaintext.platformKey ?? null;
  } catch {
    return null;
  }
}

export async function recoverFinalizedGroup(
  groupJson: Record<string, unknown>,
  ephemeralPub: string,
  ephemeralPriv: string,
  network: Network,
): Promise<FinalizeResult> {
  const { signers, pubstate, gid, walletId } = decryptFinalizedGroup(
    groupJson,
    ephemeralPub,
    ephemeralPriv,
  );

  const m = pubstate.m as number;
  const n = pubstate.n as number;
  const addressType = pubstate.addressType as number;
  const name = pubstate.name as string;
  const descriptor = buildWalletDescriptor(signers, m, addressType);
  const anyDescriptor = buildAnyDescriptor(signers, m, addressType);
  const rootKey = await deriveRootKeyFromDescriptor(anyDescriptor);
  const secretboxKey = deriveSecretboxKey(rootKey);
  const derivedGid = deriveGID(rootKey, network === "mainnet" ? "mainnet" : "testnet");
  const derivedWalletId = getWalletId(signers, m, addressType);

  if (derivedGid !== gid) {
    throw new Error("Recovered wallet GID does not match finalized group data");
  }
  if (derivedWalletId !== walletId) {
    throw new Error("Recovered wallet ID does not match finalized group data");
  }

  return {
    body: "",
    walletId,
    gid,
    descriptor,
    signers,
    secretboxKey,
    m,
    n,
    addressType,
    name,
  };
}
