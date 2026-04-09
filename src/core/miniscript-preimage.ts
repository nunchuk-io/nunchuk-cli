import { hex } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { parseDescriptor } from "./descriptor.js";
import { getScriptNode, type ScriptNode } from "./miniscript.js";

export type MiniscriptHashType = "HASH160" | "HASH256" | "RIPEMD160" | "SHA256";
type MiniscriptInputHashField = "hash160" | "hash256" | "ripemd160" | "sha256";

export interface MiniscriptPreimageRequirement {
  hash: string;
  type: MiniscriptHashType;
}

const HASH_LEAF_TYPES = new Set<MiniscriptHashType>(["HASH160", "HASH256", "RIPEMD160", "SHA256"]);

function normalizeHashHex(value: string): string {
  return value.trim().toLowerCase();
}

export function miniscriptPreimageRequirementKey(
  requirement: MiniscriptPreimageRequirement,
): string {
  return `${requirement.type}:${normalizeHashHex(requirement.hash)}`;
}

function fieldForHashType(type: MiniscriptHashType): MiniscriptInputHashField {
  switch (type) {
    case "HASH160":
      return "hash160";
    case "HASH256":
      return "hash256";
    case "RIPEMD160":
      return "ripemd160";
    case "SHA256":
      return "sha256";
  }
}

function hashPreimage(type: MiniscriptHashType, preimage: Uint8Array): Uint8Array {
  switch (type) {
    case "HASH160":
      return ripemd160(sha256(preimage));
    case "HASH256":
      return sha256(sha256(preimage));
    case "RIPEMD160":
      return ripemd160(preimage);
    case "SHA256":
      return sha256(preimage);
  }
}

function collectHashRequirements(
  node: ScriptNode,
  out: Map<string, MiniscriptPreimageRequirement>,
): void {
  if (HASH_LEAF_TYPES.has(node.type as MiniscriptHashType) && typeof node.data === "string") {
    const requirement: MiniscriptPreimageRequirement = {
      type: node.type as MiniscriptHashType,
      hash: normalizeHashHex(node.data),
    };
    out.set(miniscriptPreimageRequirementKey(requirement), requirement);
  }

  for (const sub of node.subs) {
    collectHashRequirements(sub, out);
  }
}

export function getMiniscriptHashRequirements(
  expressionOrNode: string | ScriptNode,
): MiniscriptPreimageRequirement[] {
  const node =
    typeof expressionOrNode === "string" ? getScriptNode(expressionOrNode).node : expressionOrNode;
  const requirements = new Map<string, MiniscriptPreimageRequirement>();
  collectHashRequirements(node, requirements);
  return [...requirements.values()];
}

export function getMiniscriptPlanPreimageRequirements(
  leafNodes: ScriptNode[],
): MiniscriptPreimageRequirement[] {
  const requirements = new Map<string, MiniscriptPreimageRequirement>();
  for (const node of leafNodes) {
    if (!HASH_LEAF_TYPES.has(node.type as MiniscriptHashType) || typeof node.data !== "string") {
      continue;
    }
    const requirement: MiniscriptPreimageRequirement = {
      type: node.type as MiniscriptHashType,
      hash: normalizeHashHex(node.data),
    };
    requirements.set(miniscriptPreimageRequirementKey(requirement), requirement);
  }
  return [...requirements.values()];
}

export function parseMiniscriptPreimageHex(value: string): Uint8Array {
  const trimmed = value.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(trimmed) || trimmed.length % 2 !== 0) {
    throw new Error(`Invalid miniscript preimage hex: ${value}`);
  }

  const bytes = hex.decode(trimmed);
  if (bytes.length !== 32) {
    throw new Error("Miniscript preimage must be exactly 32 bytes (64 hex characters)");
  }

  return bytes;
}

function uniquePreimages(preimages: string[]): Uint8Array[] {
  const unique = new Map<string, Uint8Array>();
  for (const value of preimages) {
    const bytes = parseMiniscriptPreimageHex(value);
    unique.set(hex.encode(bytes), bytes);
  }
  return [...unique.values()];
}

type InputWithHashes = ReturnType<Transaction["getInput"]>;

function getInputHashField(
  input: InputWithHashes,
  field: MiniscriptInputHashField,
): Array<[Uint8Array, Uint8Array]> {
  return (
    ((input as Record<string, unknown>)[field] as Array<[Uint8Array, Uint8Array]> | undefined) ?? []
  );
}

export function getInputMiniscriptPreimages(input: InputWithHashes): Map<string, Uint8Array> {
  const preimages = new Map<string, Uint8Array>();

  const fields: Array<[MiniscriptHashType, MiniscriptInputHashField]> = [
    ["HASH160", "hash160"],
    ["HASH256", "hash256"],
    ["RIPEMD160", "ripemd160"],
    ["SHA256", "sha256"],
  ];

  for (const [type, field] of fields) {
    for (const [hash, preimage] of getInputHashField(input, field)) {
      preimages.set(
        miniscriptPreimageRequirementKey({ type, hash: hex.encode(hash) }),
        Uint8Array.from(preimage),
      );
    }
  }

  return preimages;
}

export function addMiniscriptPreimagesToPsbt(
  tx: Transaction,
  descriptor: string,
  preimages: string[],
): {
  matchedRequirements: MiniscriptPreimageRequirement[];
} {
  if (preimages.length === 0) {
    return { matchedRequirements: [] };
  }

  const parsed = parseDescriptor(descriptor);
  if (parsed.kind !== "miniscript" || !parsed.miniscript) {
    throw new Error("Miniscript preimages are only supported for miniscript wallets");
  }

  const requirements = getMiniscriptHashRequirements(parsed.miniscript);
  if (requirements.length === 0) {
    throw new Error("Miniscript policy does not require hash preimages");
  }

  const matched = new Map<string, MiniscriptPreimageRequirement>();
  const updates = new Map<MiniscriptInputHashField, Array<[Uint8Array, Uint8Array]>>();

  for (const preimage of uniquePreimages(preimages)) {
    const matches = requirements.filter(
      (requirement) => hex.encode(hashPreimage(requirement.type, preimage)) === requirement.hash,
    );

    if (matches.length === 0) {
      throw new Error(
        `Provided preimage does not match any miniscript hash requirement: ${hex.encode(preimage)}`,
      );
    }

    for (const requirement of matches) {
      matched.set(miniscriptPreimageRequirementKey(requirement), requirement);
      const field = fieldForHashType(requirement.type);
      const fieldEntries = updates.get(field) ?? [];
      fieldEntries.push([hex.decode(requirement.hash), preimage]);
      updates.set(field, fieldEntries);
    }
  }

  for (let inputIndex = 0; inputIndex < tx.inputsLength; inputIndex++) {
    const input = tx.getInput(inputIndex);
    const update: Record<string, Array<[Uint8Array, Uint8Array]>> = {};

    for (const [field, entries] of updates.entries()) {
      update[field] = [...getInputHashField(input, field), ...entries];
    }

    tx.updateInput(inputIndex, update, true);
  }

  return { matchedRequirements: [...matched.values()] };
}

export function formatMiniscriptPreimageRequirement(
  requirement: MiniscriptPreimageRequirement,
): string {
  return `${requirement.type.toLowerCase()}:${requirement.hash}`;
}
