import { hex } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { deriveDescriptorMiniscriptKeys } from "./address.js";
import type { Network } from "./config.js";
import { parseDescriptor } from "./descriptor.js";
import {
  getInputMiniscriptPreimages,
  miniscriptPreimageRequirementKey,
} from "./miniscript-preimage.js";
import {
  parseMiniscript,
  timelockFromK,
  timelockK,
  type MiniscriptFragment,
  type MiniscriptTransactionState,
} from "./miniscript.js";

interface WitnessStackResult {
  preimagesUsed: string[];
  signaturesUsed: string[];
  stack: Uint8Array[];
}

interface InputResult {
  dsat: WitnessStackResult | null;
  sat: WitnessStackResult | null;
}

interface SatisfactionContext {
  preimages: Map<string, Uint8Array>;
  pubkeys: Map<string, Uint8Array>;
  signatures: Map<string, Uint8Array>;
  txState: MiniscriptTransactionState;
}

const EMPTY_STACK: WitnessStackResult = { preimagesUsed: [], signaturesUsed: [], stack: [] };
const ONE_STACK: WitnessStackResult = {
  preimagesUsed: [],
  signaturesUsed: [],
  stack: [new Uint8Array([1])],
};
const ZERO_STACK: WitnessStackResult = {
  preimagesUsed: [],
  signaturesUsed: [],
  stack: [new Uint8Array()],
};
const ZERO32_STACK: WitnessStackResult = {
  preimagesUsed: [],
  signaturesUsed: [],
  stack: [new Uint8Array(32)],
};

function concatWitnessStacks(
  lower: WitnessStackResult | null,
  upper: WitnessStackResult | null,
): WitnessStackResult | null {
  if (!lower || !upper) {
    return null;
  }

  return {
    preimagesUsed: [...lower.preimagesUsed, ...upper.preimagesUsed],
    signaturesUsed: [...lower.signaturesUsed, ...upper.signaturesUsed],
    stack: [...lower.stack, ...upper.stack],
  };
}

function firstAvailable(...options: Array<WitnessStackResult | null>): WitnessStackResult | null {
  return options.find((option) => option != null) ?? null;
}

function sequenceSatisfied(requiredSequence: number, nSequence: number): boolean {
  if (requiredSequence === 0) {
    return true;
  }

  try {
    return (
      nSequence === timelockK(timelockFromK(false, nSequence)) && nSequence >= requiredSequence
    );
  } catch {
    return false;
  }
}

function zeroStack(count: number): WitnessStackResult {
  return {
    preimagesUsed: [],
    signaturesUsed: [],
    stack: Array.from({ length: count }, () => new Uint8Array()),
  };
}

function produceInput(node: MiniscriptFragment, ctx: SatisfactionContext): InputResult {
  switch (node.fragment) {
    case "JUST_0":
      return { dsat: EMPTY_STACK, sat: null };
    case "JUST_1":
      return { dsat: null, sat: EMPTY_STACK };
    case "PK":
    case "PK_K": {
      const signature = ctx.signatures.get(node.key);
      return {
        dsat: ZERO_STACK,
        sat: signature
          ? {
              preimagesUsed: [],
              signaturesUsed: [node.key],
              stack: [signature],
            }
          : null,
      };
    }
    case "PKH":
    case "PK_H": {
      const pubkey = ctx.pubkeys.get(node.key);
      if (!pubkey) {
        throw new Error(`Missing miniscript pubkey for hashed key: ${node.key}`);
      }

      const signature = ctx.signatures.get(node.key);
      return {
        dsat: {
          preimagesUsed: [],
          signaturesUsed: [],
          stack: [new Uint8Array(), pubkey],
        },
        sat: signature
          ? {
              preimagesUsed: [],
              signaturesUsed: [node.key],
              stack: [signature, pubkey],
            }
          : null,
      };
    }
    case "OLDER":
      return {
        dsat: null,
        sat: ctx.txState.inputs.every((input) => sequenceSatisfied(node.k, input.nSequence))
          ? EMPTY_STACK
          : null,
      };
    case "AFTER":
      return {
        dsat: null,
        sat: ctx.txState.lockTime >= node.k ? EMPTY_STACK : null,
      };
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
    case "SHA256": {
      if (!node.data) {
        throw new Error(`Miniscript ${node.fragment} node is missing hash data`);
      }
      const requirement = miniscriptPreimageRequirementKey({
        type: node.fragment,
        hash: node.data,
      });
      const preimage = ctx.preimages.get(requirement);
      if (preimage && preimage.length !== 32) {
        throw new Error(`Miniscript preimage must be 32 bytes: ${requirement}`);
      }
      return {
        dsat: ZERO32_STACK,
        sat: preimage
          ? {
              preimagesUsed: [requirement],
              signaturesUsed: [],
              stack: [preimage],
            }
          : null,
      };
    }
    case "MULTI": {
      const signatures: Uint8Array[] = [];
      const signaturesUsed: string[] = [];
      for (const key of node.keys) {
        const signature = ctx.signatures.get(key);
        if (!signature) {
          continue;
        }
        signatures.push(signature);
        signaturesUsed.push(key);
        if (signatures.length === node.k) {
          break;
        }
      }

      return {
        dsat: zeroStack(node.k + 1),
        sat:
          signatures.length === node.k
            ? {
                preimagesUsed: [],
                signaturesUsed,
                stack: [new Uint8Array(), ...signatures],
              }
            : null,
      };
    }
    case "MULTI_A":
      throw new Error("Taproot miniscript finalization is not supported yet");
    case "WRAP_A":
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_N":
      return produceInput(node.sub, ctx);
    case "WRAP_D": {
      const sub = produceInput(node.sub, ctx);
      return {
        dsat: ZERO_STACK,
        sat: concatWitnessStacks(sub.sat, ONE_STACK),
      };
    }
    case "WRAP_J": {
      const sub = produceInput(node.sub, ctx);
      return {
        dsat: ZERO_STACK,
        sat: sub.sat,
      };
    }
    case "WRAP_V": {
      const sub = produceInput(node.sub, ctx);
      return {
        dsat: null,
        sat: sub.sat,
      };
    }
    case "AND_V": {
      const left = produceInput(node.subs[0], ctx);
      const right = produceInput(node.subs[1], ctx);
      return {
        dsat: concatWitnessStacks(right.dsat, left.sat),
        sat: concatWitnessStacks(right.sat, left.sat),
      };
    }
    case "AND_B": {
      const left = produceInput(node.subs[0], ctx);
      const right = produceInput(node.subs[1], ctx);
      return {
        dsat: concatWitnessStacks(right.dsat, left.dsat),
        sat: concatWitnessStacks(right.sat, left.sat),
      };
    }
    case "OR_B": {
      const left = produceInput(node.subs[0], ctx);
      const right = produceInput(node.subs[1], ctx);
      return {
        dsat: concatWitnessStacks(right.dsat, left.dsat),
        sat: firstAvailable(
          concatWitnessStacks(right.dsat, left.sat),
          concatWitnessStacks(right.sat, left.dsat),
        ),
      };
    }
    case "OR_C": {
      const left = produceInput(node.subs[0], ctx);
      const right = produceInput(node.subs[1], ctx);
      return {
        dsat: null,
        sat: firstAvailable(left.sat, concatWitnessStacks(right.sat, left.dsat)),
      };
    }
    case "OR_D": {
      const left = produceInput(node.subs[0], ctx);
      const right = produceInput(node.subs[1], ctx);
      return {
        dsat: concatWitnessStacks(right.dsat, left.dsat),
        sat: firstAvailable(left.sat, concatWitnessStacks(right.sat, left.dsat)),
      };
    }
    case "OR_I": {
      const left = produceInput(node.subs[0], ctx);
      const right = produceInput(node.subs[1], ctx);
      return {
        dsat: firstAvailable(
          concatWitnessStacks(left.dsat, ONE_STACK),
          concatWitnessStacks(right.dsat, ZERO_STACK),
        ),
        sat: firstAvailable(
          concatWitnessStacks(left.sat, ONE_STACK),
          concatWitnessStacks(right.sat, ZERO_STACK),
        ),
      };
    }
    case "ANDOR": {
      const left = produceInput(node.subs[0], ctx);
      const middle = produceInput(node.subs[1], ctx);
      const right = produceInput(node.subs[2], ctx);
      return {
        dsat: concatWitnessStacks(right.dsat, left.dsat),
        sat: firstAvailable(
          concatWitnessStacks(middle.sat, left.sat),
          concatWitnessStacks(right.sat, left.dsat),
        ),
      };
    }
    case "THRESH": {
      const subResults = node.subs.map((sub) => produceInput(sub, ctx));
      const dsat = subResults.every((result) => result.dsat != null)
        ? subResults
            .slice()
            .reverse()
            .reduce<WitnessStackResult | null>(
              (stack, result) => concatWitnessStacks(stack, result.dsat),
              EMPTY_STACK,
            )
        : null;

      const choose = (
        index: number,
        remaining: number,
        chosen: boolean[],
      ): WitnessStackResult | null => {
        if (remaining < 0 || remaining > node.subs.length - index) {
          return null;
        }
        if (index === node.subs.length) {
          if (remaining !== 0) {
            return null;
          }

          let stack: WitnessStackResult | null = EMPTY_STACK;
          for (let i = node.subs.length - 1; i >= 0; i--) {
            const result = subResults[i];
            stack = concatWitnessStacks(stack, chosen[i] ? result.sat : result.dsat);
            if (!stack) {
              return null;
            }
          }
          return stack;
        }

        if (subResults[index].sat) {
          const withSat = choose(index + 1, remaining - 1, [...chosen, true]);
          if (withSat) {
            return withSat;
          }
        }
        if (subResults[index].dsat) {
          return choose(index + 1, remaining, [...chosen, false]);
        }
        return null;
      };

      return {
        dsat,
        sat: choose(0, node.k, []),
      };
    }
  }
}

function getTransactionState(tx: Transaction): MiniscriptTransactionState {
  return {
    inputs: Array.from({ length: tx.inputsLength }, (_, index) => ({
      nSequence: tx.getInput(index).sequence ?? 0xffffffff,
    })),
    lockTime: tx.lockTime,
  };
}

function getInputChainAndIndex(input: ReturnType<Transaction["getInput"]>): {
  chain: 0 | 1;
  index: number;
} {
  const bip32Derivation = input.bip32Derivation as
    | Array<[Uint8Array, { fingerprint: number; path: number[] }]>
    | undefined;
  if (!bip32Derivation || bip32Derivation.length === 0) {
    return { chain: 0, index: 0 };
  }

  const [, { path }] = bip32Derivation[0];
  if (path.length < 2) {
    return { chain: 0, index: path[path.length - 1] ?? 0 };
  }

  return {
    chain: path[path.length - 2] === 1 ? 1 : 0,
    index: path[path.length - 1],
  };
}

function setFinalWitness(
  tx: Transaction,
  inputIndex: number,
  finalScriptWitness: Uint8Array[],
): void {
  const inputs = (tx as unknown as { inputs?: Array<Record<string, unknown>> }).inputs;
  if (!inputs?.[inputIndex]) {
    throw new Error("Unable to access PSBT input for miniscript finalization");
  }

  inputs[inputIndex].finalScriptSig = new Uint8Array();
  inputs[inputIndex].finalScriptWitness = finalScriptWitness;
}

export interface MiniscriptFinalizationSummary {
  requiredPreimages: number;
  requiredSignatures: number;
}

export function finalizeMiniscriptPsbt(
  tx: Transaction,
  descriptor: string,
  network: Network,
): MiniscriptFinalizationSummary {
  const parsed = parseDescriptor(descriptor);
  if (parsed.kind !== "miniscript" || !parsed.miniscript) {
    throw new Error("Descriptor is not a miniscript descriptor");
  }

  const fragment = parseMiniscript(parsed.miniscript, parsed.addressType as 3);
  const txState = getTransactionState(tx);
  let requiredPreimages = 0;
  let requiredSignatures = 0;

  for (let inputIndex = 0; inputIndex < tx.inputsLength; inputIndex++) {
    const input = tx.getInput(inputIndex);
    if (input.finalScriptWitness?.length) {
      continue;
    }
    if (!input.witnessScript) {
      throw new Error("Miniscript PSBT input is missing witnessScript");
    }

    const { chain, index } = getInputChainAndIndex(input);
    const keyInfos = deriveDescriptorMiniscriptKeys(descriptor, network, chain, index);
    const signatureByPubkey = new Map<string, Uint8Array>();
    const partialSig = input.partialSig as Array<[Uint8Array, Uint8Array]> | undefined;
    for (const [pubkey, signature] of partialSig ?? []) {
      signatureByPubkey.set(hex.encode(pubkey), signature);
    }

    const signatures = new Map<string, Uint8Array>();
    const pubkeys = new Map<string, Uint8Array>();
    for (const info of keyInfos) {
      pubkeys.set(info.keyExpression, info.pubkey);
      const signature = signatureByPubkey.get(hex.encode(info.pubkey));
      if (signature) {
        signatures.set(info.keyExpression, signature);
      }
    }

    const preimages = getInputMiniscriptPreimages(input);
    const result = produceInput(fragment, { preimages, pubkeys, signatures, txState }).sat;
    if (!result) {
      throw new Error("Not enough signatures or hash preimages to finalize miniscript PSBT");
    }

    requiredSignatures += result.signaturesUsed.length;
    requiredPreimages += result.preimagesUsed.length;
    setFinalWitness(tx, inputIndex, [...result.stack, input.witnessScript]);
  }

  return { requiredPreimages, requiredSignatures };
}
