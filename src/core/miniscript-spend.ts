import {
  getAllSigningPaths,
  getScriptNode,
  timelockFromK,
  timelockK,
  type MiniscriptTransactionState,
  type ScriptNode,
  type SigningPath,
} from "./miniscript.js";
import {
  getMiniscriptPlanPreimageRequirements,
  type MiniscriptPreimageRequirement,
} from "./miniscript-preimage.js";

export interface MiniscriptSpendingPlan {
  index: number;
  leafNodes: ScriptNode[];
  lockTime: number;
  path: SigningPath;
  preimageRequirements: MiniscriptPreimageRequirement[];
  requiredSignatures: number;
  sequence: number;
  signerNames: string[];
  supported: boolean;
  unsupportedReason?: string;
}

export interface MiniscriptSpendingPlanStatus extends MiniscriptSpendingPlan {
  satisfiable: boolean;
}

function nodeIdKey(id: number[]): string {
  return id.join(".");
}

function collectNodes(node: ScriptNode, out: Map<string, ScriptNode>): void {
  out.set(nodeIdKey(node.id), node);
  for (const sub of node.subs) {
    collectNodes(sub, out);
  }
}

function getLeafNodesForPath(node: ScriptNode, path: SigningPath): ScriptNode[] {
  const nodes = new Map<string, ScriptNode>();
  collectNodes(node, nodes);

  return path
    .map((id) => {
      const leaf = nodes.get(nodeIdKey(id));
      if (!leaf) {
        throw new Error(`Unknown miniscript signing path node: ${id.join(".")}`);
      }
      return leaf;
    })
    .filter(
      (leaf, index, all) =>
        all.findIndex((item) => nodeIdKey(item.id) === nodeIdKey(leaf.id)) === index,
    );
}

function buildPlan(
  index: number,
  path: SigningPath,
  leafNodes: ScriptNode[],
): MiniscriptSpendingPlan {
  let lockTime = 0;
  let requiredSignatures = 0;
  let sequence = 0;
  const signerNames = new Set<string>();
  let supported = true;
  let unsupportedReason: string | undefined;

  for (const leaf of leafNodes) {
    switch (leaf.type) {
      case "AFTER":
        lockTime = Math.max(lockTime, leaf.k);
        break;
      case "OLDER":
        sequence = Math.max(sequence, leaf.k);
        break;
      case "PK":
        requiredSignatures += 1;
        signerNames.add(leaf.keys[0]);
        break;
      case "MULTI":
        requiredSignatures += leaf.k;
        for (const key of leaf.keys) {
          signerNames.add(key);
        }
        break;
      case "HASH160":
      case "HASH256":
      case "RIPEMD160":
      case "SHA256":
      case "NONE":
        break;
      default:
        supported = false;
        unsupportedReason = `Unsupported miniscript leaf type: ${leaf.type}`;
        break;
    }
  }

  return {
    index,
    leafNodes,
    lockTime,
    path,
    preimageRequirements: getMiniscriptPlanPreimageRequirements(leafNodes),
    requiredSignatures,
    sequence,
    signerNames: [...signerNames],
    supported,
    unsupportedReason,
  };
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

export function isMiniscriptPlanSatisfied(
  plan: MiniscriptSpendingPlan,
  txState: MiniscriptTransactionState,
): boolean {
  if (!plan.supported) {
    return false;
  }

  if (txState.lockTime < plan.lockTime) {
    return false;
  }

  if (plan.sequence === 0) {
    return true;
  }

  return txState.inputs.every((input) => sequenceSatisfied(plan.sequence, input.nSequence));
}

export function getMiniscriptSpendingPlans(expression: string): MiniscriptSpendingPlan[] {
  const { node } = getScriptNode(expression);
  return getAllSigningPaths(node).map((path, index) =>
    buildPlan(index, path, getLeafNodesForPath(node, path)),
  );
}

export function describeMiniscriptSpendingPlans(
  expression: string,
  txState?: MiniscriptTransactionState,
): MiniscriptSpendingPlanStatus[] {
  const plans = getMiniscriptSpendingPlans(expression);

  return plans.map((plan) => ({
    ...plan,
    satisfiable: txState ? isMiniscriptPlanSatisfied(plan, txState) : plan.supported,
  }));
}

export function getMiniscriptSpendingPlan(
  expression: string,
  planIndex: number,
): MiniscriptSpendingPlan {
  if (!Number.isSafeInteger(planIndex) || planIndex < 0) {
    throw new Error(`Invalid miniscript signing path index: ${planIndex}`);
  }

  const plans = getMiniscriptSpendingPlans(expression);
  const plan = plans.find((item) => item.index === planIndex);
  if (!plan) {
    throw new Error(`Unknown miniscript signing path: ${planIndex}`);
  }
  return plan;
}

export function selectMiniscriptSpendingPlan(
  expression: string,
  txState?: MiniscriptTransactionState,
  planIndex?: number,
): MiniscriptSpendingPlan {
  if (planIndex != null) {
    const selected = getMiniscriptSpendingPlan(expression, planIndex);
    if (!selected.supported) {
      throw new Error(
        selected.unsupportedReason ?? `Unsupported miniscript signing path: ${planIndex}`,
      );
    }
    if (txState && !isMiniscriptPlanSatisfied(selected, txState)) {
      throw new Error(`Selected miniscript signing path is not satisfiable: ${planIndex}`);
    }
    return selected;
  }

  const plans = getMiniscriptSpendingPlans(expression);
  const match = plans.find((plan) => {
    if (!plan.supported) {
      return false;
    }
    if (!txState) {
      return true;
    }
    return isMiniscriptPlanSatisfied(plan, txState);
  });

  if (match) {
    return plans
      .filter((plan) => {
        if (!plan.supported) {
          return false;
        }
        if (!txState) {
          return true;
        }
        return isMiniscriptPlanSatisfied(plan, txState);
      })
      .sort(
        (left, right) =>
          left.preimageRequirements.length - right.preimageRequirements.length ||
          left.index - right.index,
      )[0];
  }

  const unsupported = plans.find((plan) => !plan.supported);
  if (unsupported?.unsupportedReason) {
    throw new Error(unsupported.unsupportedReason);
  }

  throw new Error("No satisfiable miniscript signing path found");
}
