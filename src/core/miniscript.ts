import { descriptorChecksum } from "./descriptor.js";

export const MINISCRIPT_ADDRESS_TYPE_ANY = 0;
export const MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT = 3;
export const MINISCRIPT_ADDRESS_TYPE_TAPROOT = 4;

const LOCKTIME_THRESHOLD = 500000000;
const SEQUENCE_LOCKTIME_MASK = 0x0000ffff;
const SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22;
const SEQUENCE_LOCKTIME_GRANULARITY = 9;

export const UNDETERMINED_TIMELOCK_VALUE = Number.MAX_SAFE_INTEGER;

export type MiniscriptAddressType =
  | typeof MINISCRIPT_ADDRESS_TYPE_ANY
  | typeof MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT
  | typeof MINISCRIPT_ADDRESS_TYPE_TAPROOT;

export type WrapperFragment =
  | "WRAP_A"
  | "WRAP_S"
  | "WRAP_C"
  | "WRAP_D"
  | "WRAP_V"
  | "WRAP_J"
  | "WRAP_N";

export type BinaryFragment = "AND_V" | "AND_B" | "OR_B" | "OR_C" | "OR_D" | "OR_I";
export type HashFragment = "HASH160" | "HASH256" | "RIPEMD160" | "SHA256";

export type MiniscriptFragment =
  | { fragment: "JUST_0" | "JUST_1" }
  | { fragment: "PK" | "PKH" | "PK_H" | "PK_K"; key: string }
  | { fragment: "OLDER" | "AFTER"; k: number }
  | { fragment: HashFragment; data: string }
  | { fragment: "MULTI" | "MULTI_A"; k: number; keys: string[] }
  | { fragment: WrapperFragment; sub: MiniscriptFragment }
  | { fragment: BinaryFragment; subs: [MiniscriptFragment, MiniscriptFragment] }
  | { fragment: "ANDOR"; subs: [MiniscriptFragment, MiniscriptFragment, MiniscriptFragment] }
  | { fragment: "THRESH"; k: number; subs: MiniscriptFragment[] };

export type PolicyNode =
  | { type: "PK"; key: string }
  | { type: "OLDER" | "AFTER"; value: string }
  | { type: HashFragment; data: string }
  | { type: "AND" | "OR"; subs: PolicyNode[]; probs?: number[] }
  | { type: "THRESH"; k: number; subs: PolicyNode[] };

interface TapTreeLeaf {
  kind: "leaf";
  value: string;
}

interface TapTreeBranch {
  kind: "branch";
  left: TapTree;
  right: TapTree;
}

type TapTree = TapTreeLeaf | TapTreeBranch;

export type ScriptNodeId = number[];
export type SigningPath = ScriptNodeId[];

export type ScriptNodeType =
  | "NONE"
  | "PK"
  | "OLDER"
  | "AFTER"
  | "HASH160"
  | "HASH256"
  | "RIPEMD160"
  | "SHA256"
  | "AND"
  | "OR"
  | "ANDOR"
  | "THRESH"
  | "MULTI"
  | "OR_TAPROOT"
  | "MUSIG";

export interface ScriptNode {
  type: ScriptNodeType;
  id: ScriptNodeId;
  subs: ScriptNode[];
  keys: string[];
  data?: string;
  k: number;
}

export type TimelockBased = "NONE" | "TIME_LOCK" | "HEIGHT_LOCK";
export type TimelockType = "LOCKTYPE_ABSOLUTE" | "LOCKTYPE_RELATIVE";

export interface Timelock {
  based: TimelockBased;
  type: TimelockType;
  value: number;
}

export interface ParsedTapscriptTemplate {
  keypath: string[];
  subscripts: string[];
  depths: number[];
}

export interface GetScriptNodeResult {
  keypath: string[];
  node: ScriptNode;
}

export interface TimelineCoin {
  blocktime: number;
  height: number;
}

export interface MiniscriptTransactionInput {
  nSequence: number;
}

export interface MiniscriptTransactionState {
  inputs: MiniscriptTransactionInput[];
  lockTime: number;
}

export interface TimelockedCoinsResult<T extends TimelineCoin> {
  lockedCoins: T[];
  lockBased: TimelockBased;
  maxLockValue: number;
}

export interface CoinsGroup<T extends TimelineCoin> {
  coins: T[];
  maxLockValue: number;
}

export interface ValidateResult {
  error?: string;
  ok: boolean;
}

type MiniscriptBaseType = "B" | "K" | "V" | "W";

interface MiniscriptTypeInfo {
  base?: MiniscriptBaseType;
  d: boolean;
  g: boolean;
  h: boolean;
  i: boolean;
  j: boolean;
  k: boolean;
  n: boolean;
  o: boolean;
  u: boolean;
  x: boolean;
  z: boolean;
}

function invalid(message: string): never {
  throw new Error(message);
}

function isWrapperPrefixChar(ch: string): boolean {
  return "asctdvjnlut".includes(ch);
}

function isNumeric(value: string): boolean {
  return /^[0-9]+$/.test(value);
}

function isHex(value: string): boolean {
  return /^[0-9a-fA-F]+$/.test(value);
}

function splitTopLevel(value: string, delimiter: string): string[] {
  const parts: string[] = [];
  let depthParen = 0;
  let depthBrace = 0;
  let depthBracket = 0;
  let depthAngle = 0;
  let start = 0;

  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === "(") depthParen++;
    else if (ch === ")") depthParen--;
    else if (ch === "{") depthBrace++;
    else if (ch === "}") depthBrace--;
    else if (ch === "[") depthBracket++;
    else if (ch === "]") depthBracket--;
    else if (ch === "<") depthAngle++;
    else if (ch === ">") depthAngle--;
    else if (
      ch === delimiter &&
      depthParen === 0 &&
      depthBrace === 0 &&
      depthBracket === 0 &&
      depthAngle === 0
    ) {
      parts.push(value.slice(start, i).trim());
      start = i + 1;
    }

    if (depthParen < 0 || depthBrace < 0 || depthBracket < 0 || depthAngle < 0) {
      invalid(`Unbalanced expression: ${value}`);
    }
  }

  if (depthParen !== 0 || depthBrace !== 0 || depthBracket !== 0 || depthAngle !== 0) {
    invalid(`Unbalanced expression: ${value}`);
  }

  parts.push(value.slice(start).trim());
  return parts.filter((part) => part.length > 0);
}

function unwrapCall(expression: string): { inner: string; name: string } {
  const working = expression.trim();
  const open = working.indexOf("(");
  if (open <= 0 || !working.endsWith(")")) {
    invalid(`Invalid miniscript expression: ${expression}`);
  }
  const name = working.slice(0, open);
  const inner = working.slice(open + 1, -1);
  if (name.includes(":")) {
    invalid(`Invalid miniscript expression: ${expression}`);
  }
  return { name, inner };
}

function collectWrappers(expression: string): { expression: string; wrappers: string[] } {
  const wrappers: string[] = [];
  let working = expression.trim();
  while (working.length >= 2 && isWrapperPrefixChar(working[0]) && working[1] === ":") {
    wrappers.push(working[0]);
    working = working.slice(2);
  }
  return { expression: working, wrappers };
}

function applyWrapper(wrapper: string, node: MiniscriptFragment): MiniscriptFragment {
  switch (wrapper) {
    case "a":
      return { fragment: "WRAP_A", sub: node };
    case "s":
      return { fragment: "WRAP_S", sub: node };
    case "c":
      return { fragment: "WRAP_C", sub: node };
    case "d":
      return { fragment: "WRAP_D", sub: node };
    case "v":
      return { fragment: "WRAP_V", sub: node };
    case "j":
      return { fragment: "WRAP_J", sub: node };
    case "n":
      return { fragment: "WRAP_N", sub: node };
    case "t":
      return { fragment: "AND_V", subs: [node, { fragment: "JUST_1" }] };
    case "l":
      return { fragment: "OR_I", subs: [{ fragment: "JUST_0" }, node] };
    case "u":
      return { fragment: "OR_I", subs: [node, { fragment: "JUST_0" }] };
    default:
      invalid(`Unsupported wrapper: ${wrapper}`);
  }
}

function parseUInt(value: string, field: string): number {
  if (!isNumeric(value)) {
    invalid(`Invalid ${field}: ${value}`);
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    invalid(`Invalid ${field}: ${value}`);
  }
  return parsed;
}

function parseHashArg(value: string, bytes: number, name: string): string {
  if (!isHex(value) || value.length !== bytes * 2) {
    invalid(`Invalid ${name} hash: ${value}`);
  }
  return value.toLowerCase();
}

function parseMiniscriptFragment(
  expression: string,
  addressType: MiniscriptAddressType = MINISCRIPT_ADDRESS_TYPE_ANY,
): MiniscriptFragment {
  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    invalid("Miniscript expression is empty");
  }
  if (trimmed === "0") {
    return { fragment: "JUST_0" };
  }
  if (trimmed === "1") {
    return { fragment: "JUST_1" };
  }

  const { expression: baseExpression, wrappers } = collectWrappers(trimmed);
  const { name, inner } = unwrapCall(baseExpression);
  const args = splitTopLevel(inner, ",");

  let node: MiniscriptFragment;
  switch (name) {
    case "pk":
    case "pk_k":
    case "pkh":
    case "pk_h":
      if (args.length !== 1) invalid(`Invalid ${name}() expression`);
      node = {
        fragment:
          name === "pk_k" ? "PK_K" : name === "pkh" ? "PKH" : name === "pk_h" ? "PK_H" : "PK",
        key: args[0],
      };
      break;
    case "older":
      if (args.length !== 1) invalid("Invalid older() expression");
      node = { fragment: "OLDER", k: parseUInt(args[0], "older value") };
      break;
    case "after":
      if (args.length !== 1) invalid("Invalid after() expression");
      node = { fragment: "AFTER", k: parseUInt(args[0], "after value") };
      break;
    case "hash160":
      if (args.length !== 1) invalid("Invalid hash160() expression");
      node = { fragment: "HASH160", data: parseHashArg(args[0], 20, "hash160") };
      break;
    case "hash256":
      if (args.length !== 1) invalid("Invalid hash256() expression");
      node = { fragment: "HASH256", data: parseHashArg(args[0], 32, "hash256") };
      break;
    case "ripemd160":
      if (args.length !== 1) invalid("Invalid ripemd160() expression");
      node = { fragment: "RIPEMD160", data: parseHashArg(args[0], 20, "ripemd160") };
      break;
    case "sha256":
      if (args.length !== 1) invalid("Invalid sha256() expression");
      node = { fragment: "SHA256", data: parseHashArg(args[0], 32, "sha256") };
      break;
    case "multi":
    case "multi_a": {
      if (args.length < 2) invalid(`Invalid ${name}() expression`);
      const k = parseUInt(args[0], `${name} threshold`);
      const keys = args.slice(1);
      if (keys.length === 0 || k < 1 || k > keys.length) {
        invalid(`Invalid ${name}() threshold`);
      }
      if (name === "multi" && keys.length > 20) {
        invalid("multi() supports at most 20 keys");
      }
      if (name === "multi_a" && addressType === MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT) {
        invalid("multi_a() is only valid for taproot miniscript");
      }
      if (name === "multi" && addressType === MINISCRIPT_ADDRESS_TYPE_TAPROOT) {
        invalid("multi() is not valid for taproot miniscript");
      }
      node = { fragment: name === "multi_a" ? "MULTI_A" : "MULTI", k, keys };
      break;
    }
    case "and_v":
    case "and_b":
    case "and_n":
    case "or_b":
    case "or_c":
    case "or_d":
    case "or_i":
      if (args.length !== 2) invalid(`Invalid ${name}() expression`);
      if (name === "and_n") {
        node = {
          fragment: "ANDOR",
          subs: [
            parseMiniscriptFragment(args[0], addressType),
            parseMiniscriptFragment(args[1], addressType),
            { fragment: "JUST_0" },
          ],
        };
      } else {
        node = {
          fragment: name.toUpperCase() as BinaryFragment,
          subs: [
            parseMiniscriptFragment(args[0], addressType),
            parseMiniscriptFragment(args[1], addressType),
          ],
        };
      }
      break;
    case "andor":
      if (args.length !== 3) invalid("Invalid andor() expression");
      node = {
        fragment: "ANDOR",
        subs: [
          parseMiniscriptFragment(args[0], addressType),
          parseMiniscriptFragment(args[1], addressType),
          parseMiniscriptFragment(args[2], addressType),
        ],
      };
      break;
    case "thresh": {
      if (args.length < 2) invalid("Invalid thresh() expression");
      const k = parseUInt(args[0], "thresh threshold");
      const subs = args.slice(1).map((arg) => parseMiniscriptFragment(arg, addressType));
      if (k < 1 || k > subs.length) {
        invalid("Invalid thresh() threshold");
      }
      node = { fragment: "THRESH", k, subs };
      break;
    }
    default:
      invalid(`Unsupported miniscript fragment: ${name}`);
  }

  for (let i = wrappers.length - 1; i >= 0; i--) {
    node = applyWrapper(wrappers[i], node);
  }
  return node;
}

function unwrapProbability(expression: string): { expression: string; probability: number } {
  const at = expression.indexOf("@");
  if (at === -1) {
    return { expression, probability: 1 };
  }
  const prob = expression.slice(0, at).trim();
  if (!isNumeric(prob)) {
    invalid(`Invalid policy probability: ${expression}`);
  }
  return {
    expression: expression.slice(at + 1).trim(),
    probability: parseUInt(prob, "probability"),
  };
}

function parsePolicyNode(expression: string): PolicyNode {
  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    invalid("Policy expression is empty");
  }

  const { name, inner } = unwrapCall(trimmed);
  const args = splitTopLevel(inner, ",");

  switch (name) {
    case "pk":
      if (args.length !== 1) invalid("Invalid pk() policy");
      return { type: "PK", key: args[0] };
    case "older":
      if (args.length !== 1) invalid("Invalid older() policy");
      return { type: "OLDER", value: args[0] };
    case "after":
      if (args.length !== 1) invalid("Invalid after() policy");
      return { type: "AFTER", value: args[0] };
    case "hash160":
      if (args.length !== 1) invalid("Invalid hash160() policy");
      return { type: "HASH160", data: args[0] };
    case "hash256":
      if (args.length !== 1) invalid("Invalid hash256() policy");
      return { type: "HASH256", data: args[0] };
    case "ripemd160":
      if (args.length !== 1) invalid("Invalid ripemd160() policy");
      return { type: "RIPEMD160", data: args[0] };
    case "sha256":
      if (args.length !== 1) invalid("Invalid sha256() policy");
      return { type: "SHA256", data: args[0] };
    case "and":
      if (args.length < 2) invalid("Invalid and() policy");
      return { type: "AND", subs: args.map((arg) => parsePolicyNode(arg)) };
    case "or": {
      if (args.length < 2) invalid("Invalid or() policy");
      const parts = args.map((arg) => unwrapProbability(arg));
      return {
        type: "OR",
        probs: parts.map((part) => part.probability),
        subs: parts.map((part) => parsePolicyNode(part.expression)),
      };
    }
    case "thresh":
      if (args.length < 2) invalid("Invalid thresh() policy");
      return {
        type: "THRESH",
        k: parseUInt(args[0], "thresh threshold"),
        subs: args.slice(1).map((arg) => parsePolicyNode(arg)),
      };
    default:
      invalid(`Unsupported policy fragment: ${name}`);
  }
}

function findMusigClosingIndex(expression: string, prefix: string): number {
  let depth = 0;
  for (let i = prefix.length; i < expression.length; i++) {
    const ch = expression[i];
    if (ch === "(") {
      depth++;
    } else if (ch === ")") {
      if (depth === 0) {
        return i;
      }
      depth--;
    }
  }
  invalid("Invalid musig template");
}

function makeScriptNode(
  type: ScriptNodeType,
  subs: ScriptNode[] = [],
  keys: string[] = [],
  data: string | undefined = undefined,
  k = 0,
): ScriptNode {
  return { type, id: [], subs, keys, data, k };
}

function miniscriptToScriptNode(node: MiniscriptFragment): ScriptNode {
  switch (node.fragment) {
    case "PK":
    case "PKH":
    case "PK_H":
    case "PK_K":
      return makeScriptNode("PK", [], [node.key], undefined, 0);
    case "OLDER":
      return makeScriptNode("OLDER", [], [], undefined, node.k);
    case "AFTER":
      return makeScriptNode("AFTER", [], [], undefined, node.k);
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
    case "SHA256":
      return makeScriptNode(node.fragment, [], [], node.data, 0);
    case "AND_B":
      return makeScriptNode("AND", node.subs.map(miniscriptToScriptNode), [], undefined, 0);
    case "AND_V":
      if (node.subs[1].fragment === "JUST_1") {
        return miniscriptToScriptNode(node.subs[0]);
      }
      return makeScriptNode("AND", node.subs.map(miniscriptToScriptNode), [], undefined, 0);
    case "OR_B":
    case "OR_C":
    case "OR_D":
      return makeScriptNode("OR", node.subs.map(miniscriptToScriptNode), [], undefined, 0);
    case "OR_I":
      if (node.subs[0].fragment === "JUST_0") {
        return miniscriptToScriptNode(node.subs[1]);
      }
      if (node.subs[1].fragment === "JUST_0") {
        return miniscriptToScriptNode(node.subs[0]);
      }
      return makeScriptNode("OR", node.subs.map(miniscriptToScriptNode), [], undefined, 0);
    case "ANDOR":
      if (node.subs[2].fragment === "JUST_0") {
        return makeScriptNode(
          "AND",
          node.subs.slice(0, 2).map(miniscriptToScriptNode),
          [],
          undefined,
          0,
        );
      }
      return makeScriptNode("ANDOR", node.subs.map(miniscriptToScriptNode), [], undefined, 0);
    case "THRESH":
      return makeScriptNode("THRESH", node.subs.map(miniscriptToScriptNode), [], undefined, node.k);
    case "MULTI":
    case "MULTI_A":
      return makeScriptNode("MULTI", [], [...node.keys], undefined, node.k);
    case "WRAP_A":
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_D":
    case "WRAP_V":
    case "WRAP_J":
    case "WRAP_N":
      return miniscriptToScriptNode(node.sub);
    case "JUST_0":
    case "JUST_1":
      return makeScriptNode("NONE");
  }
}

function assignNodeIds(node: ScriptNode, id: ScriptNodeId): ScriptNode {
  const subs = node.subs.map((sub, index) => assignNodeIds(sub, [...id, index + 1]));
  return { ...node, id, subs };
}

function clonePath(path: ScriptNodeId): ScriptNodeId {
  return [...path];
}

function getAllPaths(node: ScriptNode): SigningPath[] {
  if (!["ANDOR", "AND", "THRESH", "OR", "OR_TAPROOT"].includes(node.type)) {
    return [[clonePath(node.id)]];
  }

  const paths: SigningPath[] = [];
  if (node.type === "ANDOR") {
    const sub0 = getAllPaths(node.subs[0]);
    const sub1 = getAllPaths(node.subs[1]);
    const sub2 = getAllPaths(node.subs[2]);

    for (const a of sub0) {
      for (const b of sub1) {
        paths.push([...a, ...b].map(clonePath));
      }
    }
    for (const c of sub2) {
      paths.push(c.map(clonePath));
    }
    return paths;
  }

  if (node.type === "OR" || node.type === "OR_TAPROOT") {
    for (const sub of node.subs.slice(0, 2)) {
      for (const path of getAllPaths(sub)) {
        paths.push(path.map(clonePath));
      }
    }
    return paths;
  }

  const required = node.type === "THRESH" ? node.k : 2;
  const combinations = chooseIndices(node.subs.length, required);
  for (const selected of combinations) {
    let partials: SigningPath[] = [[]];
    for (const index of selected) {
      const subPaths = getAllPaths(node.subs[index]);
      const next: SigningPath[] = [];
      for (const partial of partials) {
        for (const subPath of subPaths) {
          next.push([...partial, ...subPath].map(clonePath));
        }
      }
      partials = next;
    }
    paths.push(...partials);
  }
  return paths;
}

function chooseIndices(length: number, count: number): number[][] {
  const result: number[][] = [];
  const current: number[] = [];

  function visit(start: number): void {
    if (current.length === count) {
      result.push([...current]);
      return;
    }
    for (let i = start; i < length; i++) {
      current.push(i);
      visit(i + 1);
      current.pop();
    }
  }

  visit(0);
  return result;
}

function typeInfo(base: MiniscriptBaseType | undefined, flags = ""): MiniscriptTypeInfo {
  return {
    base,
    d: flags.includes("d"),
    g: flags.includes("g"),
    h: flags.includes("h"),
    i: flags.includes("i"),
    j: flags.includes("j"),
    k: flags.includes("k"),
    n: flags.includes("n"),
    o: flags.includes("o"),
    u: flags.includes("u"),
    x: flags.includes("x"),
    z: flags.includes("z"),
  };
}

function invalidType(): MiniscriptTypeInfo {
  return typeInfo(undefined);
}

function sameBase(...types: MiniscriptTypeInfo[]): MiniscriptBaseType | undefined {
  const base = types[0]?.base;
  return base && types.every((type) => type.base === base) ? base : undefined;
}

function hasAnyBase(type: MiniscriptTypeInfo, bases: MiniscriptBaseType[]): boolean {
  return type.base != null && bases.includes(type.base);
}

function orFlags(...types: MiniscriptTypeInfo[]): Pick<MiniscriptTypeInfo, "g" | "h" | "i" | "j"> {
  return {
    g: types.some((type) => type.g),
    h: types.some((type) => type.h),
    i: types.some((type) => type.i),
    j: types.some((type) => type.j),
  };
}

function noTimelockMix(...types: MiniscriptTypeInfo[]): boolean {
  const flags = orFlags(...types);
  return !((flags.g && flags.h) || (flags.i && flags.j));
}

function mergeTimelock(
  out: MiniscriptTypeInfo,
  types: MiniscriptTypeInfo[],
  checkMixing: boolean,
): MiniscriptTypeInfo {
  const flags = orFlags(...types);
  out.g = flags.g;
  out.h = flags.h;
  out.i = flags.i;
  out.j = flags.j;
  out.k = types.every((type) => type.k) && (!checkMixing || noTimelockMix(...types));
  return out;
}

function computeMiniscriptType(
  node: MiniscriptFragment,
  addressType: MiniscriptAddressType,
): MiniscriptTypeInfo {
  switch (node.fragment) {
    case "JUST_0":
      return typeInfo("B", "zudxk");
    case "JUST_1":
      return typeInfo("B", "zuxk");
    case "PK_K":
      return typeInfo("K", "onduxk");
    case "PK_H":
      return typeInfo("K", "nduxk");
    case "PK":
      return typeInfo("B", "onduk");
    case "PKH":
      return typeInfo("B", "nduk");
    case "OLDER": {
      if (node.k < 1 || node.k >= 0x80000000) {
        invalid("older() value must be between 1 and 2^31 - 1");
      }
      const lock = timelockFromK(false, node.k);
      return typeInfo("B", `${lock.based === "TIME_LOCK" ? "g" : "h"}zxk`);
    }
    case "AFTER": {
      if (node.k < 1 || node.k >= 0x80000000) {
        invalid("after() value must be between 1 and 2^31 - 1");
      }
      const lock = timelockFromK(true, node.k);
      return typeInfo("B", `${lock.based === "TIME_LOCK" ? "i" : "j"}zxk`);
    }
    case "SHA256":
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
      return typeInfo("B", "onduk");
    case "MULTI":
      if (addressType === MINISCRIPT_ADDRESS_TYPE_TAPROOT) {
        invalid("multi() is not valid for taproot miniscript");
      }
      return typeInfo("B", "nduk");
    case "MULTI_A":
      if (
        addressType !== MINISCRIPT_ADDRESS_TYPE_TAPROOT &&
        addressType !== MINISCRIPT_ADDRESS_TYPE_ANY
      ) {
        invalid("multi_a() is only valid for taproot miniscript");
      }
      return typeInfo("B", "duk");
    case "WRAP_A": {
      const x = computeMiniscriptType(node.sub, addressType);
      if (x.base !== "B") return invalidType();
      return mergeTimelock({ ...typeInfo("W", "x"), d: x.d, u: x.u }, [x], false);
    }
    case "WRAP_S": {
      const x = computeMiniscriptType(node.sub, addressType);
      if (x.base !== "B" || !x.o) return invalidType();
      return mergeTimelock({ ...typeInfo("W"), d: x.d, u: x.u, x: x.x }, [x], false);
    }
    case "WRAP_C": {
      const x = computeMiniscriptType(node.sub, addressType);
      if (x.base !== "K") return invalidType();
      return mergeTimelock({ ...typeInfo("B", "u"), d: x.d, n: x.n, o: x.o }, [x], false);
    }
    case "WRAP_D": {
      const x = computeMiniscriptType(node.sub, addressType);
      if (x.base !== "V" || !x.z) return invalidType();
      return mergeTimelock(typeInfo("B", "ondx"), [x], false);
    }
    case "WRAP_V": {
      const x = computeMiniscriptType(node.sub, addressType);
      if (x.base !== "B") return invalidType();
      return mergeTimelock({ ...typeInfo("V", "x"), n: x.n, o: x.o, z: x.z }, [x], false);
    }
    case "WRAP_J": {
      const x = computeMiniscriptType(node.sub, addressType);
      if (x.base !== "B" || !x.n) return invalidType();
      return mergeTimelock(typeInfo("B", `${x.o ? "o" : ""}${x.u ? "u" : ""}ndx`), [x], false);
    }
    case "WRAP_N": {
      const x = computeMiniscriptType(node.sub, addressType);
      if (x.base !== "B") return invalidType();
      return mergeTimelock({ ...typeInfo("B", "ux"), d: x.d, n: x.n, o: x.o, z: x.z }, [x], false);
    }
    case "AND_V": {
      const x = computeMiniscriptType(node.subs[0], addressType);
      const y = computeMiniscriptType(node.subs[1], addressType);
      if (x.base !== "V" || !hasAnyBase(y, ["B", "K", "V"])) return invalidType();
      return mergeTimelock(
        {
          ...typeInfo(y.base),
          d: x.d && y.d,
          n: x.n || (x.z && y.n),
          o: (x.z && y.o) || (y.z && x.o),
          u: y.u,
          x: y.x,
          z: x.z && y.z,
        },
        [x, y],
        true,
      );
    }
    case "AND_B": {
      const x = computeMiniscriptType(node.subs[0], addressType);
      const y = computeMiniscriptType(node.subs[1], addressType);
      if (x.base !== "B" || y.base !== "W") return invalidType();
      return mergeTimelock(
        {
          ...typeInfo("B", "ux"),
          d: x.d && y.d,
          n: x.n || (x.z && y.n),
          o: (x.z && y.o) || (y.z && x.o),
          z: x.z && y.z,
        },
        [x, y],
        true,
      );
    }
    case "OR_B": {
      const x = computeMiniscriptType(node.subs[0], addressType);
      const y = computeMiniscriptType(node.subs[1], addressType);
      if (x.base !== "B" || !x.d || y.base !== "W" || !y.d) return invalidType();
      return mergeTimelock(
        {
          ...typeInfo("B", "dux"),
          o: (x.z && y.o) || (y.z && x.o),
          z: x.z && y.z,
        },
        [x, y],
        false,
      );
    }
    case "OR_D": {
      const x = computeMiniscriptType(node.subs[0], addressType);
      const y = computeMiniscriptType(node.subs[1], addressType);
      if (x.base !== "B" || !x.d || !x.u || y.base !== "B") return invalidType();
      return mergeTimelock(
        { ...typeInfo("B", "x"), d: y.d, o: x.o && y.z, u: y.u, z: x.z && y.z },
        [x, y],
        false,
      );
    }
    case "OR_C": {
      const x = computeMiniscriptType(node.subs[0], addressType);
      const y = computeMiniscriptType(node.subs[1], addressType);
      if (x.base !== "B" || !x.d || !x.u || y.base !== "V") return invalidType();
      return mergeTimelock({ ...typeInfo("V", "x"), o: x.o && y.z, z: x.z && y.z }, [x, y], false);
    }
    case "OR_I": {
      const x = computeMiniscriptType(node.subs[0], addressType);
      const y = computeMiniscriptType(node.subs[1], addressType);
      const base = sameBase(x, y);
      if (!base || !hasAnyBase(x, ["B", "K", "V"])) return invalidType();
      return mergeTimelock(
        {
          ...typeInfo(base, "x"),
          d: x.d || y.d,
          o: x.z && y.z,
          u: x.u && y.u,
        },
        [x, y],
        false,
      );
    }
    case "ANDOR": {
      const x = computeMiniscriptType(node.subs[0], addressType);
      const y = computeMiniscriptType(node.subs[1], addressType);
      const z = computeMiniscriptType(node.subs[2], addressType);
      const base = sameBase(y, z);
      if (x.base !== "B" || !x.d || !x.u || !base || !hasAnyBase(y, ["B", "K", "V"])) {
        return invalidType();
      }
      const out = mergeTimelock(
        {
          ...typeInfo(base, "x"),
          d: z.d,
          o: (x.o && y.z && z.z) || (x.z && y.o && z.o),
          u: y.u && z.u,
          z: x.z && y.z && z.z,
        },
        [x, y, z],
        false,
      );
      out.k = x.k && y.k && z.k && noTimelockMix(x, y);
      return out;
    }
    case "THRESH": {
      const subTypes = node.subs.map((sub) => computeMiniscriptType(sub, addressType));
      if (subTypes.length === 0) return invalidType();
      const [first, ...rest] = subTypes;
      if (first.base !== "B" || !first.d || !first.u) return invalidType();
      if (rest.some((type) => type.base !== "W" || !type.d || !type.u)) return invalidType();
      const z = subTypes.every((type) => type.z);
      const o =
        subTypes.filter((type) => type.o).length === 1 &&
        subTypes.every((type) => type.o || type.z);
      return mergeTimelock({ ...typeInfo("B", "du"), o, z }, subTypes, node.k >= 2);
    }
  }
}

function validateMiniscriptNode(
  node: MiniscriptFragment,
  addressType: MiniscriptAddressType,
): void {
  switch (node.fragment) {
    case "OLDER": {
      if (node.k < 1 || node.k >= 0x80000000) {
        invalid("older() value must be between 1 and 2^31 - 1");
      }
      timelockFromK(false, node.k);
      break;
    }
    case "AFTER": {
      if (node.k < 1 || node.k >= 0x80000000) {
        invalid("after() value must be between 1 and 2^31 - 1");
      }
      timelockFromK(true, node.k);
      break;
    }
    case "MULTI":
      if (addressType === MINISCRIPT_ADDRESS_TYPE_TAPROOT) {
        invalid("multi() is not valid for taproot miniscript");
      }
      break;
    case "MULTI_A":
      if (
        addressType !== MINISCRIPT_ADDRESS_TYPE_TAPROOT &&
        addressType !== MINISCRIPT_ADDRESS_TYPE_ANY
      ) {
        invalid("multi_a() is only valid for taproot miniscript");
      }
      break;
    case "WRAP_A":
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_D":
    case "WRAP_V":
    case "WRAP_J":
    case "WRAP_N":
      validateMiniscriptNode(node.sub, addressType);
      return;
    case "AND_V":
    case "AND_B":
    case "OR_B":
    case "OR_C":
    case "OR_D":
    case "OR_I":
      validateMiniscriptNode(node.subs[0], addressType);
      validateMiniscriptNode(node.subs[1], addressType);
      return;
    case "ANDOR":
      validateMiniscriptNode(node.subs[0], addressType);
      validateMiniscriptNode(node.subs[1], addressType);
      validateMiniscriptNode(node.subs[2], addressType);
      return;
    case "THRESH":
      for (const sub of node.subs) {
        validateMiniscriptNode(sub, addressType);
      }
      return;
    default:
      return;
  }
}

function maybeAppendChildPath(value: string, childPath: string): string {
  if (!childPath) {
    return value;
  }
  if (/(?:\/\d+\/\*|\/\*|\/<[^>]+>\/\*)$/.test(value)) {
    return value;
  }
  return `${value}${childPath}`;
}

function substituteMiniscriptKeys(
  node: MiniscriptFragment,
  signers: Record<string, string>,
  childPath: string,
): string {
  switch (node.fragment) {
    case "JUST_0":
      return "0";
    case "JUST_1":
      return "1";
    case "PK":
      return `pk(${maybeAppendChildPath(signers[node.key] ?? node.key, childPath)})`;
    case "PKH":
      return `pkh(${maybeAppendChildPath(signers[node.key] ?? node.key, childPath)})`;
    case "PK_H":
      return `pk_h(${maybeAppendChildPath(signers[node.key] ?? node.key, childPath)})`;
    case "PK_K":
      return `pk_k(${maybeAppendChildPath(signers[node.key] ?? node.key, childPath)})`;
    case "OLDER":
      return `older(${node.k})`;
    case "AFTER":
      return `after(${node.k})`;
    case "HASH160":
      return `hash160(${node.data})`;
    case "HASH256":
      return `hash256(${node.data})`;
    case "RIPEMD160":
      return `ripemd160(${node.data})`;
    case "SHA256":
      return `sha256(${node.data})`;
    case "MULTI":
      return `multi(${node.k},${node.keys
        .map((key) => maybeAppendChildPath(signers[key] ?? key, childPath))
        .join(",")})`;
    case "MULTI_A":
      return `multi_a(${node.k},${node.keys
        .map((key) => maybeAppendChildPath(signers[key] ?? key, childPath))
        .join(",")})`;
    case "WRAP_A":
      return `a:${substituteMiniscriptKeys(node.sub, signers, childPath)}`;
    case "WRAP_S":
      return `s:${substituteMiniscriptKeys(node.sub, signers, childPath)}`;
    case "WRAP_C":
      return `c:${substituteMiniscriptKeys(node.sub, signers, childPath)}`;
    case "WRAP_D":
      return `d:${substituteMiniscriptKeys(node.sub, signers, childPath)}`;
    case "WRAP_V":
      return `v:${substituteMiniscriptKeys(node.sub, signers, childPath)}`;
    case "WRAP_J":
      return `j:${substituteMiniscriptKeys(node.sub, signers, childPath)}`;
    case "WRAP_N":
      return `n:${substituteMiniscriptKeys(node.sub, signers, childPath)}`;
    case "AND_V":
      return `and_v(${substituteMiniscriptKeys(node.subs[0], signers, childPath)},${substituteMiniscriptKeys(node.subs[1], signers, childPath)})`;
    case "AND_B":
      return `and_b(${substituteMiniscriptKeys(node.subs[0], signers, childPath)},${substituteMiniscriptKeys(node.subs[1], signers, childPath)})`;
    case "OR_B":
      return `or_b(${substituteMiniscriptKeys(node.subs[0], signers, childPath)},${substituteMiniscriptKeys(node.subs[1], signers, childPath)})`;
    case "OR_C":
      return `or_c(${substituteMiniscriptKeys(node.subs[0], signers, childPath)},${substituteMiniscriptKeys(node.subs[1], signers, childPath)})`;
    case "OR_D":
      return `or_d(${substituteMiniscriptKeys(node.subs[0], signers, childPath)},${substituteMiniscriptKeys(node.subs[1], signers, childPath)})`;
    case "OR_I":
      return `or_i(${substituteMiniscriptKeys(node.subs[0], signers, childPath)},${substituteMiniscriptKeys(node.subs[1], signers, childPath)})`;
    case "ANDOR":
      return `andor(${substituteMiniscriptKeys(node.subs[0], signers, childPath)},${substituteMiniscriptKeys(node.subs[1], signers, childPath)},${substituteMiniscriptKeys(node.subs[2], signers, childPath)})`;
    case "THRESH":
      return `thresh(${node.k},${node.subs
        .map((sub) => substituteMiniscriptKeys(sub, signers, childPath))
        .join(",")})`;
  }
}

function parseMusigInner(expression: string): { keys: string[]; suffix: string } {
  const working = expression.trim();
  if (!working.startsWith("pk(musig(") || !working.endsWith(")")) {
    invalid("Invalid musig template");
  }
  const innerStart = "pk(musig(".length;
  const closingIndex = findMusigClosingIndex(working, "pk(musig(");
  const keys = splitTopLevel(working.slice(innerStart, closingIndex), ",");
  if (keys.length < 2) {
    invalid("Invalid musig template");
  }
  return { keys, suffix: working.slice(closingIndex + 1, -1) };
}

function parseTapTree(expression: string): TapTree {
  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    invalid("Taproot script tree is empty");
  }

  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    const inner = trimmed.slice(1, -1);
    const args = splitTopLevel(inner, ",");
    if (args.length !== 2) {
      invalid(`Invalid taproot tree: ${expression}`);
    }
    return { kind: "branch", left: parseTapTree(args[0]), right: parseTapTree(args[1]) };
  }
  return { kind: "leaf", value: trimmed };
}

function flattenTapTree(tree: TapTree, depth: number, acc: ParsedTapscriptTemplate): void {
  if (tree.kind === "leaf") {
    acc.subscripts.push(tree.value);
    acc.depths.push(depth);
    return;
  }
  flattenTapTree(tree.left, depth + 1, acc);
  flattenTapTree(tree.right, depth + 1, acc);
}

function parseInternalKeypath(expression: string): string[] {
  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    return [];
  }
  if (trimmed.startsWith("musig(")) {
    const closingIndex = findMusigClosingIndex(trimmed, "musig(");
    return splitTopLevel(trimmed.slice("musig(".length, closingIndex), ",");
  }
  if (trimmed.startsWith("pk(musig(") && trimmed.endsWith(")")) {
    return parseMusigInner(trimmed).keys;
  }
  return [trimmed];
}

function validateTapLeaf(leaf: string): void {
  if (isValidMusigTemplate(leaf)) {
    return;
  }
  if (!isValidMiniscriptTemplate(leaf, MINISCRIPT_ADDRESS_TYPE_TAPROOT)) {
    invalid(`invalid miniscript template: '${leaf}'`);
  }
}

function validateDuplicateKeys(keypath: string[], subscripts: string[]): void {
  const seen = new Set<string>();
  const add = (key: string): void => {
    if (seen.has(key)) {
      invalid(`duplicate key: '${key}'`);
    }
    seen.add(key);
  };

  for (const key of keypath) {
    add(key);
  }
  for (const subscript of subscripts) {
    if (isValidMusigTemplate(subscript)) {
      for (const key of parseMusigInner(subscript).keys) {
        add(key);
      }
    } else {
      const parsed = parseSignerNames(subscript);
      for (const key of parsed.names) {
        add(key);
      }
    }
  }
}

function foldWithAnd(expressions: string[]): string {
  if (expressions.length === 0) {
    invalid("Cannot AND an empty set of policies");
  }
  let result = expressions[0];
  for (let i = 1; i < expressions.length; i++) {
    result = `and_v(v:${result},${expressions[i]})`;
  }
  return result;
}

function foldWithOr(expressions: string[]): string {
  if (expressions.length === 0) {
    invalid("Cannot OR an empty set of policies");
  }
  let result = expressions[0];
  for (let i = 1; i < expressions.length; i++) {
    result = `or_i(${result},${expressions[i]})`;
  }
  return result;
}

function resolveConfiguredValue(value: string, config: Record<string, string>): string {
  return config[value] ?? value;
}

function policyNodeToMiniscript(
  node: PolicyNode,
  config: Record<string, string>,
  addressType: MiniscriptAddressType,
): string {
  switch (node.type) {
    case "PK":
      return `pk(${resolveConfiguredValue(node.key, config)})`;
    case "OLDER": {
      const resolved = resolveConfiguredValue(node.value, config);
      return `older(${parseUInt(resolved, "older value")})`;
    }
    case "AFTER": {
      const resolved = resolveConfiguredValue(node.value, config);
      return `after(${parseUInt(resolved, "after value")})`;
    }
    case "HASH160":
      return `hash160(${parseHashArg(resolveConfiguredValue(node.data, config), 20, "hash160")})`;
    case "HASH256":
      return `hash256(${parseHashArg(resolveConfiguredValue(node.data, config), 32, "hash256")})`;
    case "RIPEMD160":
      return `ripemd160(${parseHashArg(resolveConfiguredValue(node.data, config), 20, "ripemd160")})`;
    case "SHA256":
      return `sha256(${parseHashArg(resolveConfiguredValue(node.data, config), 32, "sha256")})`;
    case "AND":
      return foldWithAnd(node.subs.map((sub) => policyNodeToMiniscript(sub, config, addressType)));
    case "OR":
      return foldWithOr(node.subs.map((sub) => policyNodeToMiniscript(sub, config, addressType)));
    case "THRESH": {
      if (node.k < 1 || node.k > node.subs.length) {
        invalid("Invalid thresh() threshold");
      }
      if (node.subs.every((sub) => sub.type === "PK")) {
        const keys = node.subs.map((sub) =>
          resolveConfiguredValue((sub as Extract<PolicyNode, { type: "PK" }>).key, config),
        );
        const name = addressType === MINISCRIPT_ADDRESS_TYPE_TAPROOT ? "multi_a" : "multi";
        return `${name}(${node.k},${keys.join(",")})`;
      }

      const chosen = chooseIndices(node.subs.length, node.k).map((indices) =>
        foldWithAnd(
          indices.map((index) => policyNodeToMiniscript(node.subs[index], config, addressType)),
        ),
      );
      return foldWithOr(chosen);
    }
  }
}

export function timelockFromK(isAbsolute: boolean, k: number): Timelock {
  if (!Number.isSafeInteger(k) || k < 0) {
    invalid(`Invalid timelock value: ${k}`);
  }

  let based: TimelockBased;
  let type: TimelockType;
  let value: number;

  if (isAbsolute) {
    type = "LOCKTYPE_ABSOLUTE";
    based = k >= LOCKTIME_THRESHOLD ? "TIME_LOCK" : "HEIGHT_LOCK";
    value = k;
  } else {
    type = "LOCKTYPE_RELATIVE";
    if (k & SEQUENCE_LOCKTIME_TYPE_FLAG) {
      based = "TIME_LOCK";
      value = (k & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY;
    } else {
      based = "HEIGHT_LOCK";
      value = k & SEQUENCE_LOCKTIME_MASK;
    }
  }

  if (value === 0) {
    based = "NONE";
  }

  return createTimelock(based, type, value);
}

export function createTimelock(based: TimelockBased, type: TimelockType, value: number): Timelock {
  let nextValue = value;
  if (based === "TIME_LOCK" && type === "LOCKTYPE_RELATIVE" && nextValue < 512) {
    nextValue = 512;
  }
  const lock: Timelock = { based, type, value: nextValue };
  timelockK(lock);
  return lock;
}

export function timelockK(lock: Timelock): number {
  if (lock.type === "LOCKTYPE_ABSOLUTE") {
    if (lock.value < LOCKTIME_THRESHOLD && lock.based === "TIME_LOCK") {
      invalid("Invalid time value");
    }
    if (lock.value >= LOCKTIME_THRESHOLD && lock.based === "HEIGHT_LOCK") {
      invalid("Invalid height value");
    }
    return lock.value;
  }

  if (lock.based === "TIME_LOCK") {
    if (lock.value < 0 || lock.value >= 33554431) {
      invalid("Invalid time value");
    }
    return (lock.value >> SEQUENCE_LOCKTIME_GRANULARITY) | SEQUENCE_LOCKTIME_TYPE_FLAG;
  }
  if (lock.based === "HEIGHT_LOCK") {
    if (lock.value < 0 || lock.value >= 65535) {
      invalid("Invalid height value");
    }
    return lock.value & SEQUENCE_LOCKTIME_MASK;
  }
  return 0;
}

export function timelockToMiniscript(lock: Timelock): string {
  return lock.type === "LOCKTYPE_ABSOLUTE"
    ? `after(${timelockK(lock)})`
    : `older(${timelockK(lock)})`;
}

export function parseMiniscript(
  expression: string,
  addressType: MiniscriptAddressType = MINISCRIPT_ADDRESS_TYPE_ANY,
): MiniscriptFragment {
  const node = parseMiniscriptFragment(expression, addressType);
  validateMiniscriptNode(node, addressType);
  const type = computeMiniscriptType(node, addressType);
  if (type.base !== "B") {
    invalid("Invalid miniscript type");
  }
  if (!type.k) {
    invalid("Timelock mixing");
  }
  return node;
}

export function isValidMiniscriptTemplate(
  expression: string,
  addressType: MiniscriptAddressType = MINISCRIPT_ADDRESS_TYPE_ANY,
): boolean {
  try {
    parseMiniscript(expression, addressType);
    return true;
  } catch {
    return false;
  }
}

export function validateMiniscriptTemplate(
  expression: string,
  addressType: MiniscriptAddressType = MINISCRIPT_ADDRESS_TYPE_ANY,
): ValidateResult {
  try {
    parseMiniscript(expression, addressType);
    return { ok: true };
  } catch (error) {
    return { error: (error as Error).message, ok: false };
  }
}

export function miniscriptNeedsExplicitVerify(
  node: MiniscriptFragment,
  addressType: MiniscriptAddressType = MINISCRIPT_ADDRESS_TYPE_ANY,
): boolean {
  return computeMiniscriptType(node, addressType).x;
}

export function parsePolicy(expression: string): PolicyNode {
  return parsePolicyNode(expression);
}

export function isValidPolicy(expression: string): boolean {
  try {
    parsePolicy(expression);
    return true;
  } catch {
    return false;
  }
}

export function policyToMiniscript(
  expression: string,
  config: Record<string, string> = {},
  addressType: MiniscriptAddressType = MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
): string {
  const policy = parsePolicy(expression);
  const miniscript = policyNodeToMiniscript(policy, config, addressType);
  parseMiniscript(miniscript, addressType);
  return miniscript;
}

export function flexibleMultisigMiniscriptTemplate(
  m: number,
  n: number,
  newM: number,
  newN: number,
  reuseSigners: boolean,
  timelock: Timelock,
  addressType: MiniscriptAddressType,
): string {
  if (m <= 0 || newM <= 0) invalid("m, new_m must be greater than 0");
  if (n <= 0 || newN <= 0) invalid("n, new_n must be greater than 0");
  if (m > n) invalid("m must be less than or equal to n");
  if (newM > newN) invalid("new m must be less than or equal to new n");
  if (
    addressType !== MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT &&
    addressType !== MINISCRIPT_ADDRESS_TYPE_TAPROOT
  ) {
    invalid("Invalid address type");
  }

  const buildInner = (
    threshold: number,
    total: number,
    startIndex: number,
    newIndex: number,
  ): string => {
    if (total === 1) {
      return `pk(key_${startIndex}${0 < newIndex ? "_1" : "_0"})`;
    }
    const name = addressType === MINISCRIPT_ADDRESS_TYPE_TAPROOT ? "multi_a" : "multi";
    const keys: string[] = [];
    for (let i = startIndex; i < startIndex + total; i++) {
      keys.push(`key_${i}${i < newIndex ? "_1" : "_0"}`);
    }
    return `${name}(${threshold},${keys.join(",")})`;
  };

  const nextScript = buildInner(newM, newN, reuseSigners ? 0 : n, reuseSigners ? n : 0);
  const lockScript = timelockToMiniscript(timelock);

  if (addressType === MINISCRIPT_ADDRESS_TYPE_TAPROOT) {
    return `{${buildInner(m, n, 0, 0)},and_v(v:${nextScript},${lockScript})}`;
  }
  return `or_d(${buildInner(m, n, 0, 0)},and_v(v:${nextScript},${lockScript}))`;
}

export function expandingMultisigMiniscriptTemplate(
  m: number,
  n: number,
  newN: number,
  reuseSigners: boolean,
  timelock: Timelock,
  addressType: MiniscriptAddressType,
): string {
  if (n >= newN) invalid("n must be less than new n");
  return flexibleMultisigMiniscriptTemplate(m, n, m, newN, reuseSigners, timelock, addressType);
}

export function decayingMultisigMiniscriptTemplate(
  m: number,
  n: number,
  newM: number,
  reuseSigners: boolean,
  timelock: Timelock,
  addressType: MiniscriptAddressType,
): string {
  if (m <= newM) invalid("new m must be less than m");
  return flexibleMultisigMiniscriptTemplate(m, n, newM, n, reuseSigners, timelock, addressType);
}

export function miniscriptTemplateToMiniscript(
  miniscriptTemplate: string,
  signers: Record<string, string>,
  childPath = "/<0;1>/*",
  addressType: MiniscriptAddressType = MINISCRIPT_ADDRESS_TYPE_ANY,
): string {
  const node = parseMiniscript(miniscriptTemplate, addressType);
  return substituteMiniscriptKeys(node, signers, childPath);
}

export function parseTapscriptTemplate(expression: string): ParsedTapscriptTemplate {
  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    invalid("Taproot script tree is empty");
  }

  let keypath: string[] = [];
  let tapscript = trimmed;
  if (trimmed.startsWith("tr(") && trimmed.endsWith(")")) {
    const parts = splitTopLevel(trimmed.slice(3, -1), ",");
    if (parts.length === 0 || parts.length > 2) {
      invalid("Invalid tr() expression");
    }
    keypath = parseInternalKeypath(parts[0]);
    tapscript = parts[1]?.trim() ?? "";
  }

  const result: ParsedTapscriptTemplate = { keypath, subscripts: [], depths: [] };
  if (tapscript.length === 0) {
    return result;
  }

  const tree = parseTapTree(tapscript);
  flattenTapTree(tree, 0, result);
  return result;
}

export function isValidMusigTemplate(expression: string): boolean {
  try {
    parseMusigInner(expression);
    return true;
  } catch {
    return false;
  }
}

export function getMusigScript(
  musigTemplate: string,
  signers: Record<string, string>,
  childPath = "/<0;1>/*",
): string {
  const { keys, suffix } = parseMusigInner(musigTemplate);
  const resolved = keys.map((key) => {
    const signer = signers[key];
    if (!signer) {
      invalid(`Missing signer for musig key: ${key}`);
    }
    return signer;
  });
  return `pk(musig(${resolved.join(",")})${suffix || childPath})`;
}

export function validateTapscriptTemplate(expression: string): ValidateResult {
  try {
    const parsed = parseTapscriptTemplate(expression);
    if (parsed.subscripts.length === 0) {
      invalid("tapscript missing");
    }
    for (const subscript of parsed.subscripts) {
      validateTapLeaf(subscript);
    }
    validateDuplicateKeys(parsed.keypath, parsed.subscripts);
    return { ok: true };
  } catch (error) {
    return { error: (error as Error).message, ok: false };
  }
}

export function isValidTapscriptTemplate(expression: string): boolean {
  return validateTapscriptTemplate(expression).ok;
}

export function subScriptsToString(subscripts: string[], depths: number[]): string {
  if (subscripts.length !== depths.length) {
    invalid("subscripts/depths length mismatch");
  }
  if (depths.length === 0) {
    return "";
  }
  const path: boolean[] = [];
  let result = "";

  for (let pos = 0; pos < depths.length; pos++) {
    if (pos > 0) result += ",";
    while (path.length <= depths[pos]) {
      if (path.length > 0) result += "{";
      path.push(false);
    }
    result += subscripts[pos];
    while (path.length > 0 && path[path.length - 1]) {
      if (path.length > 1) result += "}";
      path.pop();
    }
    if (path.length > 0) {
      path[path.length - 1] = true;
    }
  }
  return result;
}

export function subScriptsToScriptNode(subscripts: string[], depths: number[]): ScriptNode {
  const treeExpression = subScriptsToString(subscripts, depths);
  const tree = parseTapTree(treeExpression);

  const convert = (node: TapTree): ScriptNode => {
    if (node.kind === "leaf") {
      if (isValidMusigTemplate(node.value)) {
        const keys = parseMusigInner(node.value).keys;
        return makeScriptNode("MUSIG", [], keys, undefined, keys.length);
      }
      return miniscriptToScriptNode(parseMiniscript(node.value, MINISCRIPT_ADDRESS_TYPE_ANY));
    }
    return makeScriptNode(
      "OR_TAPROOT",
      [convert(node.left), convert(node.right)],
      [],
      undefined,
      0,
    );
  };

  return assignNodeIds(convert(tree), [1]);
}

export function tapscriptTemplateToTapscript(
  tapscriptTemplate: string,
  signers: Record<string, string>,
  childPath = "/<0;1>/*",
): { keypath: string[]; tapscript: string } {
  const parsed = parseTapscriptTemplate(tapscriptTemplate);
  const subscripts = parsed.subscripts.map((subscript) =>
    isValidMusigTemplate(subscript)
      ? getMusigScript(subscript, signers, childPath)
      : miniscriptTemplateToMiniscript(
          subscript,
          signers,
          childPath,
          MINISCRIPT_ADDRESS_TYPE_TAPROOT,
        ),
  );

  return { keypath: parsed.keypath, tapscript: subScriptsToString(subscripts, parsed.depths) };
}

export function getScriptNode(expression: string): GetScriptNodeResult {
  const trimmed = expression.trim();
  const tapValidation = validateTapscriptTemplate(trimmed);
  if (tapValidation.ok || trimmed.startsWith("tr(") || trimmed.startsWith("{")) {
    const parsed = parseTapscriptTemplate(trimmed);
    if (parsed.subscripts.length > 0) {
      return {
        keypath: parsed.keypath,
        node: subScriptsToScriptNode(parsed.subscripts, parsed.depths),
      };
    }
    if (trimmed.startsWith("tr(")) {
      return { keypath: parsed.keypath, node: assignNodeIds(makeScriptNode("NONE"), [1]) };
    }
  }

  const miniscriptNode = parseMiniscript(trimmed, MINISCRIPT_ADDRESS_TYPE_ANY);
  return {
    keypath: [],
    node: assignNodeIds(miniscriptToScriptNode(miniscriptNode), [1]),
  };
}

export function scriptNodeToString(node: ScriptNode): string {
  switch (node.type) {
    case "PK":
      return `pk(${node.keys[0]})`;
    case "OLDER":
      return `older(${node.k})`;
    case "AFTER":
      return `after(${node.k})`;
    case "HASH160":
      return `hash160(${node.data ?? ""})`;
    case "HASH256":
      return `hash256(${node.data ?? ""})`;
    case "RIPEMD160":
      return `ripemd160(${node.data ?? ""})`;
    case "SHA256":
      return `sha256(${node.data ?? ""})`;
    case "AND":
      return `and(${scriptNodeToString(node.subs[0])},${scriptNodeToString(node.subs[1])})`;
    case "OR":
      return `or(${scriptNodeToString(node.subs[0])},${scriptNodeToString(node.subs[1])})`;
    case "ANDOR":
      return `andor(${scriptNodeToString(node.subs[0])},${scriptNodeToString(node.subs[1])},${scriptNodeToString(node.subs[2])})`;
    case "THRESH":
      return `thresh(${node.k},${node.subs.map(scriptNodeToString).join(",")})`;
    case "MULTI":
      return `multi(${node.k},${node.keys.join(",")})`;
    case "OR_TAPROOT":
      return `{${scriptNodeToString(node.subs[0])},${scriptNodeToString(node.subs[1])}}`;
    case "MUSIG":
      return `pk(musig(${node.keys.join(",")}))`;
    case "NONE":
      return "";
  }
}

export function getAllSigningPaths(expressionOrNode: string | ScriptNode): SigningPath[] {
  const node =
    typeof expressionOrNode === "string" ? getScriptNode(expressionOrNode).node : expressionOrNode;
  return getAllPaths(node);
}

function isNodeUnlockedInternal(
  node: ScriptNode,
  coin: TimelineCoin,
  chainTip: number,
  now: number,
  state: { value: number },
): boolean {
  let value: number;
  let currentValue: number;

  if (node.type === "AFTER") {
    const timelock = timelockFromK(true, node.k);
    value = timelock.value;
    currentValue = timelock.based === "TIME_LOCK" ? now : chainTip;
  } else if (node.type === "OLDER") {
    if (coin.height <= 0) {
      state.value = UNDETERMINED_TIMELOCK_VALUE;
      return false;
    }
    const timelock = timelockFromK(false, node.k);
    if (timelock.based === "TIME_LOCK") {
      value = coin.blocktime + timelock.value;
      currentValue = now;
    } else {
      value = coin.height + timelock.value;
      currentValue = chainTip;
    }
  } else if (node.type === "ANDOR") {
    return (
      (isNodeUnlockedInternal(node.subs[0], coin, chainTip, now, state) &&
        isNodeUnlockedInternal(node.subs[1], coin, chainTip, now, state)) ||
      isNodeUnlockedInternal(node.subs[2], coin, chainTip, now, state)
    );
  } else if (node.type === "OR" || node.type === "OR_TAPROOT") {
    return (
      isNodeUnlockedInternal(node.subs[0], coin, chainTip, now, state) ||
      isNodeUnlockedInternal(node.subs[1], coin, chainTip, now, state)
    );
  } else if (node.type === "AND") {
    return (
      isNodeUnlockedInternal(node.subs[0], coin, chainTip, now, state) &&
      isNodeUnlockedInternal(node.subs[1], coin, chainTip, now, state)
    );
  } else if (node.type === "THRESH") {
    let count = 0;
    for (const sub of node.subs) {
      if (isNodeUnlockedInternal(sub, coin, chainTip, now, state)) {
        count++;
      }
    }
    return count >= node.k;
  } else {
    return true;
  }

  if (value > currentValue && value > state.value) {
    state.value = value;
  }
  return value <= currentValue;
}

export function isNodeUnlocked(
  expressionOrNode: string | ScriptNode,
  coin: TimelineCoin,
  chainTip: number,
  now = Math.floor(Date.now() / 1000),
): { maxLockValue: number; unlocked: boolean } {
  const node =
    typeof expressionOrNode === "string" ? getScriptNode(expressionOrNode).node : expressionOrNode;
  const state = { value: 0 };
  return {
    unlocked: isNodeUnlockedInternal(node, coin, chainTip, now, state),
    maxLockValue: state.value,
  };
}

export function isNodeSatisfiable(
  expressionOrNode: string | ScriptNode,
  tx: MiniscriptTransactionState,
): boolean {
  const node =
    typeof expressionOrNode === "string" ? getScriptNode(expressionOrNode).node : expressionOrNode;

  if (node.type === "AFTER") {
    return node.k <= tx.lockTime;
  }
  if (node.type === "OLDER") {
    for (const input of tx.inputs) {
      if (input.nSequence !== timelockK(timelockFromK(false, input.nSequence))) {
        return false;
      }
      if (node.k > input.nSequence) {
        return false;
      }
    }
    return true;
  }
  if (node.type === "ANDOR") {
    return (
      (isNodeSatisfiable(node.subs[0], tx) && isNodeSatisfiable(node.subs[1], tx)) ||
      isNodeSatisfiable(node.subs[2], tx)
    );
  }
  if (node.type === "OR" || node.type === "OR_TAPROOT") {
    return isNodeSatisfiable(node.subs[0], tx) || isNodeSatisfiable(node.subs[1], tx);
  }
  if (node.type === "AND") {
    return isNodeSatisfiable(node.subs[0], tx) && isNodeSatisfiable(node.subs[1], tx);
  }
  if (node.type === "THRESH") {
    let count = 0;
    for (const sub of node.subs) {
      if (isNodeSatisfiable(sub, tx)) {
        count++;
      }
    }
    return count >= node.k;
  }
  return true;
}

export class MiniscriptTimeline {
  private readonly absoluteLocks: number[] = [];
  private readonly node: ScriptNode;
  private readonly relativeLocks: number[] = [];
  private lockType: TimelockBased = "NONE";

  constructor(expression: string) {
    this.node = getScriptNode(expression).node;
    this.addNode(this.node);
  }

  getAbsoluteLocks(): number[] {
    return [...this.absoluteLocks];
  }

  getLockType(): TimelockBased {
    return this.lockType;
  }

  getRelativeLocks(): number[] {
    return [...this.relativeLocks];
  }

  getLocks(coin: TimelineCoin): number[] {
    const locks = [...this.absoluteLocks];
    if (coin.height > 0) {
      for (const lock of this.relativeLocks) {
        locks.push(this.lockType === "TIME_LOCK" ? coin.blocktime + lock : coin.height + lock);
      }
    }
    return [...new Set(locks)].sort((a, b) => a - b);
  }

  private addNode(node: ScriptNode): void {
    if (node.type === "AFTER") {
      const timelock = timelockFromK(true, node.k);
      this.detectTimelockMixing(timelock.based);
      this.absoluteLocks.push(timelock.value);
    } else if (node.type === "OLDER") {
      const timelock = timelockFromK(false, node.k);
      this.detectTimelockMixing(timelock.based);
      this.relativeLocks.push(timelock.value);
    }
    for (const sub of node.subs) {
      this.addNode(sub);
    }
  }

  private detectTimelockMixing(nextType: TimelockBased): void {
    if (nextType === "NONE") {
      return;
    }
    if (this.lockType === "NONE") {
      this.lockType = nextType;
      return;
    }
    if (this.lockType !== nextType) {
      invalid("Timelock mixing");
    }
  }
}

export function getTimelockedCoins<T extends TimelineCoin>(
  expressionOrNode: string | ScriptNode,
  coins: T[],
  chainTip: number,
  now = Math.floor(Date.now() / 1000),
): TimelockedCoinsResult<T> {
  const node =
    typeof expressionOrNode === "string" ? getScriptNode(expressionOrNode).node : expressionOrNode;
  const timeline =
    typeof expressionOrNode === "string" ? new MiniscriptTimeline(expressionOrNode) : null;
  const lockedCoins: T[] = [];
  let maxLockValue = 0;

  for (const coin of coins) {
    const state = { value: 0 };
    if (!isNodeUnlockedInternal(node, coin, chainTip, now, state)) {
      lockedCoins.push(coin);
      if (state.value > maxLockValue) {
        maxLockValue = state.value;
      }
    }
  }

  return {
    lockedCoins,
    lockBased: timeline?.getLockType() ?? "NONE",
    maxLockValue,
  };
}

export function getCoinsGroupedBySubPolicies<T extends TimelineCoin>(
  expressionOrNode: string | ScriptNode,
  coins: T[],
  chainTip: number,
  now = Math.floor(Date.now() / 1000),
): Array<CoinsGroup<T>> {
  const node =
    typeof expressionOrNode === "string" ? getScriptNode(expressionOrNode).node : expressionOrNode;
  if (!["OR", "OR_TAPROOT", "THRESH", "ANDOR"].includes(node.type)) {
    invalid("Invalid script node");
  }

  const groups = node.subs.map(() => ({ coins: [] as T[], maxLockValue: 0 }));
  if (node.type === "ANDOR") {
    for (const coin of coins) {
      let state = { value: 0 };
      if (
        isNodeUnlockedInternal(node.subs[0], coin, chainTip, now, state) &&
        isNodeUnlockedInternal(node.subs[1], coin, chainTip, now, state)
      ) {
        groups[1].coins.push(coin);
      }
      groups[1].maxLockValue = state.value;

      state = { value: 0 };
      if (isNodeUnlockedInternal(node.subs[2], coin, chainTip, now, state)) {
        groups[2].coins.push(coin);
      }
      groups[2].maxLockValue = state.value;
    }
    return groups;
  }

  for (const coin of coins) {
    for (let i = 0; i < node.subs.length; i++) {
      const state = { value: 0 };
      if (isNodeUnlockedInternal(node.subs[i], coin, chainTip, now, state)) {
        groups[i].coins.push(coin);
      }
      groups[i].maxLockValue = state.value;
    }
  }
  return groups;
}

export function parseSignerNames(scriptTemplate: string): { keypathM: number; names: string[] } {
  if (scriptTemplate.length === 0) {
    invalid("Miniscript only");
  }
  const { keypath, node } = getScriptNode(scriptTemplate);
  const names = [...keypath];
  const keypathM = names.length;

  const visit = (current: ScriptNode): void => {
    for (const key of current.keys) {
      if (!names.includes(key)) {
        names.push(key);
      }
    }
    for (const sub of current.subs) {
      visit(sub);
    }
  };

  visit(node);
  const head = names.slice(0, keypathM);
  const tail = names.slice(keypathM).sort();
  return { keypathM, names: [...head, ...tail] };
}

export function buildMiniscriptDescriptor(
  miniscript: string,
  addressType: MiniscriptAddressType,
  keypath = "",
): string {
  if (addressType === MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT) {
    return withDescriptorChecksum(`wsh(${miniscript})`);
  }
  if (addressType === MINISCRIPT_ADDRESS_TYPE_TAPROOT) {
    return withDescriptorChecksum(`tr(${keypath},${miniscript})`);
  }
  invalid("Invalid address type");
}

export function withDescriptorChecksum(descriptor: string): string {
  return `${descriptor}#${descriptorChecksum(descriptor)}`;
}
