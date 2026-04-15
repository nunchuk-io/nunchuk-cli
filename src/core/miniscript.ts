import { descriptorChecksum } from "./descriptor.js";
import type { AddressType } from "./address-type.js";

const LOCKTIME_THRESHOLD = 500000000;
const MAX_PUBKEYS_PER_MULTISIG = 20;
const MAX_PUBKEYS_PER_MULTI_A = 999;
const MAX_OPS_PER_SCRIPT = 201;
const MAX_STANDARD_P2WSH_STACK_ITEMS = 100;
const MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;
const MAX_STANDARD_TX_WEIGHT = 400000;
const MAX_STACK_SIZE = 1000;
const MAX_TAPMINISCRIPT_STACK_ELEM_SIZE = 65;
const TAPROOT_CONTROL_BASE_SIZE = 33;
const TAPROOT_CONTROL_NODE_SIZE = 32;
const TAPROOT_CONTROL_MAX_NODE_COUNT = 128;
const TAPROOT_CONTROL_MAX_SIZE =
  TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;
const SEQUENCE_LOCKTIME_MASK = 0x0000ffff;
const SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22;
const SEQUENCE_LOCKTIME_GRANULARITY = 9;
const WITNESS_SCALE_FACTOR = 4;

export const UNDETERMINED_TIMELOCK_VALUE = Number.MAX_SAFE_INTEGER;

type MiniscriptContextAddressType = Extract<AddressType, "NATIVE_SEGWIT" | "TAPROOT">;

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
  flags: number;
  base?: MiniscriptBaseType;
  d: boolean;
  e: boolean;
  f: boolean;
  g: boolean;
  h: boolean;
  i: boolean;
  j: boolean;
  k: boolean;
  m: boolean;
  n: boolean;
  o: boolean;
  s: boolean;
  u: boolean;
  x: boolean;
  z: boolean;
}

interface MaxInt {
  valid: boolean;
  value: number;
}

interface MiniscriptOps {
  count: number;
  dsat: MaxInt;
  sat: MaxInt;
}

interface SatInfo {
  exec: number;
  netdiff: number;
  valid: boolean;
}

interface StackSize {
  dsat: SatInfo;
  sat: SatInfo;
}

interface WitnessSize {
  dsat: MaxInt;
  sat: MaxInt;
}

interface MiniscriptResourceStats {
  ops: MiniscriptOps;
  stackSize: StackSize;
  witnessSize: WitnessSize;
}

const TYPE_FLAG_BITS: Record<string, number> = {
  B: 1 << 0,
  V: 1 << 1,
  K: 1 << 2,
  W: 1 << 3,
  z: 1 << 4,
  o: 1 << 5,
  n: 1 << 6,
  d: 1 << 7,
  u: 1 << 8,
  e: 1 << 9,
  f: 1 << 10,
  s: 1 << 11,
  m: 1 << 12,
  x: 1 << 13,
  g: 1 << 14,
  h: 1 << 15,
  i: 1 << 16,
  j: 1 << 17,
  k: 1 << 18,
};

const miniscriptTemplateValidationCache = new Map<string, ValidateResult>();

function invalid(message: string): never {
  throw new Error(message);
}

function isMiniscriptContextAddressType(
  addressType: AddressType,
): addressType is MiniscriptContextAddressType {
  return addressType === "NATIVE_SEGWIT" || addressType === "TAPROOT";
}

function resolveMiniscriptContext(
  expression: string,
  addressType?: AddressType,
): MiniscriptContextAddressType {
  if (addressType !== undefined) {
    if (!isMiniscriptContextAddressType(addressType)) {
      invalid("Only native segwit and taproot miniscript are supported");
    }
    return addressType;
  }
  return expression.includes("multi_a(") ? "TAPROOT" : "NATIVE_SEGWIT";
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

type TextParseContext =
  | "WRAPPED_EXPR"
  | "EXPR"
  | "SWAP"
  | "ALT"
  | "CHECK"
  | "DUP_IF"
  | "VERIFY"
  | "NON_ZERO"
  | "ZERO_NOTEQUAL"
  | "WRAP_U"
  | "WRAP_T"
  | "AND_N"
  | "AND_V"
  | "AND_B"
  | "ANDOR"
  | "OR_B"
  | "OR_C"
  | "OR_D"
  | "OR_I"
  | "THRESH"
  | "COMMA"
  | "CLOSE_BRACKET";

interface TextParseFrame {
  context: TextParseContext;
  k: number;
  n: number;
}

function parseMiniscriptFragment(
  expression: string,
  addressType?: AddressType,
): MiniscriptFragment {
  const input = expression.trim();
  if (input.length === 0) {
    invalid("Miniscript expression is empty");
  }

  const context = resolveMiniscriptContext(input, addressType);
  const toParse: TextParseFrame[] = [{ context: "WRAPPED_EXPR", k: -1, n: -1 }];
  const constructed: MiniscriptFragment[] = [];
  let pos = 0;

  const malformed = (): never => invalid(`Invalid miniscript expression: ${expression}`);
  const consume = (prefix: string): boolean => {
    if (!input.startsWith(prefix, pos)) {
      return false;
    }
    pos += prefix.length;
    return true;
  };
  const findNextChar = (ch: string): number => {
    for (let i = pos; i < input.length; i++) {
      if (input[i] === ch) return i;
      if (input[i] === ")") break;
    }
    return -1;
  };
  const parseIntegralEnd = (field: string): number => {
    const close = findNextChar(")");
    if (close - pos < 1) malformed();
    const raw = input.slice(pos, close);
    if (!isNumeric(raw)) malformed();
    const parsed = Number.parseInt(raw, 10);
    if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed >= 0x80000000) {
      invalid(`Invalid ${field}: ${raw}`);
    }
    pos = close + 1;
    return parsed;
  };
  const parseHashEnd = (bytes: number, name: string): string => {
    const close = findNextChar(")");
    if (close - pos < 1) malformed();
    const data = parseHashArg(input.slice(pos, close), bytes, name);
    pos = close + 1;
    return data;
  };
  const parseKeyEnd = (): string => {
    const close = findNextChar(")");
    const keySize = close - pos;
    if (keySize < 1 || keySize > 200) malformed();
    const key = input.slice(pos, close);
    pos = close + 1;
    return key;
  };
  const parseThresholdBeforeComma = (name: string): number => {
    const comma = findNextChar(",");
    if (comma - pos < 1) malformed();
    const raw = input.slice(pos, comma);
    if (!isNumeric(raw)) malformed();
    const k = Number.parseInt(raw, 10);
    if (!Number.isSafeInteger(k) || k < 1) {
      invalid(`Invalid ${name} threshold`);
    }
    pos = comma + 1;
    return k;
  };
  const replaceTop = (fragment: MiniscriptFragment): void => {
    if (constructed.length < 1) malformed();
    constructed[constructed.length - 1] = fragment;
  };
  const getTop = (): MiniscriptFragment => {
    const top = constructed[constructed.length - 1];
    if (!top) malformed();
    return top;
  };
  const wrapTop = (fragment: WrapperFragment): void => {
    if (constructed.length < 1) malformed();
    replaceTop({ fragment, sub: getTop() });
  };
  const buildBack = (fragment: BinaryFragment): void => {
    if (constructed.length < 2) malformed();
    const child = constructed.pop() ?? malformed();
    replaceTop({ fragment, subs: [getTop(), child] });
  };
  const parseBinaryContext = (): TextParseContext => {
    if (consume("and_n(")) return "AND_N";
    if (consume("and_b(")) return "AND_B";
    if (consume("and_v(")) return "AND_V";
    if (consume("or_b(")) return "OR_B";
    if (consume("or_c(")) return "OR_C";
    if (consume("or_d(")) return "OR_D";
    if (consume("or_i(")) return "OR_I";
    return malformed();
  };
  const parseMultiExpression = (isMultiA: boolean): void => {
    if ((isMultiA && context !== "TAPROOT") || (!isMultiA && context !== "NATIVE_SEGWIT")) {
      malformed();
    }

    const name = isMultiA ? "multi_a" : "multi";
    const k = parseThresholdBeforeComma(name);
    const keys: string[] = [];
    let nextComma = pos - 1;
    while (nextComma !== -1) {
      nextComma = findNextChar(",");
      const close = findNextChar(")");
      const keyEnd = nextComma === -1 || (close !== -1 && close < nextComma) ? close : nextComma;
      const keyLength = keyEnd - pos;
      if (keyEnd < 0 || keyLength < 1 || keyLength > 200) malformed();
      keys.push(input.slice(pos, keyEnd));
      pos = keyEnd + 1;
      if (keyEnd === close) {
        nextComma = -1;
      }
    }

    const maxKeys = isMultiA ? MAX_PUBKEYS_PER_MULTI_A : MAX_PUBKEYS_PER_MULTISIG;
    if (keys.length < 1 || keys.length > maxKeys || k > keys.length) {
      invalid(`Invalid ${name}() threshold`);
    }
    constructed.push({ fragment: isMultiA ? "MULTI_A" : "MULTI", k, keys });
  };

  while (toParse.length > 0) {
    const frame = toParse.pop() ?? malformed();

    switch (frame.context) {
      case "WRAPPED_EXPR": {
        let colonIndex: number | undefined;
        for (let i = pos + 1; i < input.length; i++) {
          const code = input.charCodeAt(i);
          if (input[i] === ":") {
            colonIndex = i;
            break;
          }
          if (code < 97 || code > 122) {
            break;
          }
        }

        let lastWasVerify = false;
        if (colonIndex != null) {
          for (let i = pos; i < colonIndex; i++) {
            switch (input[i]) {
              case "a":
                toParse.push({ context: "ALT", k: -1, n: -1 });
                break;
              case "s":
                toParse.push({ context: "SWAP", k: -1, n: -1 });
                break;
              case "c":
                toParse.push({ context: "CHECK", k: -1, n: -1 });
                break;
              case "d":
                toParse.push({ context: "DUP_IF", k: -1, n: -1 });
                break;
              case "j":
                toParse.push({ context: "NON_ZERO", k: -1, n: -1 });
                break;
              case "n":
                toParse.push({ context: "ZERO_NOTEQUAL", k: -1, n: -1 });
                break;
              case "v":
                if (lastWasVerify) malformed();
                toParse.push({ context: "VERIFY", k: -1, n: -1 });
                break;
              case "u":
                toParse.push({ context: "WRAP_U", k: -1, n: -1 });
                break;
              case "t":
                toParse.push({ context: "WRAP_T", k: -1, n: -1 });
                break;
              case "l":
                constructed.push({ fragment: "JUST_0" });
                toParse.push({ context: "OR_I", k: -1, n: -1 });
                break;
              default:
                malformed();
            }
            lastWasVerify = input[i] === "v";
          }
          pos = colonIndex + 1;
        }
        toParse.push({ context: "EXPR", k: -1, n: -1 });
        break;
      }
      case "EXPR": {
        if (consume("0")) {
          constructed.push({ fragment: "JUST_0" });
        } else if (consume("1")) {
          constructed.push({ fragment: "JUST_1" });
        } else if (consume("pk(")) {
          constructed.push({ fragment: "WRAP_C", sub: { fragment: "PK_K", key: parseKeyEnd() } });
        } else if (consume("pkh(")) {
          constructed.push({ fragment: "WRAP_C", sub: { fragment: "PK_H", key: parseKeyEnd() } });
        } else if (consume("pk_k(")) {
          constructed.push({ fragment: "PK_K", key: parseKeyEnd() });
        } else if (consume("pk_h(")) {
          constructed.push({ fragment: "PK_H", key: parseKeyEnd() });
        } else if (consume("sha256(")) {
          constructed.push({ fragment: "SHA256", data: parseHashEnd(32, "sha256") });
        } else if (consume("ripemd160(")) {
          constructed.push({ fragment: "RIPEMD160", data: parseHashEnd(20, "ripemd160") });
        } else if (consume("hash256(")) {
          constructed.push({ fragment: "HASH256", data: parseHashEnd(32, "hash256") });
        } else if (consume("hash160(")) {
          constructed.push({ fragment: "HASH160", data: parseHashEnd(20, "hash160") });
        } else if (consume("after(")) {
          constructed.push({ fragment: "AFTER", k: parseIntegralEnd("after value") });
        } else if (consume("older(")) {
          constructed.push({ fragment: "OLDER", k: parseIntegralEnd("older value") });
        } else if (consume("multi(")) {
          parseMultiExpression(false);
        } else if (consume("multi_a(")) {
          parseMultiExpression(true);
        } else if (consume("thresh(")) {
          const k = parseThresholdBeforeComma("thresh");
          toParse.push({ context: "THRESH", k, n: 1 });
          toParse.push({ context: "WRAPPED_EXPR", k: -1, n: -1 });
        } else if (consume("andor(")) {
          toParse.push({ context: "ANDOR", k: -1, n: -1 });
          toParse.push({ context: "CLOSE_BRACKET", k: -1, n: -1 });
          toParse.push({ context: "WRAPPED_EXPR", k: -1, n: -1 });
          toParse.push({ context: "COMMA", k: -1, n: -1 });
          toParse.push({ context: "WRAPPED_EXPR", k: -1, n: -1 });
          toParse.push({ context: "COMMA", k: -1, n: -1 });
          toParse.push({ context: "WRAPPED_EXPR", k: -1, n: -1 });
        } else {
          toParse.push({ context: parseBinaryContext(), k: -1, n: -1 });
          toParse.push({ context: "CLOSE_BRACKET", k: -1, n: -1 });
          toParse.push({ context: "WRAPPED_EXPR", k: -1, n: -1 });
          toParse.push({ context: "COMMA", k: -1, n: -1 });
          toParse.push({ context: "WRAPPED_EXPR", k: -1, n: -1 });
        }
        break;
      }
      case "ALT":
        wrapTop("WRAP_A");
        break;
      case "SWAP":
        wrapTop("WRAP_S");
        break;
      case "CHECK":
        wrapTop("WRAP_C");
        break;
      case "DUP_IF":
        wrapTop("WRAP_D");
        break;
      case "VERIFY":
        wrapTop("WRAP_V");
        break;
      case "NON_ZERO":
        wrapTop("WRAP_J");
        break;
      case "ZERO_NOTEQUAL":
        wrapTop("WRAP_N");
        break;
      case "WRAP_U":
        if (constructed.length < 1) malformed();
        replaceTop({
          fragment: "OR_I",
          subs: [getTop(), { fragment: "JUST_0" }],
        });
        break;
      case "WRAP_T":
        if (constructed.length < 1) malformed();
        replaceTop({
          fragment: "AND_V",
          subs: [getTop(), { fragment: "JUST_1" }],
        });
        break;
      case "AND_B":
      case "AND_V":
      case "OR_B":
      case "OR_C":
      case "OR_D":
      case "OR_I":
        buildBack(frame.context);
        break;
      case "AND_N": {
        if (constructed.length < 2) malformed();
        const mid = constructed.pop() ?? malformed();
        replaceTop({
          fragment: "ANDOR",
          subs: [getTop(), mid, { fragment: "JUST_0" }],
        });
        break;
      }
      case "ANDOR": {
        if (constructed.length < 3) malformed();
        const right = constructed.pop() ?? malformed();
        const mid = constructed.pop() ?? malformed();
        replaceTop({ fragment: "ANDOR", subs: [getTop(), mid, right] });
        break;
      }
      case "THRESH":
        if (pos >= input.length) malformed();
        if (input[pos] === ",") {
          pos++;
          toParse.push({ context: "THRESH", k: frame.k, n: frame.n + 1 });
          toParse.push({ context: "WRAPPED_EXPR", k: -1, n: -1 });
        } else if (input[pos] === ")") {
          if (frame.k > frame.n || constructed.length < frame.n) {
            invalid("Invalid thresh() threshold");
          }
          pos++;
          const subs = constructed.splice(constructed.length - frame.n, frame.n);
          constructed.push({ fragment: "THRESH", k: frame.k, subs });
        } else {
          malformed();
        }
        break;
      case "COMMA":
        if (input[pos] !== ",") malformed();
        pos++;
        break;
      case "CLOSE_BRACKET":
        if (input[pos] !== ")") malformed();
        pos++;
        break;
    }
  }

  if (constructed.length !== 1 || pos !== input.length) {
    malformed();
  }
  return constructed[0] ?? malformed();
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

function typeBits(flags: string): number {
  let result = 0;
  for (const flag of flags) {
    const bit = TYPE_FLAG_BITS[flag];
    if (bit == null) invalid(`Unknown miniscript type flag: ${flag}`);
    result |= bit;
  }
  return result;
}

function typeFromFlags(flags: number): MiniscriptTypeInfo {
  const has = (flag: string): boolean => (flags & typeBits(flag)) === typeBits(flag);
  const bases = (["B", "V", "K", "W"] as const).filter((base) => has(base));
  return {
    flags,
    base: bases.length === 1 ? bases[0] : undefined,
    d: has("d"),
    e: has("e"),
    f: has("f"),
    g: has("g"),
    h: has("h"),
    i: has("i"),
    j: has("j"),
    k: has("k"),
    m: has("m"),
    n: has("n"),
    o: has("o"),
    s: has("s"),
    u: has("u"),
    x: has("x"),
    z: has("z"),
  };
}

function typeFromString(flags: string): MiniscriptTypeInfo {
  return typeFromFlags(typeBits(flags));
}

function invalidType(): MiniscriptTypeInfo {
  return typeFromFlags(0);
}

function typeOr(...types: MiniscriptTypeInfo[]): MiniscriptTypeInfo {
  return typeFromFlags(types.reduce((flags, type) => flags | type.flags, 0));
}

function typeAnd(...types: MiniscriptTypeInfo[]): MiniscriptTypeInfo {
  return typeFromFlags(types.reduce((flags, type) => flags & type.flags, types[0]?.flags ?? 0));
}

function typeIf(type: MiniscriptTypeInfo | string, condition: boolean): MiniscriptTypeInfo {
  if (!condition) return invalidType();
  return typeof type === "string" ? typeFromString(type) : type;
}

function typeHasAll(type: MiniscriptTypeInfo, flags: string): boolean {
  const bits = typeBits(flags);
  return (type.flags & bits) === bits;
}

function sanitizeType(type: MiniscriptTypeInfo): MiniscriptTypeInfo {
  const baseCount = (["B", "V", "K", "W"] as const).filter((base) => typeHasAll(type, base)).length;
  return baseCount === 1 ? type : invalidType();
}

function hasTimelockConflict(x: MiniscriptTypeInfo, y: MiniscriptTypeInfo): boolean {
  return (
    (typeHasAll(x, "g") && typeHasAll(y, "h")) ||
    (typeHasAll(x, "h") && typeHasAll(y, "g")) ||
    (typeHasAll(x, "i") && typeHasAll(y, "j")) ||
    (typeHasAll(x, "j") && typeHasAll(y, "i"))
  );
}

function computeMiniscriptType(
  node: MiniscriptFragment,
  addressType: AddressType,
): MiniscriptTypeInfo {
  const tapscript = addressType === "TAPROOT";
  const result = ((): MiniscriptTypeInfo => {
    switch (node.fragment) {
      case "JUST_0":
        return typeFromString("Bzudemsxk");
      case "JUST_1":
        return typeFromString("Bzufmxk");
      case "PK":
        return computeMiniscriptType(
          { fragment: "WRAP_C", sub: { fragment: "PK_K", key: node.key } },
          addressType,
        );
      case "PKH":
        return computeMiniscriptType(
          { fragment: "WRAP_C", sub: { fragment: "PK_H", key: node.key } },
          addressType,
        );
      case "PK_K":
        return typeFromString("Konudemsxk");
      case "PK_H":
        return typeFromString("Knudemsxk");
      case "OLDER":
        if (node.k < 1 || node.k >= 0x80000000) {
          invalid("older() value must be between 1 and 2^31 - 1");
        }
        return typeOr(
          typeIf("g", (node.k & SEQUENCE_LOCKTIME_TYPE_FLAG) !== 0),
          typeIf("h", (node.k & SEQUENCE_LOCKTIME_TYPE_FLAG) === 0),
          typeFromString("Bzfmxk"),
        );
      case "AFTER":
        if (node.k < 1 || node.k >= 0x80000000) {
          invalid("after() value must be between 1 and 2^31 - 1");
        }
        return typeOr(
          typeIf("i", node.k >= LOCKTIME_THRESHOLD),
          typeIf("j", node.k < LOCKTIME_THRESHOLD),
          typeFromString("Bzfmxk"),
        );
      case "SHA256":
      case "RIPEMD160":
      case "HASH256":
      case "HASH160":
        return typeFromString("Bonudmk");
      case "MULTI":
        if (tapscript) invalid("multi() is not valid for taproot miniscript");
        return typeFromString("Bnudemsk");
      case "MULTI_A":
        if (!tapscript) invalid("multi_a() is only valid for taproot miniscript");
        return typeFromString("Budemsk");
      case "WRAP_A": {
        const x = computeMiniscriptType(node.sub, addressType);
        return typeOr(
          typeIf("W", typeHasAll(x, "B")),
          typeAnd(x, typeFromString("ghijk")),
          typeAnd(x, typeFromString("udfems")),
          typeFromString("x"),
        );
      }
      case "WRAP_S": {
        const x = computeMiniscriptType(node.sub, addressType);
        return typeOr(
          typeIf("W", typeHasAll(x, "Bo")),
          typeAnd(x, typeFromString("ghijk")),
          typeAnd(x, typeFromString("udfemsx")),
        );
      }
      case "WRAP_C": {
        const x = computeMiniscriptType(node.sub, addressType);
        return typeOr(
          typeIf("B", typeHasAll(x, "K")),
          typeAnd(x, typeFromString("ghijk")),
          typeAnd(x, typeFromString("ondfem")),
          typeFromString("us"),
        );
      }
      case "WRAP_D": {
        const x = computeMiniscriptType(node.sub, addressType);
        return typeOr(
          typeIf("B", typeHasAll(x, "Vz")),
          typeIf("o", typeHasAll(x, "z")),
          typeIf("e", typeHasAll(x, "f")),
          typeAnd(x, typeFromString("ghijk")),
          typeAnd(x, typeFromString("ms")),
          typeIf("u", tapscript),
          typeFromString("ndx"),
        );
      }
      case "WRAP_V": {
        const x = computeMiniscriptType(node.sub, addressType);
        return typeOr(
          typeIf("V", typeHasAll(x, "B")),
          typeAnd(x, typeFromString("ghijk")),
          typeAnd(x, typeFromString("zonms")),
          typeFromString("fx"),
        );
      }
      case "WRAP_J": {
        const x = computeMiniscriptType(node.sub, addressType);
        return typeOr(
          typeIf("B", typeHasAll(x, "Bn")),
          typeIf("e", typeHasAll(x, "f")),
          typeAnd(x, typeFromString("ghijk")),
          typeAnd(x, typeFromString("oums")),
          typeFromString("ndx"),
        );
      }
      case "WRAP_N": {
        const x = computeMiniscriptType(node.sub, addressType);
        return typeOr(
          typeAnd(x, typeFromString("ghijk")),
          typeAnd(x, typeFromString("Bzondfems")),
          typeFromString("ux"),
        );
      }
      case "AND_V": {
        const x = computeMiniscriptType(node.subs[0], addressType);
        const y = computeMiniscriptType(node.subs[1], addressType);
        return typeOr(
          typeIf(typeAnd(y, typeFromString("KVB")), typeHasAll(x, "V")),
          typeAnd(x, typeFromString("n")),
          typeIf(typeAnd(y, typeFromString("n")), typeHasAll(x, "z")),
          typeIf(typeAnd(typeOr(x, y), typeFromString("o")), typeHasAll(typeOr(x, y), "z")),
          typeAnd(x, y, typeFromString("dmz")),
          typeAnd(typeOr(x, y), typeFromString("s")),
          typeIf("f", typeHasAll(y, "f") || typeHasAll(x, "s")),
          typeAnd(y, typeFromString("ux")),
          typeAnd(typeOr(x, y), typeFromString("ghij")),
          typeIf("k", typeHasAll(typeAnd(x, y), "k") && !hasTimelockConflict(x, y)),
        );
      }
      case "AND_B": {
        const x = computeMiniscriptType(node.subs[0], addressType);
        const y = computeMiniscriptType(node.subs[1], addressType);
        return typeOr(
          typeIf(typeAnd(x, typeFromString("B")), typeHasAll(y, "W")),
          typeIf(typeAnd(typeOr(x, y), typeFromString("o")), typeHasAll(typeOr(x, y), "z")),
          typeAnd(x, typeFromString("n")),
          typeIf(typeAnd(y, typeFromString("n")), typeHasAll(x, "z")),
          typeIf(typeAnd(x, y, typeFromString("e")), typeHasAll(typeAnd(x, y), "s")),
          typeAnd(x, y, typeFromString("dzm")),
          typeIf("f", typeHasAll(typeAnd(x, y), "f") || typeHasAll(x, "sf") || typeHasAll(y, "sf")),
          typeAnd(typeOr(x, y), typeFromString("s")),
          typeFromString("ux"),
          typeAnd(typeOr(x, y), typeFromString("ghij")),
          typeIf("k", typeHasAll(typeAnd(x, y), "k") && !hasTimelockConflict(x, y)),
        );
      }
      case "OR_B": {
        const x = computeMiniscriptType(node.subs[0], addressType);
        const y = computeMiniscriptType(node.subs[1], addressType);
        return typeOr(
          typeIf("B", typeHasAll(x, "Bd") && typeHasAll(y, "Wd")),
          typeIf(typeAnd(typeOr(x, y), typeFromString("o")), typeHasAll(typeOr(x, y), "z")),
          typeIf(
            typeAnd(x, y, typeFromString("m")),
            typeHasAll(typeOr(x, y), "s") && typeHasAll(typeAnd(x, y), "e"),
          ),
          typeAnd(x, y, typeFromString("zse")),
          typeFromString("dux"),
          typeAnd(typeOr(x, y), typeFromString("ghij")),
          typeAnd(x, y, typeFromString("k")),
        );
      }
      case "OR_D": {
        const x = computeMiniscriptType(node.subs[0], addressType);
        const y = computeMiniscriptType(node.subs[1], addressType);
        return typeOr(
          typeIf(typeAnd(y, typeFromString("B")), typeHasAll(x, "Bdu")),
          typeIf(typeAnd(x, typeFromString("o")), typeHasAll(y, "z")),
          typeIf(
            typeAnd(x, y, typeFromString("m")),
            typeHasAll(x, "e") && typeHasAll(typeOr(x, y), "s"),
          ),
          typeAnd(x, y, typeFromString("zs")),
          typeAnd(y, typeFromString("ufde")),
          typeFromString("x"),
          typeAnd(typeOr(x, y), typeFromString("ghij")),
          typeAnd(x, y, typeFromString("k")),
        );
      }
      case "OR_C": {
        const x = computeMiniscriptType(node.subs[0], addressType);
        const y = computeMiniscriptType(node.subs[1], addressType);
        return typeOr(
          typeIf(typeAnd(y, typeFromString("V")), typeHasAll(x, "Bdu")),
          typeIf(typeAnd(x, typeFromString("o")), typeHasAll(y, "z")),
          typeIf(
            typeAnd(x, y, typeFromString("m")),
            typeHasAll(x, "e") && typeHasAll(typeOr(x, y), "s"),
          ),
          typeAnd(x, y, typeFromString("zs")),
          typeFromString("fx"),
          typeAnd(typeOr(x, y), typeFromString("ghij")),
          typeAnd(x, y, typeFromString("k")),
        );
      }
      case "OR_I": {
        const x = computeMiniscriptType(node.subs[0], addressType);
        const y = computeMiniscriptType(node.subs[1], addressType);
        return typeOr(
          typeAnd(x, y, typeFromString("VBKufs")),
          typeIf("o", typeHasAll(typeAnd(x, y), "z")),
          typeIf(typeAnd(typeOr(x, y), typeFromString("e")), typeHasAll(typeOr(x, y), "f")),
          typeIf(typeAnd(x, y, typeFromString("m")), typeHasAll(typeOr(x, y), "s")),
          typeAnd(typeOr(x, y), typeFromString("d")),
          typeFromString("x"),
          typeAnd(typeOr(x, y), typeFromString("ghij")),
          typeAnd(x, y, typeFromString("k")),
        );
      }
      case "ANDOR": {
        const x = computeMiniscriptType(node.subs[0], addressType);
        const y = computeMiniscriptType(node.subs[1], addressType);
        const z = computeMiniscriptType(node.subs[2], addressType);
        return typeOr(
          typeIf(typeAnd(y, z, typeFromString("BKV")), typeHasAll(x, "Bdu")),
          typeAnd(x, y, z, typeFromString("z")),
          typeIf(
            typeAnd(typeOr(x, typeAnd(y, z)), typeFromString("o")),
            typeHasAll(typeOr(x, typeAnd(y, z)), "z"),
          ),
          typeAnd(y, z, typeFromString("u")),
          typeIf(typeAnd(z, typeFromString("f")), typeHasAll(x, "s") || typeHasAll(y, "f")),
          typeAnd(z, typeFromString("d")),
          typeIf(typeAnd(z, typeFromString("e")), typeHasAll(x, "s") || typeHasAll(y, "f")),
          typeIf(
            typeAnd(x, y, z, typeFromString("m")),
            typeHasAll(x, "e") && typeHasAll(typeOr(x, y, z), "s"),
          ),
          typeAnd(z, typeOr(x, y), typeFromString("s")),
          typeFromString("x"),
          typeAnd(typeOr(x, y, z), typeFromString("ghij")),
          typeIf("k", typeHasAll(typeAnd(x, y, z), "k") && !hasTimelockConflict(x, y)),
        );
      }
      case "THRESH": {
        const subTypes = node.subs.map((sub) => computeMiniscriptType(sub, addressType));
        let allE = true;
        let allM = true;
        let args = 0;
        let numS = 0;
        let accTl = typeFromString("k");

        for (let index = 0; index < subTypes.length; index++) {
          const type = subTypes[index];
          if (!typeHasAll(type, index === 0 ? "Bdu" : "Wdu")) return invalidType();
          if (!type.e) allE = false;
          if (!type.m) allM = false;
          if (type.s) numS++;
          args += type.z ? 0 : type.o ? 1 : 2;
          accTl = typeOr(
            typeAnd(typeOr(accTl, type), typeFromString("ghij")),
            typeIf(
              "k",
              typeHasAll(typeAnd(accTl, type), "k") &&
                (node.k <= 1 || !hasTimelockConflict(accTl, type)),
            ),
          );
        }

        return typeOr(
          typeFromString("Bdu"),
          typeIf("z", args === 0),
          typeIf("o", args === 1),
          typeIf("e", allE && numS === node.subs.length),
          typeIf("m", allE && allM && numS >= node.subs.length - node.k),
          typeIf("s", numS >= node.subs.length - node.k + 1),
          accTl,
        );
      }
    }
  })();

  return sanitizeType(result);
}

function compactSizeSize(value: number): number {
  if (value < 253) return 1;
  if (value <= 0xffff) return 3;
  if (value <= 0xffffffff) return 5;
  return 9;
}

function scriptNumberPushSize(value: number): number {
  if (value >= 0 && value <= 16) return 1;
  let bytes = 0;
  let remaining = value;
  while (remaining > 0) {
    bytes++;
    remaining = Math.floor(remaining / 256);
  }
  const highByte = Math.floor(value / 256 ** (bytes - 1)) & 0xff;
  if ((highByte & 0x80) !== 0) bytes++;
  return 1 + bytes;
}

function maxScriptSize(addressType: AddressType): number {
  if (addressType !== "TAPROOT") {
    return MAX_STANDARD_P2WSH_SCRIPT_SIZE;
  }
  const txOverhead = 4 + 4;
  const txinBytesNoWitness = 36 + 4 + 1;
  const p2wshTxoutBytes = 8 + 1 + 1 + 33;
  const txBodyLeewayWeight =
    (txOverhead + compactSizeSize(1) + txinBytesNoWitness + compactSizeSize(1) + p2wshTxoutBytes) *
      WITNESS_SCALE_FACTOR +
    2;
  const maxTapscriptSatSize =
    compactSizeSize(MAX_STACK_SIZE) +
    (compactSizeSize(MAX_TAPMINISCRIPT_STACK_ELEM_SIZE) + MAX_TAPMINISCRIPT_STACK_ELEM_SIZE) *
      MAX_STACK_SIZE +
    compactSizeSize(TAPROOT_CONTROL_MAX_SIZE) +
    TAPROOT_CONTROL_MAX_SIZE;
  const maxSize = MAX_STANDARD_TX_WEIGHT - txBodyLeewayWeight - maxTapscriptSatSize;
  return maxSize - compactSizeSize(maxSize);
}

function computeMiniscriptScriptSize(node: MiniscriptFragment, addressType: AddressType): number {
  const childSizes = (subs: MiniscriptFragment[]): number =>
    subs.reduce((size, sub) => size + computeMiniscriptScriptSize(sub, addressType), 0);
  switch (node.fragment) {
    case "JUST_0":
    case "JUST_1":
      return 1;
    case "PK":
      return computeMiniscriptScriptSize(
        { fragment: "WRAP_C", sub: { fragment: "PK_K", key: node.key } },
        addressType,
      );
    case "PKH":
      return computeMiniscriptScriptSize(
        { fragment: "WRAP_C", sub: { fragment: "PK_H", key: node.key } },
        addressType,
      );
    case "PK_K":
      return addressType === "TAPROOT" ? 33 : 34;
    case "PK_H":
      return 24;
    case "OLDER":
    case "AFTER":
      return 1 + scriptNumberPushSize(node.k);
    case "SHA256":
    case "HASH256":
      return 39;
    case "HASH160":
    case "RIPEMD160":
      return 27;
    case "MULTI":
      return (
        1 +
        scriptNumberPushSize(node.keys.length) +
        scriptNumberPushSize(node.k) +
        34 * node.keys.length
      );
    case "MULTI_A":
      return (1 + 32 + 1) * node.keys.length + scriptNumberPushSize(node.k) + 1;
    case "AND_V":
      return childSizes(node.subs);
    case "WRAP_V": {
      const subType = computeMiniscriptType(node.sub, addressType);
      return computeMiniscriptScriptSize(node.sub, addressType) + (subType.x ? 1 : 0);
    }
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_N":
      return computeMiniscriptScriptSize(node.sub, addressType) + 1;
    case "AND_B":
    case "OR_B":
      return childSizes(node.subs) + 1;
    case "WRAP_A":
      return computeMiniscriptScriptSize(node.sub, addressType) + 2;
    case "OR_C":
      return childSizes(node.subs) + 2;
    case "WRAP_D":
      return computeMiniscriptScriptSize(node.sub, addressType) + 3;
    case "OR_D":
    case "OR_I":
      return childSizes(node.subs) + 3;
    case "ANDOR":
      return childSizes(node.subs) + 3;
    case "WRAP_J":
      return computeMiniscriptScriptSize(node.sub, addressType) + 4;
    case "THRESH":
      return childSizes(node.subs) + node.subs.length + scriptNumberPushSize(node.k);
  }
}

function maxInt(value?: number): MaxInt {
  return value == null ? { valid: false, value: 0 } : { valid: true, value };
}

function maxIntAdd(a: MaxInt, b: MaxInt): MaxInt {
  if (!a.valid || !b.valid) return maxInt();
  return maxInt(a.value + b.value);
}

function maxIntAddValue(a: MaxInt, value: number): MaxInt {
  return maxIntAdd(a, maxInt(value));
}

function maxIntOr(a: MaxInt, b: MaxInt): MaxInt {
  if (!a.valid) return b;
  if (!b.valid) return a;
  return maxInt(Math.max(a.value, b.value));
}

function satInfo(netdiff?: number, exec?: number): SatInfo {
  return netdiff == null || exec == null
    ? { exec: 0, netdiff: 0, valid: false }
    : { exec, netdiff, valid: true };
}

function satInfoOr(a: SatInfo, b: SatInfo): SatInfo {
  if (!a.valid) return b;
  if (!b.valid) return a;
  return satInfo(Math.max(a.netdiff, b.netdiff), Math.max(a.exec, b.exec));
}

function satInfoAdd(a: SatInfo, b: SatInfo): SatInfo {
  if (!a.valid || !b.valid) return satInfo();
  return satInfo(a.netdiff + b.netdiff, Math.max(b.exec, b.netdiff + a.exec));
}

const Sat = {
  BinaryOp: (): SatInfo => satInfo(1, 1),
  Empty: (): SatInfo => satInfo(0, 0),
  Hash: (): SatInfo => satInfo(0, 0),
  If: (): SatInfo => satInfo(1, 1),
  Nop: (): SatInfo => satInfo(0, 0),
  OP_0NOTEQUAL: (): SatInfo => satInfo(0, 0),
  OP_CHECKSIG: (): SatInfo => satInfo(1, 1),
  OP_DUP: (): SatInfo => satInfo(-1, 0),
  OP_EQUAL: (): SatInfo => satInfo(1, 1),
  OP_EQUALVERIFY: (): SatInfo => satInfo(2, 2),
  OP_IFDUP: (nonzero: boolean): SatInfo => satInfo(nonzero ? -1 : 0, 0),
  OP_SIZE: (): SatInfo => satInfo(-1, 0),
  OP_VERIFY: (): SatInfo => satInfo(1, 1),
  Push: (): SatInfo => satInfo(-1, 0),
};

function pkSugarNode(node: {
  fragment: "PK" | "PKH" | "PK_H" | "PK_K";
  key: string;
}): MiniscriptFragment {
  return {
    fragment: "WRAP_C",
    sub: { fragment: node.fragment === "PK" ? "PK_K" : "PK_H", key: node.key },
  };
}

function computeMiniscriptOps(node: MiniscriptFragment, addressType: AddressType): MiniscriptOps {
  const childOps = (sub: MiniscriptFragment): MiniscriptOps =>
    computeMiniscriptOps(sub, addressType);

  switch (node.fragment) {
    case "PK":
    case "PKH":
      return computeMiniscriptOps(pkSugarNode(node), addressType);
    case "JUST_1":
      return { count: 0, dsat: maxInt(), sat: maxInt(0) };
    case "JUST_0":
      return { count: 0, dsat: maxInt(0), sat: maxInt() };
    case "PK_K":
      return { count: 0, dsat: maxInt(0), sat: maxInt(0) };
    case "PK_H":
      return { count: 3, dsat: maxInt(0), sat: maxInt(0) };
    case "OLDER":
    case "AFTER":
      return { count: 1, dsat: maxInt(), sat: maxInt(0) };
    case "SHA256":
    case "RIPEMD160":
    case "HASH256":
    case "HASH160":
      return { count: 4, dsat: maxInt(), sat: maxInt(0) };
    case "AND_V": {
      const x = childOps(node.subs[0]);
      const y = childOps(node.subs[1]);
      return {
        count: x.count + y.count,
        dsat: maxInt(),
        sat: maxIntAdd(x.sat, y.sat),
      };
    }
    case "AND_B": {
      const x = childOps(node.subs[0]);
      const y = childOps(node.subs[1]);
      return {
        count: 1 + x.count + y.count,
        dsat: maxIntAdd(x.dsat, y.dsat),
        sat: maxIntAdd(x.sat, y.sat),
      };
    }
    case "OR_B": {
      const x = childOps(node.subs[0]);
      const y = childOps(node.subs[1]);
      return {
        count: 1 + x.count + y.count,
        dsat: maxIntAdd(x.dsat, y.dsat),
        sat: maxIntOr(maxIntAdd(x.sat, y.dsat), maxIntAdd(y.sat, x.dsat)),
      };
    }
    case "OR_D": {
      const x = childOps(node.subs[0]);
      const y = childOps(node.subs[1]);
      return {
        count: 3 + x.count + y.count,
        dsat: maxIntAdd(x.dsat, y.dsat),
        sat: maxIntOr(x.sat, maxIntAdd(y.sat, x.dsat)),
      };
    }
    case "OR_C": {
      const x = childOps(node.subs[0]);
      const y = childOps(node.subs[1]);
      return {
        count: 2 + x.count + y.count,
        dsat: maxInt(),
        sat: maxIntOr(x.sat, maxIntAdd(y.sat, x.dsat)),
      };
    }
    case "OR_I": {
      const x = childOps(node.subs[0]);
      const y = childOps(node.subs[1]);
      return {
        count: 3 + x.count + y.count,
        dsat: maxIntOr(x.dsat, y.dsat),
        sat: maxIntOr(x.sat, y.sat),
      };
    }
    case "ANDOR": {
      const x = childOps(node.subs[0]);
      const y = childOps(node.subs[1]);
      const z = childOps(node.subs[2]);
      return {
        count: 3 + x.count + y.count + z.count,
        dsat: maxIntAdd(x.dsat, z.dsat),
        sat: maxIntOr(maxIntAdd(y.sat, x.sat), maxIntAdd(x.dsat, z.sat)),
      };
    }
    case "MULTI":
      return { count: 1, dsat: maxInt(node.keys.length), sat: maxInt(node.keys.length) };
    case "MULTI_A":
      return { count: node.keys.length + 1, dsat: maxInt(0), sat: maxInt(0) };
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_N": {
      const x = childOps(node.sub);
      return { count: 1 + x.count, dsat: x.dsat, sat: x.sat };
    }
    case "WRAP_A": {
      const x = childOps(node.sub);
      return { count: 2 + x.count, dsat: x.dsat, sat: x.sat };
    }
    case "WRAP_D": {
      const x = childOps(node.sub);
      return { count: 3 + x.count, dsat: maxInt(0), sat: x.sat };
    }
    case "WRAP_J": {
      const x = childOps(node.sub);
      return { count: 4 + x.count, dsat: maxInt(0), sat: x.sat };
    }
    case "WRAP_V": {
      const x = childOps(node.sub);
      const type = computeMiniscriptType(node.sub, addressType);
      return { count: x.count + (type.x ? 1 : 0), dsat: maxInt(), sat: x.sat };
    }
    case "THRESH": {
      let count = 0;
      let sats = [maxInt(0)];
      for (const sub of node.subs) {
        const subOps = childOps(sub);
        count += subOps.count + 1;
        const nextSats = [maxIntAdd(sats[0], subOps.dsat)];
        for (let index = 1; index < sats.length; index++) {
          nextSats.push(
            maxIntOr(maxIntAdd(sats[index], subOps.dsat), maxIntAdd(sats[index - 1], subOps.sat)),
          );
        }
        nextSats.push(maxIntAdd(sats[sats.length - 1], subOps.sat));
        sats = nextSats;
      }
      return { count, dsat: sats[0], sat: sats[node.k] };
    }
  }
}

function computeMiniscriptStackSize(node: MiniscriptFragment, addressType: AddressType): StackSize {
  const childStack = (sub: MiniscriptFragment): StackSize =>
    computeMiniscriptStackSize(sub, addressType);

  switch (node.fragment) {
    case "PK":
    case "PKH":
      return computeMiniscriptStackSize(pkSugarNode(node), addressType);
    case "JUST_0":
      return { dsat: Sat.Push(), sat: satInfo() };
    case "JUST_1":
      return { dsat: satInfo(), sat: Sat.Push() };
    case "OLDER":
    case "AFTER":
      return { dsat: satInfo(), sat: satInfoAdd(Sat.Push(), Sat.Nop()) };
    case "PK_K":
      return { dsat: Sat.Push(), sat: Sat.Push() };
    case "PK_H": {
      const both = satInfoAdd(
        satInfoAdd(satInfoAdd(Sat.OP_DUP(), Sat.Hash()), Sat.Push()),
        Sat.OP_EQUALVERIFY(),
      );
      return { dsat: both, sat: both };
    }
    case "SHA256":
    case "RIPEMD160":
    case "HASH256":
    case "HASH160":
      return {
        dsat: satInfo(),
        sat: satInfoAdd(
          satInfoAdd(
            satInfoAdd(satInfoAdd(Sat.OP_SIZE(), Sat.Push()), Sat.OP_EQUALVERIFY()),
            Sat.Hash(),
          ),
          satInfoAdd(Sat.Push(), Sat.OP_EQUAL()),
        ),
      };
    case "ANDOR": {
      const x = childStack(node.subs[0]);
      const y = childStack(node.subs[1]);
      const z = childStack(node.subs[2]);
      return {
        dsat: satInfoAdd(satInfoAdd(x.dsat, Sat.If()), z.dsat),
        sat: satInfoOr(
          satInfoAdd(satInfoAdd(x.sat, Sat.If()), y.sat),
          satInfoAdd(satInfoAdd(x.dsat, Sat.If()), z.sat),
        ),
      };
    }
    case "AND_V": {
      const x = childStack(node.subs[0]);
      const y = childStack(node.subs[1]);
      return { dsat: satInfo(), sat: satInfoAdd(x.sat, y.sat) };
    }
    case "AND_B": {
      const x = childStack(node.subs[0]);
      const y = childStack(node.subs[1]);
      return {
        dsat: satInfoAdd(satInfoAdd(x.dsat, y.dsat), Sat.BinaryOp()),
        sat: satInfoAdd(satInfoAdd(x.sat, y.sat), Sat.BinaryOp()),
      };
    }
    case "OR_B": {
      const x = childStack(node.subs[0]);
      const y = childStack(node.subs[1]);
      return {
        dsat: satInfoAdd(satInfoAdd(x.dsat, y.dsat), Sat.BinaryOp()),
        sat: satInfoAdd(
          satInfoOr(satInfoAdd(x.sat, y.dsat), satInfoAdd(x.dsat, y.sat)),
          Sat.BinaryOp(),
        ),
      };
    }
    case "OR_C": {
      const x = childStack(node.subs[0]);
      const y = childStack(node.subs[1]);
      return {
        dsat: satInfo(),
        sat: satInfoOr(
          satInfoAdd(x.sat, Sat.If()),
          satInfoAdd(satInfoAdd(x.dsat, Sat.If()), y.sat),
        ),
      };
    }
    case "OR_D": {
      const x = childStack(node.subs[0]);
      const y = childStack(node.subs[1]);
      return {
        dsat: satInfoAdd(satInfoAdd(satInfoAdd(x.dsat, Sat.OP_IFDUP(false)), Sat.If()), y.dsat),
        sat: satInfoOr(
          satInfoAdd(satInfoAdd(x.sat, Sat.OP_IFDUP(true)), Sat.If()),
          satInfoAdd(satInfoAdd(satInfoAdd(x.dsat, Sat.OP_IFDUP(false)), Sat.If()), y.sat),
        ),
      };
    }
    case "OR_I": {
      const x = childStack(node.subs[0]);
      const y = childStack(node.subs[1]);
      return {
        dsat: satInfoAdd(Sat.If(), satInfoOr(x.dsat, y.dsat)),
        sat: satInfoAdd(Sat.If(), satInfoOr(x.sat, y.sat)),
      };
    }
    case "MULTI": {
      const both = satInfo(node.k, node.k + node.keys.length + 2);
      return { dsat: both, sat: both };
    }
    case "MULTI_A": {
      const both = satInfo(node.keys.length - 1, node.keys.length);
      return { dsat: both, sat: both };
    }
    case "WRAP_A":
    case "WRAP_N":
    case "WRAP_S":
      return childStack(node.sub);
    case "WRAP_C": {
      const x = childStack(node.sub);
      return {
        dsat: satInfoAdd(x.dsat, Sat.OP_CHECKSIG()),
        sat: satInfoAdd(x.sat, Sat.OP_CHECKSIG()),
      };
    }
    case "WRAP_D": {
      const prefix = satInfoAdd(Sat.OP_DUP(), Sat.If());
      const x = childStack(node.sub);
      return { dsat: prefix, sat: satInfoAdd(prefix, x.sat) };
    }
    case "WRAP_V": {
      const x = childStack(node.sub);
      return { dsat: satInfo(), sat: satInfoAdd(x.sat, Sat.OP_VERIFY()) };
    }
    case "WRAP_J": {
      const prefix = satInfoAdd(satInfoAdd(Sat.OP_SIZE(), Sat.OP_0NOTEQUAL()), Sat.If());
      const x = childStack(node.sub);
      return { dsat: prefix, sat: satInfoAdd(prefix, x.sat) };
    }
    case "THRESH": {
      let sats = [Sat.Empty()];
      for (let i = 0; i < node.subs.length; i++) {
        const sub = childStack(node.subs[i]);
        const add = i > 0 ? Sat.BinaryOp() : Sat.Empty();
        const nextSats = [satInfoAdd(satInfoAdd(sats[0], sub.dsat), add)];
        for (let index = 1; index < sats.length; index++) {
          nextSats.push(
            satInfoAdd(
              satInfoOr(satInfoAdd(sats[index], sub.dsat), satInfoAdd(sats[index - 1], sub.sat)),
              add,
            ),
          );
        }
        nextSats.push(satInfoAdd(satInfoAdd(sats[sats.length - 1], sub.sat), add));
        sats = nextSats;
      }
      return {
        dsat: satInfoAdd(satInfoAdd(sats[0], Sat.Push()), Sat.OP_EQUAL()),
        sat: satInfoAdd(satInfoAdd(sats[node.k], Sat.Push()), Sat.OP_EQUAL()),
      };
    }
  }
}

function computeMiniscriptWitnessSize(
  node: MiniscriptFragment,
  addressType: AddressType,
): WitnessSize {
  const sigSize = addressType === "TAPROOT" ? 1 + 65 : 1 + 72;
  const pubkeySize = addressType === "TAPROOT" ? 1 + 32 : 1 + 33;
  const childWitness = (sub: MiniscriptFragment): WitnessSize =>
    computeMiniscriptWitnessSize(sub, addressType);

  switch (node.fragment) {
    case "PK":
    case "PKH":
      return computeMiniscriptWitnessSize(pkSugarNode(node), addressType);
    case "JUST_0":
      return { dsat: maxInt(0), sat: maxInt() };
    case "JUST_1":
    case "OLDER":
    case "AFTER":
      return { dsat: maxInt(), sat: maxInt(0) };
    case "PK_K":
      return { dsat: maxInt(1), sat: maxInt(sigSize) };
    case "PK_H":
      return { dsat: maxInt(1 + pubkeySize), sat: maxInt(sigSize + pubkeySize) };
    case "SHA256":
    case "RIPEMD160":
    case "HASH256":
    case "HASH160":
      return { dsat: maxInt(), sat: maxInt(1 + 32) };
    case "ANDOR": {
      const x = childWitness(node.subs[0]);
      const y = childWitness(node.subs[1]);
      const z = childWitness(node.subs[2]);
      return {
        dsat: maxIntAdd(x.dsat, z.dsat),
        sat: maxIntOr(maxIntAdd(x.sat, y.sat), maxIntAdd(x.dsat, z.sat)),
      };
    }
    case "AND_V": {
      const x = childWitness(node.subs[0]);
      const y = childWitness(node.subs[1]);
      return { dsat: maxInt(), sat: maxIntAdd(x.sat, y.sat) };
    }
    case "AND_B": {
      const x = childWitness(node.subs[0]);
      const y = childWitness(node.subs[1]);
      return { dsat: maxIntAdd(x.dsat, y.dsat), sat: maxIntAdd(x.sat, y.sat) };
    }
    case "OR_B": {
      const x = childWitness(node.subs[0]);
      const y = childWitness(node.subs[1]);
      return {
        dsat: maxIntAdd(x.dsat, y.dsat),
        sat: maxIntOr(maxIntAdd(x.dsat, y.sat), maxIntAdd(x.sat, y.dsat)),
      };
    }
    case "OR_C": {
      const x = childWitness(node.subs[0]);
      const y = childWitness(node.subs[1]);
      return { dsat: maxInt(), sat: maxIntOr(x.sat, maxIntAdd(x.dsat, y.sat)) };
    }
    case "OR_D": {
      const x = childWitness(node.subs[0]);
      const y = childWitness(node.subs[1]);
      return {
        dsat: maxIntAdd(x.dsat, y.dsat),
        sat: maxIntOr(x.sat, maxIntAdd(x.dsat, y.sat)),
      };
    }
    case "OR_I": {
      const x = childWitness(node.subs[0]);
      const y = childWitness(node.subs[1]);
      return {
        dsat: maxIntOr(maxIntAddValue(x.dsat, 2), maxIntAddValue(y.dsat, 1)),
        sat: maxIntOr(maxIntAddValue(x.sat, 2), maxIntAddValue(y.sat, 1)),
      };
    }
    case "MULTI":
      return { dsat: maxInt(node.k + 1), sat: maxInt(node.k * sigSize + 1) };
    case "MULTI_A":
      return {
        dsat: maxInt(node.keys.length),
        sat: maxInt(node.k * sigSize + node.keys.length - node.k),
      };
    case "WRAP_A":
    case "WRAP_N":
    case "WRAP_S":
    case "WRAP_C":
      return childWitness(node.sub);
    case "WRAP_D": {
      const x = childWitness(node.sub);
      return { dsat: maxInt(1), sat: maxIntAddValue(x.sat, 2) };
    }
    case "WRAP_V": {
      const x = childWitness(node.sub);
      return { dsat: maxInt(), sat: x.sat };
    }
    case "WRAP_J": {
      const x = childWitness(node.sub);
      return { dsat: maxInt(1), sat: x.sat };
    }
    case "THRESH": {
      let sats = [maxInt(0)];
      for (const sub of node.subs) {
        const subWitness = childWitness(sub);
        const nextSats = [maxIntAdd(sats[0], subWitness.dsat)];
        for (let index = 1; index < sats.length; index++) {
          nextSats.push(
            maxIntOr(
              maxIntAdd(sats[index], subWitness.dsat),
              maxIntAdd(sats[index - 1], subWitness.sat),
            ),
          );
        }
        nextSats.push(maxIntAdd(sats[sats.length - 1], subWitness.sat));
        sats = nextSats;
      }
      return { dsat: sats[0], sat: sats[node.k] };
    }
  }
}

function computeMiniscriptResourceStats(
  node: MiniscriptFragment,
  addressType: AddressType,
  includeWitnessSize = false,
): MiniscriptResourceStats {
  return {
    ops: computeMiniscriptOps(node, addressType),
    stackSize: computeMiniscriptStackSize(node, addressType),
    witnessSize: includeWitnessSize
      ? computeMiniscriptWitnessSize(node, addressType)
      : { dsat: maxInt(), sat: maxInt() },
  };
}

function isBkwType(type: MiniscriptTypeInfo): boolean {
  return typeHasAll(type, "B") || typeHasAll(type, "K") || typeHasAll(type, "W");
}

function getMiniscriptOps(stats: MiniscriptResourceStats): number | undefined {
  return stats.ops.sat.valid ? stats.ops.count + stats.ops.sat.value : undefined;
}

function getMiniscriptStackSize(
  type: MiniscriptTypeInfo,
  stats: MiniscriptResourceStats,
): number | undefined {
  return stats.stackSize.sat.valid
    ? stats.stackSize.sat.netdiff + (isBkwType(type) ? 1 : 0)
    : undefined;
}

function getMiniscriptExecStackSize(
  type: MiniscriptTypeInfo,
  stats: MiniscriptResourceStats,
): number | undefined {
  return stats.stackSize.sat.valid
    ? stats.stackSize.sat.exec + (isBkwType(type) ? 1 : 0)
    : undefined;
}

function checkMiniscriptOpsLimit(
  stats: MiniscriptResourceStats,
  addressType: AddressType,
): boolean {
  if (addressType === "TAPROOT") return true;
  const ops = getMiniscriptOps(stats);
  return ops == null || ops <= MAX_OPS_PER_SCRIPT;
}

function checkMiniscriptStackSize(
  type: MiniscriptTypeInfo,
  stats: MiniscriptResourceStats,
  addressType: AddressType,
): boolean {
  if (addressType === "TAPROOT") {
    const execStackSize = getMiniscriptExecStackSize(type, stats);
    return execStackSize == null || execStackSize <= MAX_STACK_SIZE;
  }
  const stackSize = getMiniscriptStackSize(type, stats);
  return stackSize == null || stackSize <= MAX_STANDARD_P2WSH_STACK_ITEMS;
}

function collectDuplicateCheckedKeys(node: MiniscriptFragment, keys = new Set<string>()): boolean {
  const addKey = (key: string): boolean => {
    if (keys.has(key)) return false;
    keys.add(key);
    return true;
  };

  switch (node.fragment) {
    case "PK":
    case "PKH":
    case "PK_H":
    case "PK_K":
      return addKey(node.key);
    case "MULTI":
    case "MULTI_A":
      return node.keys.every(addKey);
    case "WRAP_A":
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_D":
    case "WRAP_V":
    case "WRAP_J":
    case "WRAP_N":
      return collectDuplicateCheckedKeys(node.sub, keys);
    case "AND_V":
    case "AND_B":
    case "OR_B":
    case "OR_C":
    case "OR_D":
    case "OR_I":
      return (
        collectDuplicateCheckedKeys(node.subs[0], keys) &&
        collectDuplicateCheckedKeys(node.subs[1], keys)
      );
    case "ANDOR":
      return (
        collectDuplicateCheckedKeys(node.subs[0], keys) &&
        collectDuplicateCheckedKeys(node.subs[1], keys) &&
        collectDuplicateCheckedKeys(node.subs[2], keys)
      );
    case "THRESH":
      return node.subs.every((sub) => collectDuplicateCheckedKeys(sub, keys));
    case "JUST_0":
    case "JUST_1":
    case "OLDER":
    case "AFTER":
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
    case "SHA256":
      return true;
  }
}

function validateMiniscriptTimelineNode(node: MiniscriptFragment): void {
  let lockType: TimelockBased = "NONE";
  const detectTimelock = (timelock: Timelock, k: number): void => {
    if (timelockK(timelock) !== k) {
      invalid(timelock.based === "TIME_LOCK" ? "Invalid time value" : "Invalid height value");
    }
    if (timelock.based === "NONE") {
      return;
    }
    if (lockType === "NONE") {
      lockType = timelock.based;
    } else if (lockType !== timelock.based) {
      invalid("Timelock mixing");
    }
  };
  const visit = (current: MiniscriptFragment): void => {
    switch (current.fragment) {
      case "AFTER":
        detectTimelock(timelockFromK(true, current.k), current.k);
        return;
      case "OLDER":
        detectTimelock(timelockFromK(false, current.k), current.k);
        return;
      case "WRAP_A":
      case "WRAP_S":
      case "WRAP_C":
      case "WRAP_D":
      case "WRAP_V":
      case "WRAP_J":
      case "WRAP_N":
        visit(current.sub);
        return;
      case "AND_V":
      case "AND_B":
      case "OR_B":
      case "OR_C":
      case "OR_D":
      case "OR_I":
        visit(current.subs[0]);
        visit(current.subs[1]);
        return;
      case "ANDOR":
        visit(current.subs[0]);
        visit(current.subs[1]);
        visit(current.subs[2]);
        return;
      case "THRESH":
        current.subs.forEach(visit);
        return;
      case "JUST_0":
      case "JUST_1":
      case "PK":
      case "PKH":
      case "PK_H":
      case "PK_K":
      case "MULTI":
      case "MULTI_A":
      case "HASH160":
      case "HASH256":
      case "RIPEMD160":
      case "SHA256":
        return;
    }
  };
  visit(node);
}

function validateMiniscriptNode(node: MiniscriptFragment, addressType: AddressType): void {
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
      if (addressType === "TAPROOT") {
        invalid("multi() is not valid for taproot miniscript");
      }
      break;
    case "MULTI_A":
      if (addressType !== "TAPROOT") {
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
  wrapped = false,
): string {
  const prefix = wrapped ? ":" : "";
  const keyExpression = (key: string): string =>
    maybeAppendChildPath(signers[key] ?? key, childPath);
  const wrappedSub = (sub: MiniscriptFragment): string =>
    substituteMiniscriptKeys(sub, signers, childPath, true);
  const normalSub = (sub: MiniscriptFragment): string =>
    substituteMiniscriptKeys(sub, signers, childPath);

  switch (node.fragment) {
    case "JUST_0":
      return `${prefix}0`;
    case "JUST_1":
      return `${prefix}1`;
    case "PK":
      return `${prefix}pk(${keyExpression(node.key)})`;
    case "PKH":
      return `${prefix}pkh(${keyExpression(node.key)})`;
    case "PK_H":
      return `${prefix}pk_h(${keyExpression(node.key)})`;
    case "PK_K":
      return `${prefix}pk_k(${keyExpression(node.key)})`;
    case "OLDER":
      return `${prefix}older(${node.k})`;
    case "AFTER":
      return `${prefix}after(${node.k})`;
    case "HASH160":
      return `${prefix}hash160(${node.data})`;
    case "HASH256":
      return `${prefix}hash256(${node.data})`;
    case "RIPEMD160":
      return `${prefix}ripemd160(${node.data})`;
    case "SHA256":
      return `${prefix}sha256(${node.data})`;
    case "MULTI":
      return `${prefix}multi(${node.k},${node.keys.map(keyExpression).join(",")})`;
    case "MULTI_A":
      return `${prefix}multi_a(${node.k},${node.keys.map(keyExpression).join(",")})`;
    case "WRAP_A":
      return `a${wrappedSub(node.sub)}`;
    case "WRAP_S":
      return `s${wrappedSub(node.sub)}`;
    case "WRAP_C": {
      if (node.sub.fragment === "PK_K") {
        return `${prefix}pk(${keyExpression(node.sub.key)})`;
      }
      if (node.sub.fragment === "PK_H") {
        return `${prefix}pkh(${keyExpression(node.sub.key)})`;
      }
      return `c${wrappedSub(node.sub)}`;
    }
    case "WRAP_D":
      return `d${wrappedSub(node.sub)}`;
    case "WRAP_V":
      return `v${wrappedSub(node.sub)}`;
    case "WRAP_J":
      return `j${wrappedSub(node.sub)}`;
    case "WRAP_N":
      return `n${wrappedSub(node.sub)}`;
    case "AND_V":
      if (node.subs[1].fragment === "JUST_1") {
        return `t${wrappedSub(node.subs[0])}`;
      }
      return `${prefix}and_v(${normalSub(node.subs[0])},${normalSub(node.subs[1])})`;
    case "AND_B":
      return `${prefix}and_b(${normalSub(node.subs[0])},${normalSub(node.subs[1])})`;
    case "OR_B":
      return `${prefix}or_b(${normalSub(node.subs[0])},${normalSub(node.subs[1])})`;
    case "OR_C":
      return `${prefix}or_c(${normalSub(node.subs[0])},${normalSub(node.subs[1])})`;
    case "OR_D":
      return `${prefix}or_d(${normalSub(node.subs[0])},${normalSub(node.subs[1])})`;
    case "OR_I":
      if (node.subs[0].fragment === "JUST_0") {
        return `l${wrappedSub(node.subs[1])}`;
      }
      if (node.subs[1].fragment === "JUST_0") {
        return `u${wrappedSub(node.subs[0])}`;
      }
      return `${prefix}or_i(${normalSub(node.subs[0])},${normalSub(node.subs[1])})`;
    case "ANDOR":
      if (node.subs[2].fragment === "JUST_0") {
        return `${prefix}and_n(${normalSub(node.subs[0])},${normalSub(node.subs[1])})`;
      }
      return `${prefix}andor(${normalSub(node.subs[0])},${normalSub(node.subs[1])},${normalSub(node.subs[2])})`;
    case "THRESH":
      return `${prefix}thresh(${node.k},${node.subs.map(normalSub).join(",")})`;
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
  if (!isValidMiniscriptTemplate(leaf, "TAPROOT")) {
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

function resolveConfiguredValue(value: string, config: Record<string, string>): string {
  return config[value] ?? value;
}

type CompiledPolicyNode =
  | { type: "PK"; key: string }
  | { type: "OLDER" | "AFTER"; k: number }
  | { type: HashFragment; data: string }
  | { type: "AND"; subs: CompiledPolicyNode[] }
  | { type: "OR"; probs: number[]; subs: CompiledPolicyNode[] }
  | { type: "THRESH"; k: number; subs: CompiledPolicyNode[] };

type PolicyCompilerStratType =
  | "JUST_0"
  | "JUST_1"
  | "PK_K"
  | "MULTI"
  | "OLDER"
  | "AFTER"
  | HashFragment
  | "AND"
  | "OR"
  | "ANDOR"
  | "THRESH"
  | "WRAP_AS"
  | "WRAP_C"
  | "WRAP_D"
  | "WRAP_V"
  | "WRAP_J"
  | "WRAP_N"
  | "ALTERNATIVES"
  | "CACHE";

interface PolicyCompilerStrat {
  data?: string;
  id: number;
  k: number;
  keys: string[];
  prob: number;
  subs: PolicyCompilerStrat[];
  type: PolicyCompilerStratType;
}

interface PolicyCompilerState {
  nextId: number;
  stratFalse: PolicyCompilerStrat;
  stratTrue: PolicyCompilerStrat;
}

interface CostPair {
  nsat: number;
  sat: number;
}

interface CompileResult {
  cost: number;
  node: MiniscriptFragment;
  pair: CostPair;
  scriptSize: number;
  type: MiniscriptTypeInfo;
}

interface Compilation {
  p: number;
  q: number;
  results: CompileResult[];
  seq: number;
}

interface CompilerFilter {
  care: string;
  required: string;
}

function parsePolicyPositiveInt(value: string, field: string): number {
  const parsed = parseUInt(value, field);
  if (parsed < 1 || parsed >= 0x80000000) {
    invalid(`Invalid ${field}: ${value}`);
  }
  return parsed;
}

function configurePolicyNode(node: PolicyNode, config: Record<string, string>): CompiledPolicyNode {
  switch (node.type) {
    case "PK":
      return { type: "PK", key: resolveConfiguredValue(node.key, config) };
    case "OLDER": {
      const resolved = resolveConfiguredValue(node.value, config);
      return { type: "OLDER", k: parsePolicyPositiveInt(resolved, "older value") };
    }
    case "AFTER": {
      const resolved = resolveConfiguredValue(node.value, config);
      return { type: "AFTER", k: parsePolicyPositiveInt(resolved, "after value") };
    }
    case "HASH160":
      return {
        type: "HASH160",
        data: parseHashArg(resolveConfiguredValue(node.data, config), 20, "hash160"),
      };
    case "HASH256":
      return {
        type: "HASH256",
        data: parseHashArg(resolveConfiguredValue(node.data, config), 32, "hash256"),
      };
    case "RIPEMD160":
      return {
        type: "RIPEMD160",
        data: parseHashArg(resolveConfiguredValue(node.data, config), 20, "ripemd160"),
      };
    case "SHA256":
      return {
        type: "SHA256",
        data: parseHashArg(resolveConfiguredValue(node.data, config), 32, "sha256"),
      };
    case "AND":
      return { type: "AND", subs: node.subs.map((sub) => configurePolicyNode(sub, config)) };
    case "OR":
      return {
        type: "OR",
        probs: node.probs ?? node.subs.map(() => 1),
        subs: node.subs.map((sub) => configurePolicyNode(sub, config)),
      };
    case "THRESH": {
      if (node.k < 1 || node.k > node.subs.length) {
        invalid("Invalid thresh() threshold");
      }
      return {
        type: "THRESH",
        k: node.k,
        subs: node.subs.map((sub) => configurePolicyNode(sub, config)),
      };
    }
  }
}

function makePolicyCompilerStrat(
  state: PolicyCompilerState,
  type: PolicyCompilerStratType,
  subs: PolicyCompilerStrat[] = [],
  options: { data?: string; k?: number; keys?: string[]; prob?: number } = {},
): PolicyCompilerStrat {
  return {
    data: options.data,
    id: state.nextId++,
    k: options.k ?? 0,
    keys: options.keys ?? [],
    prob: options.prob ?? 0,
    subs,
    type,
  };
}

function createPolicyCompilerState(): PolicyCompilerState {
  const state = { nextId: 0 } as PolicyCompilerState;
  state.stratFalse = makePolicyCompilerStrat(state, "CACHE", [
    makePolicyCompilerStrat(state, "JUST_0"),
  ]);
  state.stratTrue = makePolicyCompilerStrat(state, "CACHE", [
    makePolicyCompilerStrat(state, "JUST_1"),
  ]);
  return state;
}

function computePolicyStrategy(
  node: CompiledPolicyNode,
  cache: Map<CompiledPolicyNode, PolicyCompilerStrat>,
  state: PolicyCompilerState,
): PolicyCompilerStrat | null {
  const cached = cache.get(node);
  if (cached) {
    return cached;
  }

  const strats: PolicyCompilerStrat[] = [];
  switch (node.type) {
    case "PK":
      strats.push(makePolicyCompilerStrat(state, "PK_K", [], { keys: [node.key] }));
      break;
    case "OLDER":
      strats.push(makePolicyCompilerStrat(state, "OLDER", [], { k: node.k }));
      break;
    case "AFTER":
      strats.push(makePolicyCompilerStrat(state, "AFTER", [], { k: node.k }));
      break;
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
    case "SHA256":
      strats.push(makePolicyCompilerStrat(state, node.type, [], { data: node.data }));
      break;
    case "AND": {
      if (node.subs.length !== 2) {
        return null;
      }
      const left = computePolicyStrategy(node.subs[0], cache, state);
      const right = computePolicyStrategy(node.subs[1], cache, state);
      if (!left || !right) {
        return null;
      }
      strats.push(makePolicyCompilerStrat(state, "AND", [left, right]));
      strats.push(
        makePolicyCompilerStrat(state, "ANDOR", [left, right, state.stratFalse], { prob: 1 }),
      );
      break;
    }
    case "OR": {
      if (node.subs.length !== 2 || node.probs.length !== 2) {
        return null;
      }
      const [leftProb, rightProb] = node.probs;
      const totalProb = leftProb + rightProb;
      if (
        !Number.isSafeInteger(leftProb) ||
        !Number.isSafeInteger(rightProb) ||
        leftProb < 1 ||
        rightProb < 1 ||
        !Number.isSafeInteger(totalProb)
      ) {
        return null;
      }
      const prob = leftProb / totalProb;
      const left = computePolicyStrategy(node.subs[0], cache, state);
      const right = computePolicyStrategy(node.subs[1], cache, state);
      if (!left || !right) {
        return null;
      }
      if (node.subs[0].type === "AND" && node.subs[0].subs.length === 2) {
        const leftLeft = computePolicyStrategy(node.subs[0].subs[0], cache, state);
        const leftRight = computePolicyStrategy(node.subs[0].subs[1], cache, state);
        if (!leftLeft || !leftRight) {
          return null;
        }
        strats.push(
          makePolicyCompilerStrat(state, "ANDOR", [leftLeft, leftRight, right], { prob }),
        );
      }
      if (node.subs[1].type === "AND" && node.subs[1].subs.length === 2) {
        const rightLeft = computePolicyStrategy(node.subs[1].subs[0], cache, state);
        const rightRight = computePolicyStrategy(node.subs[1].subs[1], cache, state);
        if (!rightLeft || !rightRight) {
          return null;
        }
        strats.push(
          makePolicyCompilerStrat(state, "ANDOR", [rightLeft, rightRight, left], {
            prob: 1 - prob,
          }),
        );
      }
      strats.push(
        makePolicyCompilerStrat(state, "ANDOR", [left, state.stratTrue, right], { prob }),
      );
      strats.push(makePolicyCompilerStrat(state, "OR", [left, right], { prob }));
      break;
    }
    case "THRESH": {
      if (node.k < 1 || node.k > node.subs.length || node.subs.length > 100) {
        return null;
      }
      const subs = node.subs.map((sub) => computePolicyStrategy(sub, cache, state));
      if (subs.some((sub) => sub == null)) {
        return null;
      }
      const strategies = subs as PolicyCompilerStrat[];
      if (
        node.subs.length <= MAX_PUBKEYS_PER_MULTISIG &&
        node.subs.every((sub) => sub.type === "PK")
      ) {
        strats.push(
          makePolicyCompilerStrat(state, "MULTI", [], {
            k: node.k,
            keys: node.subs.map((sub) => (sub as Extract<CompiledPolicyNode, { type: "PK" }>).key),
          }),
        );
      }
      if (node.k === 1 || node.k === node.subs.length) {
        const grouped = [...strategies];
        while (grouped.length > 1) {
          const prob = 1 / grouped.length;
          const right = grouped.pop()!;
          const left = grouped.pop()!;
          const rep = makePolicyCompilerStrat(state, node.k === 1 ? "OR" : "AND", [left, right], {
            prob,
          });
          grouped.push(makePolicyCompilerStrat(state, "CACHE", [rep]));
        }
        strats.push(grouped[0]);
      }
      strats.push(
        makePolicyCompilerStrat(state, "THRESH", strategies, {
          k: node.k,
          prob: node.k / strategies.length,
        }),
      );
      break;
    }
  }

  const initial =
    strats.length === 1 ? strats : [makePolicyCompilerStrat(state, "ALTERNATIVES", strats)];
  const result = makePolicyCompilerStrat(state, "CACHE", initial);
  cache.set(node, result);
  result.subs.push(makePolicyCompilerStrat(state, "WRAP_C", [result]));
  result.subs.push(makePolicyCompilerStrat(state, "WRAP_V", [result]));
  result.subs.push(makePolicyCompilerStrat(state, "AND", [result, state.stratTrue]));
  result.subs.push(makePolicyCompilerStrat(state, "WRAP_N", [result]));
  result.subs.push(makePolicyCompilerStrat(state, "WRAP_D", [result]));
  result.subs.push(makePolicyCompilerStrat(state, "WRAP_J", [result]));
  result.subs.push(makePolicyCompilerStrat(state, "OR", [result, state.stratFalse], { prob: 1 }));
  result.subs.push(makePolicyCompilerStrat(state, "WRAP_AS", [result]));
  return result;
}

function multiplyCompilerCost(coef: number, value: number): number {
  return coef === 0 ? 0 : coef * value;
}

function calcCompilerCostPair(
  fragment: MiniscriptFragment["fragment"],
  results: CompileResult[],
  prob: number,
): CostPair {
  const rightProb = 1 - prob;
  switch (fragment) {
    case "PK_K":
      return { sat: 73, nsat: 1 };
    case "PK_H":
      return { sat: 107, nsat: 35 };
    case "OLDER":
    case "AFTER":
      return { sat: 0, nsat: Number.POSITIVE_INFINITY };
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
    case "SHA256":
      return { sat: 33, nsat: 33 };
    case "WRAP_A":
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_N":
      return results[0].pair;
    case "WRAP_D":
      return { sat: 2 + results[0].pair.sat, nsat: 1 };
    case "WRAP_V":
      return { sat: results[0].pair.sat, nsat: Number.POSITIVE_INFINITY };
    case "WRAP_J":
      return { sat: results[0].pair.sat, nsat: 1 };
    case "JUST_1":
      return { sat: 0, nsat: Number.POSITIVE_INFINITY };
    case "JUST_0":
      return { sat: Number.POSITIVE_INFINITY, nsat: 0 };
    case "AND_V":
      return { sat: results[0].pair.sat + results[1].pair.sat, nsat: Number.POSITIVE_INFINITY };
    case "AND_B":
      return {
        sat: results[0].pair.sat + results[1].pair.sat,
        nsat: results[0].pair.nsat + results[1].pair.nsat,
      };
    case "OR_B":
      return {
        sat:
          multiplyCompilerCost(prob, results[0].pair.sat + results[1].pair.nsat) +
          multiplyCompilerCost(rightProb, results[0].pair.nsat + results[1].pair.sat),
        nsat: results[0].pair.nsat + results[1].pair.nsat,
      };
    case "OR_C":
    case "OR_D":
      return {
        sat:
          multiplyCompilerCost(prob, results[0].pair.sat) +
          multiplyCompilerCost(rightProb, results[0].pair.nsat + results[1].pair.sat),
        nsat: results[0].pair.nsat + results[1].pair.nsat,
      };
    case "OR_I":
      return {
        sat:
          multiplyCompilerCost(prob, results[0].pair.sat + 2) +
          multiplyCompilerCost(rightProb, results[1].pair.sat + 1),
        nsat: Math.min(2 + results[0].pair.nsat, 1 + results[1].pair.nsat),
      };
    case "ANDOR":
      return {
        sat:
          multiplyCompilerCost(prob, results[0].pair.sat + results[1].pair.sat) +
          multiplyCompilerCost(rightProb, results[0].pair.nsat + results[2].pair.sat),
        nsat: results[0].pair.nsat + results[2].pair.nsat,
      };
    case "MULTI":
      return { sat: 1 + prob * 73, nsat: 1 + prob };
    case "THRESH": {
      let sat = 0;
      let nsat = 0;
      for (const result of results) {
        sat += result.pair.sat;
        nsat += result.pair.nsat;
      }
      return {
        sat: multiplyCompilerCost(prob, sat) + multiplyCompilerCost(rightProb, nsat),
        nsat,
      };
    }
    case "PK":
    case "PKH":
    case "MULTI_A":
      invalid(`Unsupported policy compiler fragment: ${fragment}`);
  }
}

function getCompilerPqs(
  fragment: MiniscriptFragment["fragment"],
  p: number,
  q: number,
  prob: number,
  subCount: number,
): { ps: number[]; qs: number[] } {
  const rightProb = 1 - prob;
  switch (fragment) {
    case "JUST_1":
    case "JUST_0":
    case "PK_K":
    case "PK_H":
    case "MULTI":
    case "OLDER":
    case "AFTER":
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
    case "SHA256":
      return { ps: [], qs: [] };
    case "WRAP_A":
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_N":
      return { ps: [p], qs: [q] };
    case "WRAP_D":
    case "WRAP_V":
    case "WRAP_J":
      return { ps: [p], qs: [0] };
    case "AND_V":
    case "AND_B":
      return { ps: [p, p], qs: [q, q] };
    case "OR_B":
      return { ps: [prob * p, rightProb * p], qs: [rightProb * p + q, prob * p + q] };
    case "OR_D":
      return { ps: [prob * p, rightProb * p], qs: [rightProb * p + q, q] };
    case "OR_C":
      return { ps: [prob * p, rightProb * p], qs: [rightProb * p, 0] };
    case "OR_I":
      return {
        ps: [prob * p, rightProb * p],
        qs: [subCount === 0 ? q : 0, subCount === 1 ? q : 0],
      };
    case "ANDOR":
      return { ps: [prob * p, prob * p, rightProb * p], qs: [q + rightProb * p, 0, q] };
    case "THRESH":
      return {
        ps: Array.from({ length: subCount }, () => p * prob),
        qs: Array.from({ length: subCount }, () => q + p * rightProb),
      };
    case "PK":
    case "PKH":
    case "MULTI_A":
      invalid(`Unsupported policy compiler fragment: ${fragment}`);
  }
}

function parseCompilerFilter(filter: string): CompilerFilter {
  const [required, care = ""] = filter.split("/", 2);
  return { required, care };
}

function getCompilerTypeFilters(fragment: MiniscriptFragment["fragment"]): CompilerFilter[][] {
  const filters = (values: string[][]): CompilerFilter[][] =>
    values.map((row) => row.map(parseCompilerFilter));
  switch (fragment) {
    case "JUST_1":
    case "JUST_0":
    case "PK_K":
    case "PK_H":
    case "MULTI":
    case "OLDER":
    case "AFTER":
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
    case "SHA256":
      return [[]];
    case "WRAP_A":
      return filters([["B/udfems"]]);
    case "WRAP_S":
      return filters([["Bo/udfemsx"]]);
    case "WRAP_C":
      return filters([["K/onde"]]);
    case "WRAP_D":
      return filters([["V/zfms"]]);
    case "WRAP_V":
      return filters([["B/zonmsx"]]);
    case "WRAP_J":
      return filters([["Bn/oufms"]]);
    case "WRAP_N":
      return filters([["B/zondfems"]]);
    case "AND_V":
      return filters([
        ["V/nzoms", "B/unzofmsx"],
        ["V/nsoms", "K/unzofmsx"],
        ["V/nzoms", "V/unzofmsx"],
      ]);
    case "AND_B":
      return filters([["B/zondfems", "W/zondfems"]]);
    case "OR_B":
      return filters([["Bde/zoms", "Wde/zoms"]]);
    case "OR_D":
      return filters([["Bdue/zoms", "B/zoudfems"]]);
    case "OR_C":
      return filters([["Bdue/zoms", "V/zoms"]]);
    case "OR_I":
      return filters([
        ["V/zudfems", "V/zudfems"],
        ["B/zudfems", "B/zudfems"],
        ["K/zudfems", "K/zudfems"],
      ]);
    case "ANDOR":
      return filters([
        ["Bdue/zoms", "B/zoufms", "B/zoudfems"],
        ["Bdue/zoms", "K/zoufms", "K/zoudfems"],
        ["Bdue/zoms", "V/zoufms", "V/zoudfems"],
      ]);
    case "THRESH":
    case "PK":
    case "PKH":
    case "MULTI_A":
      invalid(`Unsupported policy compiler type filter: ${fragment}`);
  }
}

function makeCompilerMiniscriptNode(
  fragment: MiniscriptFragment["fragment"],
  subs: MiniscriptFragment[],
  options: { data?: string; k?: number; keys?: string[] } = {},
): MiniscriptFragment {
  switch (fragment) {
    case "JUST_0":
    case "JUST_1":
      return { fragment };
    case "PK_K":
    case "PK_H":
      return { fragment, key: options.keys?.[0] ?? invalid(`Missing key for ${fragment}`) };
    case "OLDER":
    case "AFTER":
      return { fragment, k: options.k ?? invalid(`Missing k for ${fragment}`) };
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
    case "SHA256":
      return { fragment, data: options.data ?? invalid(`Missing hash data for ${fragment}`) };
    case "MULTI":
      return {
        fragment,
        k: options.k ?? invalid("Missing multi threshold"),
        keys: options.keys ?? invalid("Missing multi keys"),
      };
    case "WRAP_A":
    case "WRAP_S":
    case "WRAP_C":
    case "WRAP_D":
    case "WRAP_V":
    case "WRAP_J":
    case "WRAP_N":
      return { fragment, sub: subs[0] ?? invalid(`Missing subexpression for ${fragment}`) };
    case "AND_V":
    case "AND_B":
    case "OR_B":
    case "OR_C":
    case "OR_D":
    case "OR_I":
      if (subs.length !== 2) invalid(`Invalid ${fragment} subexpression count`);
      return { fragment, subs: [subs[0], subs[1]] };
    case "ANDOR":
      if (subs.length !== 3) invalid("Invalid andor subexpression count");
      return { fragment, subs: [subs[0], subs[1], subs[2]] };
    case "THRESH":
      return {
        fragment,
        k: options.k ?? invalid("Missing thresh threshold"),
        subs,
      };
    case "PK":
    case "PKH":
    case "MULTI_A":
      invalid(`Unsupported policy compiler node: ${fragment}`);
  }
}

function analyzeCompiledNode(node: MiniscriptFragment): {
  scriptSize: number;
  stats: MiniscriptResourceStats;
  type: MiniscriptTypeInfo;
} | null {
  try {
    const addressType = "NATIVE_SEGWIT";
    const type = computeMiniscriptType(node, addressType);
    const scriptSize = computeMiniscriptScriptSize(node, addressType);
    const stats = computeMiniscriptResourceStats(node, addressType);
    return { scriptSize, stats, type };
  } catch {
    return null;
  }
}

function isValidCompiledSatisfaction(
  type: MiniscriptTypeInfo,
  scriptSize: number,
  stats: MiniscriptResourceStats,
): boolean {
  return (
    type.flags !== 0 &&
    scriptSize <= maxScriptSize("NATIVE_SEGWIT") &&
    checkMiniscriptOpsLimit(stats, "NATIVE_SEGWIT") &&
    checkMiniscriptStackSize(type, stats, "NATIVE_SEGWIT")
  );
}

function typeIsSubtype(left: MiniscriptTypeInfo, right: MiniscriptTypeInfo): boolean {
  return (right.flags & ~left.flags) === 0;
}

function compareCompileResultTo(
  result: CompileResult,
  otherCost: number,
  otherScriptSize: number,
): number {
  if (result.cost < otherCost) return -1;
  if (result.cost > otherCost) return 1;
  if (result.scriptSize > otherScriptSize) return -1;
  if (result.scriptSize < otherScriptSize) return 1;
  return 0;
}

function addCompilationResult(
  compilation: Compilation,
  pair: CostPair,
  node: MiniscriptFragment,
): void {
  const analysis = analyzeCompiledNode(node);
  if (!analysis) return;
  if (
    !(
      isValidCompiledSatisfaction(analysis.type, analysis.scriptSize, analysis.stats) &&
      analysis.type.m &&
      analysis.type.k
    )
  ) {
    return;
  }

  const cost =
    analysis.scriptSize +
    multiplyCompilerCost(compilation.p, pair.sat) +
    multiplyCompilerCost(compilation.q, pair.nsat);
  if (cost > 10000) {
    return;
  }

  for (const result of compilation.results) {
    if (
      typeIsSubtype(result.type, analysis.type) &&
      compareCompileResultTo(result, cost, analysis.scriptSize) <= 0
    ) {
      return;
    }
  }

  compilation.results = compilation.results.filter(
    (result) =>
      !(
        typeIsSubtype(analysis.type, result.type) &&
        compareCompileResultTo(result, cost, analysis.scriptSize) >= 0
      ),
  );
  compilation.results.push({
    cost,
    node,
    pair,
    scriptSize: analysis.scriptSize,
    type: analysis.type,
  });
  compilation.seq++;
}

function addCompilerInner(
  compilation: Compilation,
  fragment: MiniscriptFragment["fragment"],
  results: CompileResult[],
  prob: number,
  options: { data?: string; k?: number; keys?: string[] } = {},
): void {
  const node = makeCompilerMiniscriptNode(
    fragment,
    results.map((result) => result.node),
    options,
  );
  addCompilationResult(compilation, calcCompilerCostPair(fragment, results, prob), node);
}

function queryCompilation(compilation: Compilation, filter: CompilerFilter): CompileResult[] {
  const requiredBits = typeBits(filter.required);
  const careBits = typeBits(filter.care);
  const byMask = new Map<number, CompileResult>();
  for (const result of compilation.results) {
    if ((result.type.flags & requiredBits) !== requiredBits) {
      continue;
    }
    const masked = result.type.flags & careBits;
    const existing = byMask.get(masked);
    if (!existing || compareCompileResultTo(result, existing.cost, existing.scriptSize) < 0) {
      byMask.set(masked, result);
    }
  }
  return [...byMask.values()];
}

function addCompilerStrategyResults(
  compilation: Compilation,
  fragment: MiniscriptFragment["fragment"],
  subStrategies: PolicyCompilerStrat[],
  prob: number,
  mode: number,
  cache: Map<string, Compilation>,
  options: { data?: string; k?: number; keys?: string[] } = {},
): void {
  const pqs = getCompilerPqs(fragment, compilation.p, compilation.q, prob, mode);
  const filters = getCompilerTypeFilters(fragment);

  for (const row of filters) {
    const resultLists: CompileResult[][] = [];
    let missing = false;
    for (let i = 0; i < row.length; i++) {
      const subCompilation = getPolicyCompilation(subStrategies[i], pqs.ps[i], pqs.qs[i], cache);
      const results = queryCompilation(subCompilation, row[i]);
      if (results.length === 0) {
        missing = true;
        break;
      }
      resultLists.push(results);
    }
    if (missing) {
      continue;
    }

    const visit = (index: number, selected: CompileResult[]): void => {
      if (index === resultLists.length) {
        addCompilerInner(compilation, fragment, selected, prob, options);
        return;
      }
      for (const result of resultLists[index]) {
        visit(index + 1, [...selected, result]);
      }
    };
    visit(0, []);
  }
}

function getPolicyCompilation(
  strat: PolicyCompilerStrat,
  p: number,
  q: number,
  cache: Map<string, Compilation>,
): Compilation {
  if (strat.type !== "CACHE") {
    invalid("Policy compiler cache root expected");
  }
  const cacheKey = `${strat.id}:${p}:${q}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const compilation: Compilation = { p, q, results: [], seq: 0 };
  compilePolicyStrategy(strat.subs[0], compilation, cache);
  cache.set(cacheKey, compilation);

  if (strat.subs.length > 1) {
    let last = 1;
    let pos = 1;
    do {
      const previousSeq = compilation.seq;
      compilePolicyStrategy(strat.subs[pos], compilation, cache);
      if (compilation.seq !== previousSeq) {
        last = pos;
      }
      pos++;
      if (pos === strat.subs.length) {
        pos = 1;
      }
    } while (pos !== last);
  }

  return compilation;
}

function compilePolicyStrategy(
  strat: PolicyCompilerStrat,
  compilation: Compilation,
  cache: Map<string, Compilation>,
): void {
  switch (strat.type) {
    case "ALTERNATIVES":
      for (const sub of strat.subs) compilePolicyStrategy(sub, compilation, cache);
      return;
    case "CACHE": {
      const subCompilation = getPolicyCompilation(strat, compilation.p, compilation.q, cache);
      for (const result of subCompilation.results) {
        addCompilationResult(compilation, result.pair, result.node);
      }
      return;
    }
    case "JUST_0":
      addCompilerStrategyResults(compilation, "JUST_0", strat.subs, 0, 0, cache);
      return;
    case "JUST_1":
      addCompilerStrategyResults(compilation, "JUST_1", strat.subs, 0, 0, cache);
      return;
    case "AFTER":
    case "OLDER":
      addCompilerStrategyResults(compilation, strat.type, strat.subs, 0, 0, cache, { k: strat.k });
      return;
    case "HASH160":
    case "HASH256":
    case "RIPEMD160":
    case "SHA256":
      addCompilerStrategyResults(compilation, strat.type, strat.subs, 0, 0, cache, {
        data: strat.data,
      });
      return;
    case "PK_K":
      addCompilerStrategyResults(compilation, "PK_K", strat.subs, 0, 0, cache, {
        keys: strat.keys,
      });
      addCompilerStrategyResults(compilation, "PK_H", strat.subs, 0, 0, cache, {
        keys: strat.keys,
      });
      return;
    case "MULTI":
      addCompilerStrategyResults(compilation, "MULTI", strat.subs, strat.k, 0, cache, {
        k: strat.k,
        keys: strat.keys,
      });
      return;
    case "WRAP_AS":
      addCompilerStrategyResults(compilation, "WRAP_A", strat.subs, 0, 0, cache);
      addCompilerStrategyResults(compilation, "WRAP_S", strat.subs, 0, 0, cache);
      return;
    case "WRAP_C":
      addCompilerStrategyResults(compilation, "WRAP_C", strat.subs, 0, 0, cache);
      return;
    case "WRAP_D":
      addCompilerStrategyResults(compilation, "WRAP_D", strat.subs, 0, 0, cache);
      return;
    case "WRAP_N":
      addCompilerStrategyResults(compilation, "WRAP_N", strat.subs, 0, 0, cache);
      return;
    case "WRAP_J":
      addCompilerStrategyResults(compilation, "WRAP_J", strat.subs, 0, 0, cache);
      return;
    case "WRAP_V":
      addCompilerStrategyResults(compilation, "WRAP_V", strat.subs, 0, 0, cache);
      return;
    case "AND": {
      const rev = [strat.subs[1], strat.subs[0]];
      if (compilation.q === 0) {
        addCompilerStrategyResults(compilation, "AND_V", strat.subs, 0, 0, cache);
        addCompilerStrategyResults(compilation, "AND_V", rev, 0, 0, cache);
      }
      addCompilerStrategyResults(compilation, "AND_B", strat.subs, 0, 0, cache);
      addCompilerStrategyResults(compilation, "AND_B", rev, 0, 0, cache);
      return;
    }
    case "OR": {
      const rev = [strat.subs[1], strat.subs[0]];
      const prob = strat.prob;
      const revProb = 1 - prob;
      if (compilation.q === 0) {
        addCompilerStrategyResults(compilation, "OR_C", strat.subs, prob, 0, cache);
        addCompilerStrategyResults(compilation, "OR_C", rev, revProb, 0, cache);
      }
      addCompilerStrategyResults(compilation, "OR_B", strat.subs, prob, 0, cache);
      addCompilerStrategyResults(compilation, "OR_B", rev, revProb, 0, cache);
      addCompilerStrategyResults(compilation, "OR_D", strat.subs, prob, 0, cache);
      addCompilerStrategyResults(compilation, "OR_D", rev, revProb, 0, cache);
      addCompilerStrategyResults(compilation, "OR_I", strat.subs, prob, 0, cache);
      addCompilerStrategyResults(compilation, "OR_I", rev, revProb, 0, cache);
      addCompilerStrategyResults(compilation, "OR_I", strat.subs, prob, 1, cache);
      addCompilerStrategyResults(compilation, "OR_I", rev, revProb, 1, cache);
      return;
    }
    case "ANDOR": {
      addCompilerStrategyResults(compilation, "ANDOR", strat.subs, strat.prob, 0, cache);
      addCompilerStrategyResults(
        compilation,
        "ANDOR",
        [strat.subs[1], strat.subs[0], strat.subs[2]],
        strat.prob,
        0,
        cache,
      );
      return;
    }
    case "THRESH": {
      const pqs = getCompilerPqs(
        "THRESH",
        compilation.p,
        compilation.q,
        strat.prob,
        strat.subs.length,
      );
      const bs: CompileResult[] = [];
      const ws: CompileResult[] = [];
      let bPosition = -1;
      let costDiff = -1;

      for (let i = 0; i < strat.subs.length; i++) {
        const subCompilation = getPolicyCompilation(strat.subs[i], pqs.ps[i], pqs.qs[i], cache);
        const bResults = queryCompilation(subCompilation, parseCompilerFilter("Bemdu"));
        if (bResults.length === 0) return;
        bs.push(bResults[0]);
        const wResults = queryCompilation(subCompilation, parseCompilerFilter("Wemdu"));
        if (wResults.length === 0) return;
        ws.push(wResults[0]);
        const diff = ws[ws.length - 1].cost - bs[bs.length - 1].cost;
        if (diff > costDiff) {
          costDiff = diff;
          bPosition = i;
        }
      }

      const selected: CompileResult[] = [bs[bPosition]];
      for (let i = 0; i < strat.subs.length; i++) {
        if (i !== bPosition) {
          selected.push(ws[i]);
        }
      }
      addCompilerInner(compilation, "THRESH", selected, strat.prob, { k: strat.k });
      return;
    }
  }
}

function isSaneCompiledNode(node: MiniscriptFragment): boolean {
  const analysis = analyzeCompiledNode(node);
  if (!analysis) return false;
  return (
    analysis.type.base === "B" &&
    isValidCompiledSatisfaction(analysis.type, analysis.scriptSize, analysis.stats) &&
    analysis.type.m &&
    analysis.type.k &&
    analysis.type.s &&
    collectDuplicateCheckedKeys(node)
  );
}

function compilePolicyToMiniscript(
  node: PolicyNode,
  config: Record<string, string>,
  addressType: AddressType,
): string {
  const configured = configurePolicyNode(node, config);
  const state = createPolicyCompilerState();
  const strategy = computePolicyStrategy(configured, new Map(), state);
  if (!strategy) {
    invalid("Invalid policy");
  }

  const compilation = getPolicyCompilation(strategy, 1, 0, new Map());
  const results = queryCompilation(compilation, parseCompilerFilter("Bms"));
  if (results.length !== 1 || !isSaneCompiledNode(results[0].node)) {
    invalid("Invalid policy");
  }

  const miniscript = substituteMiniscriptKeys(results[0].node, {}, "");
  return addressType === "TAPROOT" ? miniscript.replaceAll("multi(", "multi_a(") : miniscript;
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

export function parseMiniscript(expression: string, addressType?: AddressType): MiniscriptFragment {
  const node = parseMiniscriptFragment(expression, addressType);
  const effectiveAddressType = resolveMiniscriptContext(expression, addressType);
  validateMiniscriptNode(node, effectiveAddressType);
  return node;
}

function validateMiniscriptTemplateStrict(expression: string, addressType?: AddressType): void {
  const node = parseMiniscript(expression, addressType);
  const effectiveAddressType = resolveMiniscriptContext(expression, addressType);
  const type = computeMiniscriptType(node, effectiveAddressType);
  if (type.base !== "B") {
    invalid("Invalid miniscript type");
  }
  if (
    computeMiniscriptScriptSize(node, effectiveAddressType) > maxScriptSize(effectiveAddressType)
  ) {
    invalid("Miniscript script exceeds maximum script size");
  }
  const stats = computeMiniscriptResourceStats(node, effectiveAddressType);
  if (!checkMiniscriptOpsLimit(stats, effectiveAddressType)) {
    invalid("Miniscript ops exceed consensus limit");
  }
  if (!checkMiniscriptStackSize(type, stats, effectiveAddressType)) {
    invalid("Miniscript stack size exceeds standard limit");
  }
  if (!type.m) {
    invalid("Miniscript is not non-malleable");
  }
  if (!type.k) {
    invalid("Timelock mixing");
  }
  if (!type.s) {
    invalid("Miniscript does not require a signature");
  }
  if (!collectDuplicateCheckedKeys(node)) {
    invalid("Duplicate miniscript key");
  }
  if (getMiniscriptStackSize(type, stats) == null) {
    invalid("Miniscript is not satisfiable");
  }
  validateMiniscriptTimelineNode(node);
}

export function isValidMiniscriptTemplate(expression: string, addressType?: AddressType): boolean {
  return validateMiniscriptTemplate(expression, addressType).ok;
}

export function validateMiniscriptTemplate(
  expression: string,
  addressType?: AddressType,
): ValidateResult {
  const cacheKey = `${addressType}\u0000${expression}`;
  const cached = miniscriptTemplateValidationCache.get(cacheKey);
  if (cached) {
    return { ...cached };
  }

  let result: ValidateResult;
  try {
    validateMiniscriptTemplateStrict(expression, addressType);
    result = { ok: true };
  } catch (error) {
    result = { error: (error as Error).message, ok: false };
  }
  miniscriptTemplateValidationCache.set(cacheKey, result);
  return { ...result };
}

export function miniscriptNeedsExplicitVerify(
  node: MiniscriptFragment,
  addressType?: AddressType,
): boolean {
  return computeMiniscriptType(node, resolveMiniscriptContext("", addressType)).x;
}

export function parsePolicy(expression: string): PolicyNode {
  return parsePolicyNode(expression);
}

export function isValidPolicy(expression: string): boolean {
  try {
    compilePolicyToMiniscript(parsePolicy(expression), {}, "NATIVE_SEGWIT");
    return true;
  } catch {
    return false;
  }
}

export function policyToMiniscript(
  expression: string,
  config: Record<string, string> = {},
  addressType: AddressType = "NATIVE_SEGWIT",
): string {
  const policy = parsePolicy(expression);
  const miniscript = compilePolicyToMiniscript(policy, config, addressType);
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
  addressType: AddressType,
): string {
  if (m <= 0 || newM <= 0) invalid("m, new_m must be greater than 0");
  if (n <= 0 || newN <= 0) invalid("n, new_n must be greater than 0");
  if (m > n) invalid("m must be less than or equal to n");
  if (newM > newN) invalid("new m must be less than or equal to new n");
  if (addressType !== "NATIVE_SEGWIT" && addressType !== "TAPROOT") {
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
    const name = addressType === "TAPROOT" ? "multi_a" : "multi";
    const keys: string[] = [];
    for (let i = startIndex; i < startIndex + total; i++) {
      keys.push(`key_${i}${i < newIndex ? "_1" : "_0"}`);
    }
    return `${name}(${threshold},${keys.join(",")})`;
  };

  const nextScript = buildInner(newM, newN, reuseSigners ? 0 : n, reuseSigners ? n : 0);
  const lockScript = timelockToMiniscript(timelock);

  if (addressType === "TAPROOT") {
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
  addressType: AddressType,
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
  addressType: AddressType,
): string {
  if (m <= newM) invalid("new m must be less than m");
  return flexibleMultisigMiniscriptTemplate(m, n, newM, n, reuseSigners, timelock, addressType);
}

export function miniscriptTemplateToMiniscript(
  miniscriptTemplate: string,
  signers: Record<string, string>,
  childPath = "/<0;1>/*",
  addressType?: AddressType,
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
      return miniscriptToScriptNode(parseMiniscript(node.value));
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
      : miniscriptTemplateToMiniscript(subscript, signers, childPath, "TAPROOT"),
  );

  return { keypath: parsed.keypath, tapscript: subScriptsToString(subscripts, parsed.depths) };
}

export function getScriptNode(expression: string): GetScriptNodeResult {
  const trimmed = expression.trim();
  if (trimmed.startsWith("tr(") || trimmed.startsWith("{")) {
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

  const miniscriptNode = parseMiniscript(trimmed);
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
      if (timelockK(timelock) !== node.k) {
        invalid(timelock.based === "TIME_LOCK" ? "Invalid time value" : "Invalid height value");
      }
      this.detectTimelockMixing(timelock.based);
      this.absoluteLocks.push(timelock.value);
    } else if (node.type === "OLDER") {
      const timelock = timelockFromK(false, node.k);
      if (timelockK(timelock) !== node.k) {
        invalid(timelock.based === "TIME_LOCK" ? "Invalid time value" : "Invalid height value");
      }
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
  addressType: AddressType,
  keypath = "",
): string {
  if (addressType === "NATIVE_SEGWIT") {
    return withDescriptorChecksum(`wsh(${miniscript})`);
  }
  if (addressType === "TAPROOT") {
    return withDescriptorChecksum(`tr(${keypath},${miniscript})`);
  }
  invalid("Invalid address type");
}

export function withDescriptorChecksum(descriptor: string): string {
  return `${descriptor}#${descriptorChecksum(descriptor)}`;
}
