// Bitcoin output descriptor builder and checksum
// Reference: libnunchuk src/descriptor.cpp

import { HDKey, type Versions } from "@scure/bip32";
import { hex } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import type { AddressType } from "./address-type.js";
import { bytesEqual, combinationIndices, compareBytes, concatBytes } from "./utils.js";

export const TAPROOT_UNSPENDABLE_KEY =
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const TAPROOT_MUSIG_MAX_KEYS = 5;
const COMPRESSED_TAPROOT_UNSPENDABLE_KEY = hex.decode(`02${TAPROOT_UNSPENDABLE_KEY}`);
const MAINNET_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };
const TESTNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };

export type TaprootWalletTemplate = "DEFAULT" | "DISABLE_KEY_PATH";
const DEFAULT_TAPROOT_WALLET_TEMPLATE: TaprootWalletTemplate = "DISABLE_KEY_PATH";

const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}" +
  "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
  'ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';

const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Bitcoin descriptor checksum (PolyMod-based)
// Reference: Bitcoin Core src/script/descriptor.cpp
function polyMod(c: bigint, val: number): bigint {
  const c0 = c >> 35n;
  c = ((c & 0x7ffffffffn) << 5n) ^ BigInt(val);
  if (c0 & 1n) c ^= 0xf5dee51989n;
  if (c0 & 2n) c ^= 0xa9fdca3312n;
  if (c0 & 4n) c ^= 0x1bab10e32dn;
  if (c0 & 8n) c ^= 0x3706b1677an;
  if (c0 & 16n) c ^= 0x644d626ffdn;
  return c;
}

export function descriptorChecksum(desc: string): string {
  let c = 1n;
  let cls = 0;
  let clsCount = 0;

  for (const ch of desc) {
    const pos = INPUT_CHARSET.indexOf(ch);
    if (pos === -1) throw new Error(`Invalid descriptor character: ${ch}`);
    c = polyMod(c, pos & 31);
    cls = cls * 3 + (pos >> 5);
    clsCount++;
    if (clsCount === 3) {
      c = polyMod(c, cls);
      cls = 0;
      clsCount = 0;
    }
  }

  if (clsCount > 0) c = polyMod(c, cls);
  for (let i = 0; i < 8; i++) c = polyMod(c, 0);
  c ^= 1n;

  let result = "";
  for (let i = 0; i < 8; i++) {
    result += CHECKSUM_CHARSET[Number((c >> BigInt(5 * (7 - i))) & 31n)];
  }
  return result;
}

function addChecksum(desc: string): string {
  return `${desc}#${descriptorChecksum(desc)}`;
}

// Matches libnunchuk FormalizePath: strip leading "m", replace "h" with "'", ensure leading "/"
export function formalizePath(path: string): string {
  let rs = path;
  if (rs.startsWith("m")) rs = rs.slice(1);
  rs = rs.replaceAll("h", "'");
  if (rs.length > 0 && rs[0] !== "/") rs = "/" + rs;
  return rs;
}

// Address type integer to descriptor wrapper
// Reference: GetDescriptorForSigners in src/descriptor.cpp:280-318
interface SignerDescriptor {
  masterFingerprint: string;
  derivationPath: string;
  xpub: string;
}

export function parseSignerDescriptor(desc: string): SignerDescriptor {
  // Parse "[xfp/path]xpub" or "[xfp]xpub" format
  const match = desc.match(/^\[([0-9a-fA-F]+)(\/[^\]]*)?\](.+)$/);
  if (!match) throw new Error(`Invalid signer descriptor: ${desc}`);
  return {
    masterFingerprint: match[1],
    derivationPath: match[2] ?? "",
    xpub: match[3],
  };
}

function compareSignerMasterFingerprint(a: string, b: string): number {
  return parseSignerDescriptor(a)
    .masterFingerprint.toLowerCase()
    .localeCompare(parseSignerDescriptor(b).masterFingerprint.toLowerCase());
}

export function sortTaprootDisableKeyPathSigners(
  signers: string[],
  addressType: AddressType,
  taprootWalletTemplate: TaprootWalletTemplate = DEFAULT_TAPROOT_WALLET_TEMPLATE,
): string[] {
  if (addressType !== "TAPROOT" || taprootWalletTemplate !== "DISABLE_KEY_PATH") {
    return signers;
  }
  return [...signers].sort(compareSignerMasterFingerprint);
}

function versionsForXpub(xpub: string): Versions {
  for (const versions of [MAINNET_VERSIONS, TESTNET_VERSIONS]) {
    try {
      HDKey.fromExtendedKey(xpub, versions);
      return versions;
    } catch {
      // try the next known xpub version
    }
  }
  throw new Error(`Unsupported xpub version: ${xpub}`);
}

function decodeAnyXpub(xpub: string): HDKey {
  return HDKey.fromExtendedKey(xpub, versionsForXpub(xpub));
}

export function getUnspendableXpub(signers: string[]): string {
  if (signers.length === 0) {
    throw new Error("Cannot build unspendable xpub without signers");
  }

  const pubkeys = signers
    .map((signer) => {
      const parsed = parseSignerDescriptor(signer);
      const key = decodeAnyXpub(parsed.xpub);
      if (!key.publicKey) {
        throw new Error("Invalid signer xpub");
      }
      return key.publicKey;
    })
    .sort(compareBytes)
    .filter((pubkey, index, all) => index === 0 || !bytesEqual(pubkey, all[index - 1]));

  const firstSigner = parseSignerDescriptor(signers[0]);
  const key = new HDKey({
    versions: versionsForXpub(firstSigner.xpub),
    publicKey: COMPRESSED_TAPROOT_UNSPENDABLE_KEY,
    chainCode: sha256(concatBytes(pubkeys)),
  });
  return key.publicExtendedKey;
}

export function isUnspendableXpub(expression: string): boolean {
  if (expression.trim().length === 0) {
    return false;
  }

  try {
    const base = expression.trim().replace(CHILD_PATH_SUFFIX, "");
    const key = decodeAnyXpub(base);
    return !!key.publicKey && bytesEqual(key.publicKey, COMPRESSED_TAPROOT_UNSPENDABLE_KEY);
  } catch {
    return false;
  }
}

function formatSignerKey(desc: string, childPath: string): string {
  const s = parseSignerDescriptor(desc);
  return `[${s.masterFingerprint}${s.derivationPath}]${s.xpub}${childPath}`;
}

// Build wallet descriptor for DescriptorPath::EXTERNAL_INTERNAL (appends /<0;1>/*)
// This is the standard format used by mobile apps (BIP-389 multipath descriptors)
// Reference: GetDescriptorForSigners in descriptor.cpp:240-328
export function buildWalletDescriptor(
  signers: string[],
  m: number,
  addressType: AddressType,
  taprootWalletTemplate: TaprootWalletTemplate = DEFAULT_TAPROOT_WALLET_TEMPLATE,
): string {
  return addChecksum(
    buildDescriptorBody(signers, m, addressType, "/<0;1>/*", taprootWalletTemplate),
  );
}

// Build wallet descriptor for DescriptorPath::ANY (appends /*)
// Used as PBKDF2 input for key derivation — must match SoftwareSigner behavior
// Reference: SoftwareSigner(Wallet) in softwaresigner.cpp:97-98
export function buildAnyDescriptor(
  signers: string[],
  m: number,
  addressType: AddressType,
  taprootWalletTemplate: TaprootWalletTemplate = DEFAULT_TAPROOT_WALLET_TEMPLATE,
): string {
  return addChecksum(buildDescriptorBody(signers, m, addressType, "/*", taprootWalletTemplate));
}

// Build raw descriptor body for a given child path suffix
function buildDescriptorBody(
  signers: string[],
  m: number,
  addressType: AddressType,
  childPath: string,
  taprootWalletTemplate: TaprootWalletTemplate = DEFAULT_TAPROOT_WALLET_TEMPLATE,
): string {
  const descriptorSigners = sortTaprootDisableKeyPathSigners(
    signers,
    addressType,
    taprootWalletTemplate,
  );
  const keys = descriptorSigners.map((s) => formatSignerKey(s, childPath));

  if (addressType === "TAPROOT") {
    return buildTaprootMultisigDescriptorBody(keys, m, taprootWalletTemplate);
  } else if (addressType === "NATIVE_SEGWIT") {
    return `wsh(sortedmulti(${m},${keys.join(",")}))`;
  } else if (addressType === "NESTED_SEGWIT") {
    return `sh(wsh(sortedmulti(${m},${keys.join(",")})))`;
  } else if (addressType === "LEGACY") {
    return `sh(sortedmulti(${m},${keys.join(",")}))`;
  } else {
    throw new Error("Taproot multisig descriptor not yet supported");
  }
}

function buildScriptpathDescriptor(nodes: string[]): string {
  if (nodes.length === 1) {
    return nodes[0];
  }

  const next: string[] = [];
  for (let i = 0; i < nodes.length; i += 2) {
    if (i === nodes.length - 1) {
      next.push(nodes[i]);
    } else {
      next.push(`{${nodes[i]},${nodes[i + 1]}}`);
    }
  }
  return buildScriptpathDescriptor(next);
}

function buildMusigDescriptor(keys: string[], m: number, disableValueKeyset: boolean): string {
  const leaves: string[] = [];
  const musig = (indices: number[]): string => `musig(${indices.map((i) => keys[i]).join(",")})`;
  const combinations = combinationIndices(keys.length, m);

  let descriptor = disableValueKeyset
    ? `tr(${TAPROOT_UNSPENDABLE_KEY}`
    : `tr(${musig(combinations[0])}`;

  if (disableValueKeyset) {
    leaves.push(`pk(${musig(combinations[0])})`);
  } else if (keys.length === m) {
    return `${descriptor})`;
  }

  descriptor += ",";
  for (const indices of combinations.slice(1)) {
    leaves.push(`pk(${musig(indices)})`);
  }
  return `${descriptor}${buildScriptpathDescriptor(leaves)})`;
}

function buildTaprootMultisigDescriptorBody(
  keys: string[],
  m: number,
  taprootWalletTemplate: TaprootWalletTemplate = DEFAULT_TAPROOT_WALLET_TEMPLATE,
): string {
  if (keys.length < 2 || m < 1 || m > keys.length) {
    throw new Error("Invalid taproot multisig m/n");
  }

  if (keys.length <= TAPROOT_MUSIG_MAX_KEYS || keys.length === m) {
    return buildMusigDescriptor(keys, m, taprootWalletTemplate === "DISABLE_KEY_PATH");
  }

  if (taprootWalletTemplate === "DEFAULT") {
    return `tr(musig(${keys.slice(0, m).join(",")}),sortedmulti_a(${m},${keys.join(",")}))`;
  }

  return `tr(${TAPROOT_UNSPENDABLE_KEY},sortedmulti_a(${m},${keys.join(",")}))`;
}

// Build wallet descriptor for DescriptorPath::EXTERNAL_ALL (appends /0/*)
// Reference: GetDescriptorForSigners in descriptor.cpp
export function buildExternalDescriptor(
  signers: string[],
  m: number,
  addressType: AddressType,
  taprootWalletTemplate: TaprootWalletTemplate = DEFAULT_TAPROOT_WALLET_TEMPLATE,
): string {
  return addChecksum(buildDescriptorBody(signers, m, addressType, "/0/*", taprootWalletTemplate));
}

// Derive local walletId — checksum of external descriptor (raw, no checksum suffix)
// Reference: GetWalletId in descriptor.cpp:345-349
export function getWalletId(
  signers: string[],
  m: number,
  addressType: AddressType,
  taprootWalletTemplate: TaprootWalletTemplate = DEFAULT_TAPROOT_WALLET_TEMPLATE,
): string {
  return descriptorChecksum(
    buildDescriptorBody(signers, m, addressType, "/0/*", taprootWalletTemplate),
  );
}

// --- Descriptor parsing (reverse of building) ---
// Reference: libnunchuk ParseOutputDescriptors (descriptor.cpp:598-626),
//            ParseSignerString (descriptor.cpp:386-401)

export type DescriptorKind = "miniscript" | "multisig";

export interface ParsedDescriptor {
  descriptor: string;
  kind: DescriptorKind;
  m: number;
  n: number;
  addressType: AddressType;
  signers: string[]; // ["[xfp/path]xpub", ...] — paths use ' notation
  miniscript?: string;
  taprootWalletTemplate?: TaprootWalletTemplate;
}

// Wrapper prefixes → addressType, ordered longest-first to avoid false matches
const WRAPPER_PREFIXES: Array<{ prefix: string; suffix: string; addressType: AddressType }> = [
  { prefix: "sh(wsh(sortedmulti(", suffix: ")))", addressType: "NESTED_SEGWIT" },
  { prefix: "wsh(sortedmulti(", suffix: "))", addressType: "NATIVE_SEGWIT" },
  { prefix: "sh(sortedmulti(", suffix: "))", addressType: "LEGACY" },
];

// Regex to strip child path suffixes from xpub: /0/*, /*, /<0;1>/*
const CHILD_PATH_SUFFIX = /(?:\/\d+\/\*|\/\*|\/<[^>]+>\/\*)$/;
const MINISCRIPT_SIGNER_TOKEN = /\[[0-9a-fA-F]+\/[^\]]*\][^,(){}#\s]+/g;

function normalizeSignerDescriptor(desc: string): string {
  const s = parseSignerDescriptor(desc.replace(CHILD_PATH_SUFFIX, ""));
  const xfp = s.masterFingerprint.toLowerCase();
  const path = formalizePath(s.derivationPath);
  return `[${xfp}${path}]${s.xpub}`;
}

function normalizeMiniscriptBody(body: string, childPath: string): string {
  return body.replace(MINISCRIPT_SIGNER_TOKEN, (match) => {
    return `${normalizeSignerDescriptor(match)}${childPath}`;
  });
}

function extractMiniscriptSigners(body: string): string[] {
  const matches = body.match(MINISCRIPT_SIGNER_TOKEN) ?? [];
  const signers: string[] = [];
  const seen = new Set<string>();

  for (const match of matches) {
    const signer = normalizeSignerDescriptor(match);
    if (seen.has(signer)) {
      continue;
    }
    seen.add(signer);
    signers.push(signer);
  }

  return signers;
}

export function requireMiniscriptBody(parsed: ParsedDescriptor): string {
  if (parsed.kind !== "miniscript" || !parsed.miniscript) {
    throw new Error("Parsed descriptor does not contain a miniscript body");
  }
  return parsed.miniscript;
}

function formatSignerKeyWithoutChildPath(desc: string): string {
  const s = parseSignerDescriptor(desc);
  return `[${s.masterFingerprint}${s.derivationPath}]${s.xpub}`;
}

function buildTaprootMiniscriptKeypath(
  signers: string[],
  keypathM: number,
  childPath: string,
): string {
  if (keypathM === 0) {
    return `${getUnspendableXpub(signers)}${childPath}`;
  }
  if (keypathM < 0 || keypathM > signers.length) {
    throw new Error("Invalid taproot miniscript keypath");
  }
  if (keypathM === 1) {
    return formatSignerKey(signers[0], childPath);
  }

  return `musig(${signers.slice(0, keypathM).map(formatSignerKeyWithoutChildPath).join(",")})${childPath}`;
}

function parseMusigLeaf(leaf: string): { keys: string[]; suffix: string } | null {
  if (!leaf.startsWith("pk(musig(") || !leaf.endsWith(")")) {
    return null;
  }

  const innerStart = "pk(musig(".length;
  const closingIndex = findClosingParen(leaf, "pk(musig".length);
  if (closingIndex === -1) {
    return null;
  }

  const keys = splitTopLevel(leaf.slice(innerStart, closingIndex)).map((key) => key.trim());
  if (keys.length === 0 || keys.some((key) => key.length === 0)) {
    return null;
  }

  return { keys, suffix: leaf.slice(closingIndex + 1, -1) };
}

function normalizeMusigLeaf(leaf: string, childPath: string): string | null {
  const parsed = parseMusigLeaf(leaf);
  if (!parsed) {
    return null;
  }

  const keys = parsed.keys.map(normalizeSignerDescriptor);
  return `pk(musig(${keys.join(",")})${childPath})`;
}

function normalizeTaprootScriptTree(script: string, childPath: string): string {
  const trimmed = script.trim();
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    const parts = splitTopLevel(trimmed.slice(1, -1));
    if (parts.length !== 2) {
      throw new Error("Could not parse descriptor: invalid taproot script tree");
    }
    return `{${normalizeTaprootScriptTree(parts[0], childPath)},${normalizeTaprootScriptTree(
      parts[1],
      childPath,
    )}}`;
  }

  return normalizeMusigLeaf(trimmed, childPath) ?? normalizeMiniscriptBody(trimmed, childPath);
}

function buildMiniscriptDescriptorBody(parsed: ParsedDescriptor, childPath: string): string {
  const miniscript = requireMiniscriptBody(parsed);
  if (parsed.addressType === "NATIVE_SEGWIT") {
    return `wsh(${normalizeMiniscriptBody(miniscript, childPath)})`;
  }
  if (parsed.addressType === "TAPROOT") {
    const keypath = buildTaprootMiniscriptKeypath(parsed.signers, parsed.m, childPath);
    return `tr(${keypath},${normalizeTaprootScriptTree(miniscript, childPath)})`;
  }
  throw new Error("Only native segwit and taproot miniscript descriptors are supported");
}

export function buildWalletDescriptorForParsed(parsed: ParsedDescriptor): string {
  if (parsed.kind === "multisig") {
    return buildWalletDescriptor(
      parsed.signers,
      parsed.m,
      parsed.addressType,
      parsed.taprootWalletTemplate,
    );
  }
  return addChecksum(buildMiniscriptDescriptorBody(parsed, "/<0;1>/*"));
}

export function buildAnyDescriptorForParsed(parsed: ParsedDescriptor): string {
  if (parsed.kind === "multisig") {
    return buildAnyDescriptor(
      parsed.signers,
      parsed.m,
      parsed.addressType,
      parsed.taprootWalletTemplate,
    );
  }
  return addChecksum(buildMiniscriptDescriptorBody(parsed, "/*"));
}

export function buildExternalDescriptorForParsed(parsed: ParsedDescriptor): string {
  if (parsed.kind === "multisig") {
    return buildExternalDescriptor(
      parsed.signers,
      parsed.m,
      parsed.addressType,
      parsed.taprootWalletTemplate,
    );
  }
  return addChecksum(buildMiniscriptDescriptorBody(parsed, "/0/*"));
}

export function getWalletIdForParsed(parsed: ParsedDescriptor): string {
  if (parsed.kind === "multisig") {
    return getWalletId(parsed.signers, parsed.m, parsed.addressType, parsed.taprootWalletTemplate);
  }
  return descriptorChecksum(buildMiniscriptDescriptorBody(parsed, "/0/*"));
}

function splitTopLevel(content: string): string[] {
  const parts: string[] = [];
  let bracketDepth = 0;
  let parenDepth = 0;
  let angleDepth = 0;
  let braceDepth = 0;
  let start = 0;
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (ch === "[") bracketDepth++;
    else if (ch === "]") bracketDepth--;
    else if (ch === "(") parenDepth++;
    else if (ch === ")") parenDepth--;
    else if (ch === "<") angleDepth++;
    else if (ch === ">") angleDepth--;
    else if (ch === "{") braceDepth++;
    else if (ch === "}") braceDepth--;
    else if (
      ch === "," &&
      bracketDepth === 0 &&
      parenDepth === 0 &&
      angleDepth === 0 &&
      braceDepth === 0
    ) {
      parts.push(content.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(content.slice(start));
  return parts;
}

export function descriptorHasTaprootScriptPath(descriptor: string): boolean {
  const hashIndex = descriptor.lastIndexOf("#");
  const body = hashIndex === -1 ? descriptor : descriptor.slice(0, hashIndex);
  if (!body.startsWith("tr(") || !body.endsWith(")")) {
    return false;
  }

  return splitTopLevel(body.slice(3, -1)).length === 2;
}

function collectTaprootLeaves(script: string): string[] {
  const trimmed = script.trim();
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    const parts = splitTopLevel(trimmed.slice(1, -1));
    if (parts.length !== 2) {
      throw new Error("Could not parse descriptor: invalid taproot script tree");
    }
    return [...collectTaprootLeaves(parts[0]), ...collectTaprootLeaves(parts[1])];
  }
  return [trimmed];
}

function findClosingParen(expression: string, openParenIndex: number): number {
  let depth = 0;
  for (let i = openParenIndex; i < expression.length; i++) {
    const ch = expression[i];
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function parseMusigLeafKeys(leaf: string): string[] | null {
  if (!leaf.startsWith("pk(musig(") || !leaf.endsWith(")")) {
    return null;
  }

  const innerStart = "pk(musig(".length;
  const closingIndex = findClosingParen(leaf, "pk(musig".length);
  if (closingIndex === -1) {
    return null;
  }
  const suffix = leaf.slice(closingIndex + 1, -1);
  if (suffix.length > 0) {
    throw new Error("Could not parse descriptor: unsupported musig derivation suffix");
  }

  const keys = splitTopLevel(leaf.slice(innerStart, closingIndex)).map((key) => key.trim());
  return keys.length > 0 && keys.every((key) => key.length > 0) ? keys : null;
}

function parseMusigKeypath(expression: string): { keys: string[]; suffix: string } | null {
  const trimmed = expression.trim();
  if (!trimmed.startsWith("musig(")) {
    return null;
  }

  const closingIndex = findClosingParen(trimmed, "musig".length);
  if (closingIndex === -1) {
    return null;
  }
  const suffix = trimmed.slice(closingIndex + 1);
  const keys = splitTopLevel(trimmed.slice("musig(".length, closingIndex)).map((key) => key.trim());
  return keys.length > 0 && keys.every((key) => key.length > 0) ? { keys, suffix } : null;
}

function parseMusigKeypathKeys(expression: string): string[] | null {
  return parseMusigKeypath(expression)?.keys ?? null;
}

interface ParsedTaprootKeypath {
  disabled: boolean;
  keys: string[];
}

function parseTaprootKeypath(expression: string): ParsedTaprootKeypath {
  const trimmed = expression.trim();
  if (
    trimmed === TAPROOT_UNSPENDABLE_KEY ||
    trimmed.replace(CHILD_PATH_SUFFIX, "") === TAPROOT_UNSPENDABLE_KEY ||
    isUnspendableXpub(trimmed)
  ) {
    return { disabled: true, keys: [] };
  }

  const musig = parseMusigKeypath(trimmed);
  if (musig) {
    return { disabled: false, keys: musig.keys };
  }

  return { disabled: false, keys: [trimmed] };
}

function mergeTaprootSigners(...keyGroups: string[][]): string[] {
  const signers: string[] = [];
  const seen = new Set<string>();

  for (const group of keyGroups) {
    for (const key of group) {
      const signer = normalizeSignerDescriptor(key);
      if (seen.has(signer)) {
        continue;
      }
      seen.add(signer);
      signers.push(signer);
    }
  }

  return signers;
}

function parseTaprootMultisigScript(script: string): { m: number; signers: string[] } {
  const prefix = script.startsWith("sortedmulti_a(")
    ? "sortedmulti_a("
    : script.startsWith("multi_a(")
      ? "multi_a("
      : null;
  if (prefix && script.endsWith(")")) {
    const parts = splitTopLevel(script.slice(prefix.length, -1)).map((part) => part.trim());
    if (parts.length < 2) {
      throw new Error("Could not parse descriptor: invalid taproot multisig content");
    }

    const m = parseInt(parts[0], 10);
    if (isNaN(m) || m < 1) {
      throw new Error("Could not parse descriptor: invalid m value");
    }

    return { m, signers: parts.slice(1).map(normalizeSignerDescriptor) };
  }

  const leaves = collectTaprootLeaves(script);
  const signers: string[] = [];
  const seen = new Set<string>();
  let m = 0;

  for (const leaf of leaves) {
    const keys = parseMusigLeafKeys(leaf);
    if (!keys) {
      throw new Error("Could not parse descriptor: unsupported taproot multisig script");
    }
    if (m === 0) {
      m = keys.length;
    } else if (keys.length !== m) {
      throw new Error("Could not parse descriptor: inconsistent musig leaf size");
    }

    for (const key of keys) {
      const signer = normalizeSignerDescriptor(key);
      if (seen.has(signer)) {
        continue;
      }
      seen.add(signer);
      signers.push(signer);
    }
  }

  if (m < 1 || signers.length < m) {
    throw new Error("Could not parse descriptor: invalid musig leaf set");
  }
  return { m, signers };
}

function buildParsedTaprootMultisig(
  signers: string[],
  m: number,
  taprootWalletTemplate: TaprootWalletTemplate,
): ParsedDescriptor {
  if (signers.length < 2 || m < 1 || m > signers.length) {
    throw new Error("Could not parse descriptor: invalid taproot multisig m/n");
  }
  const descriptorSigners = sortTaprootDisableKeyPathSigners(
    signers,
    "TAPROOT",
    taprootWalletTemplate,
  );

  return {
    descriptor: buildWalletDescriptor(descriptorSigners, m, "TAPROOT", taprootWalletTemplate),
    kind: "multisig",
    m,
    n: descriptorSigners.length,
    addressType: "TAPROOT",
    signers: descriptorSigners,
    taprootWalletTemplate,
  };
}

function extractTaprootScriptSigners(script: string): string[] {
  const trimmed = script.trim();
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    const parts = splitTopLevel(trimmed.slice(1, -1));
    if (parts.length !== 2) {
      throw new Error("Could not parse descriptor: invalid taproot script tree");
    }
    return [...extractTaprootScriptSigners(parts[0]), ...extractTaprootScriptSigners(parts[1])];
  }

  const musig = parseMusigLeaf(trimmed);
  if (musig) {
    return musig.keys.map(normalizeSignerDescriptor);
  }

  return extractMiniscriptSigners(trimmed);
}

function buildParsedTaprootMiniscript(
  script: string,
  keypath: ParsedTaprootKeypath,
): ParsedDescriptor {
  const keypathSigners = keypath.keys.map(normalizeSignerDescriptor);
  const scriptSigners = extractTaprootScriptSigners(script);
  const signers = mergeTaprootSigners(keypathSigners, scriptSigners);
  const miniscript = normalizeTaprootScriptTree(script, "/<0;1>/*");
  const parsed: ParsedDescriptor = {
    descriptor: "",
    kind: "miniscript",
    m: keypath.disabled ? 0 : keypathSigners.length,
    n: signers.length,
    addressType: "TAPROOT",
    signers,
    miniscript,
    taprootWalletTemplate: keypath.disabled ? "DISABLE_KEY_PATH" : "DEFAULT",
  };
  parsed.descriptor = addChecksum(buildMiniscriptDescriptorBody(parsed, "/<0;1>/*"));
  return parsed;
}

function parseTaprootMultisigBody(body: string): ParsedDescriptor | null {
  if (!body.startsWith("tr(") || !body.endsWith(")")) {
    return null;
  }

  const args = splitTopLevel(body.slice(3, -1)).map((arg) => arg.trim());
  if (args.length === 1) {
    const keypathKeys = parseMusigKeypathKeys(args[0]);
    if (!keypathKeys || keypathKeys.length < 2) {
      throw new Error(
        "Could not parse descriptor: taproot single-sig descriptors are not supported",
      );
    }

    const signers = mergeTaprootSigners(keypathKeys);
    return buildParsedTaprootMultisig(signers, keypathKeys.length, "DEFAULT");
  }

  if (args.length !== 2) {
    throw new Error("Could not parse descriptor: taproot key-path descriptors are not supported");
  }

  const keypath = parseTaprootKeypath(args[0]);
  if (keypath.disabled) {
    try {
      const { m, signers } = parseTaprootMultisigScript(args[1]);
      return buildParsedTaprootMultisig(signers, m, "DISABLE_KEY_PATH");
    } catch {
      return buildParsedTaprootMiniscript(args[1], keypath);
    }
  }

  if (keypath.keys.length > 1) {
    try {
      const script = parseTaprootMultisigScript(args[1]);
      const signers = mergeTaprootSigners(keypath.keys, script.signers);
      return buildParsedTaprootMultisig(signers, keypath.keys.length, "DEFAULT");
    } catch {
      return buildParsedTaprootMiniscript(args[1], keypath);
    }
  }

  return buildParsedTaprootMiniscript(args[1], keypath);
}

/**
 * Parse a descriptor string into wallet components.
 * Accepts descriptors with any child path variant (\/*, /0/*, /<0;1>/*) and strips them.
 * Normalizes derivation paths: h → ' (to match libnunchuk FormalizePath).
 */
export function parseDescriptor(descriptor: string): ParsedDescriptor {
  // 1. Validate checksum
  const hashIdx = descriptor.lastIndexOf("#");
  if (hashIdx === -1) {
    throw new Error("Could not parse descriptor: missing checksum");
  }
  const body = descriptor.slice(0, hashIdx);
  const checksum = descriptor.slice(hashIdx + 1);
  const expected = descriptorChecksum(body);
  if (checksum !== expected) {
    throw new Error("Descriptor checksum mismatch");
  }

  // 2. Detect wrapper → addressType
  let innerContent: string | null = null;
  let addressType: AddressType | undefined;
  for (const w of WRAPPER_PREFIXES) {
    if (body.startsWith(w.prefix) && body.endsWith(w.suffix)) {
      innerContent = body.slice(w.prefix.length, body.length - w.suffix.length);
      addressType = w.addressType;
      break;
    }
  }
  if (innerContent === null) {
    if (body.startsWith("tr(") && body.endsWith(")")) {
      const parsedTaproot = parseTaprootMultisigBody(body);
      if (parsedTaproot) return parsedTaproot;
    }

    if (body.startsWith("wsh(") && body.endsWith(")")) {
      const miniscript = normalizeMiniscriptBody(body.slice(4, -1), "/<0;1>/*");
      const signers = extractMiniscriptSigners(miniscript);
      return {
        descriptor: addChecksum(`wsh(${miniscript})`),
        kind: "miniscript",
        m: 0,
        n: signers.length,
        addressType: "NATIVE_SEGWIT",
        signers,
        miniscript,
      };
    }

    throw new Error("Could not parse descriptor: unsupported wrapper");
  }
  const resolvedAddressType = addressType;
  if (!resolvedAddressType) {
    throw new Error("Could not parse descriptor: unsupported wrapper");
  }

  // 3. Split inner content: m, key1, key2, ...
  // Keys contain commas inside brackets, so we split carefully
  const parts = splitSortedMulti(innerContent);
  if (parts.length < 2) {
    throw new Error("Could not parse descriptor: invalid sortedmulti content");
  }

  const m = parseInt(parts[0], 10);
  if (isNaN(m) || m < 1) {
    throw new Error("Could not parse descriptor: invalid m value");
  }

  // 4. Parse each signer key — reuse parseSignerDescriptor, strip child path
  const signers: string[] = [];
  for (let i = 1; i < parts.length; i++) {
    const raw = parts[i].replace(CHILD_PATH_SUFFIX, "");
    const s = parseSignerDescriptor(raw);
    const xfp = s.masterFingerprint.toLowerCase();
    const path = formalizePath(s.derivationPath); // normalize h → '
    signers.push(`[${xfp}${path}]${s.xpub}`);
  }

  return {
    descriptor: addChecksum(body),
    kind: "multisig",
    m,
    n: signers.length,
    addressType: resolvedAddressType,
    signers,
  };
}

/** Split sortedmulti inner content by top-level commas (not inside brackets). */
function splitSortedMulti(content: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "[" || content[i] === "<") depth++;
    else if (content[i] === "]" || content[i] === ">") depth--;
    else if (content[i] === "," && depth === 0) {
      parts.push(content.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(content.slice(start));
  return parts;
}

/**
 * Parse a BSMS 1.0 record.
 * Validates version, path restrictions, and first address.
 * Uses dynamic import for address.ts to avoid circular dependency.
 * Reference: libnunchuk ParseBSMSRecord() in bsms.hpp:49-79
 */
export async function parseBsmsRecord(
  content: string,
  network: import("./config.js").Network,
): Promise<ParsedDescriptor> {
  const lines = content.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length < 4) {
    throw new Error("Invalid BSMS record: expected at least 4 lines");
  }
  if (lines[0] !== "BSMS 1.0") {
    throw new Error(`Invalid BSMS record: unsupported version "${lines[0]}"`);
  }

  if (lines[2] !== "/0/*,/1/*" && lines[2] !== "No path restrictions") {
    throw new Error(`Invalid BSMS record: invalid path restriction "${lines[2]}"`);
  }

  // Dynamic import to avoid circular dependency (address.ts imports from descriptor.ts)
  const parsed = parseDescriptor(lines[1]);
  const { deriveDescriptorFirstAddress } = await import("./address.js");
  const expectedAddress = deriveDescriptorFirstAddress(parsed.descriptor, network);
  if (lines[3] !== expectedAddress) {
    throw new Error("Invalid BSMS record: first address does not match descriptor");
  }

  return parsed;
}
