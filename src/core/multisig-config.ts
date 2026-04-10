import { HDKey } from "@scure/bip32";
import { formalizePath, parseSignerDescriptor, type ParsedDescriptor } from "./descriptor.js";
import type { Network } from "./config.js";
import { MAINNET_VERSIONS, TESTNET_VERSIONS } from "./address.js";

const MULTISIG_CONFIG_FORMATS: Record<number, string> = {
  1: "P2SH",
  2: "P2WSH-P2SH",
  3: "P2WSH",
  4: "P2TR",
};

const FORMAT_TO_ADDRESS_TYPE: Record<string, number> = {
  p2sh: 1,
  p2wsh: 3,
  "p2wsh-p2sh": 2,
  "p2sh-p2wsh": 2,
  p2tr: 4,
};

const NAME_REGEX = /^name\s*:(.+)$/i;
const POLICY_REGEX = /^policy\s*:\s*([0-9]{1,2})(.+?)([0-9]{1,2})$/i;
const FORMAT_REGEX = /^format\s*:(.+)$/i;
const DERIVATION_REGEX = /^derivation\s*:(.+)$/i;
const XFP_REGEX = /^([0-9a-fA-F]{8})\s*:(.+)$/;

function getMultisigConfigFormat(addressType: number): string {
  const format = MULTISIG_CONFIG_FORMATS[addressType];
  if (!format) {
    throw new Error(`Unsupported address type for multisig config export: ${addressType}`);
  }
  return format;
}

function formatMultisigConfigDerivationPath(path: string): string {
  const normalized = formalizePath(path);
  return (normalized ? `m${normalized}` : "m").replaceAll("'", "h");
}

export function buildMultisigConfig(
  name: string,
  signers: string[],
  m: number,
  n: number,
  addressType: number,
): string {
  const lines = [
    "# Export from nunchuk-cli",
    `Name: ${name.slice(0, 20)}`,
    `Policy: ${m} of ${n}`,
    `Format: ${getMultisigConfigFormat(addressType)}`,
    "",
  ];

  for (const signer of signers) {
    const { masterFingerprint, derivationPath, xpub } = parseSignerDescriptor(signer);
    lines.push(`Derivation: ${formatMultisigConfigDerivationPath(derivationPath)}`);
    lines.push(`${masterFingerprint}: ${xpub}`);
    lines.push("");
  }

  return lines.join("\n");
}

function isValidDerivationPath(value: string): boolean {
  const normalized = value.trim().replaceAll("h", "'");
  if (normalized === "m") {
    return true;
  }

  const withRoot = normalized.startsWith("m")
    ? normalized
    : normalized.startsWith("/")
      ? `m${normalized}`
      : `m/${normalized}`;

  return /^m(?:\/\d+'?)*$/.test(withRoot);
}

function parseMultisigConfigFormat(value: string): number {
  const addressType = FORMAT_TO_ADDRESS_TYPE[value.trim().toLowerCase()];
  if (addressType == null) {
    throw new Error(`Invalid address type: ${value}`);
  }
  return addressType;
}

function validateExtendedPublicKeyForNetwork(value: string, network: Network): string {
  const xpub = value.trim();
  const expectedPrefix = network === "mainnet" ? "xpub" : "tpub";
  const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;

  if (!xpub.startsWith(expectedPrefix)) {
    throw new Error(`Expected ${expectedPrefix} for ${network} multisig config`);
  }

  try {
    return HDKey.fromExtendedKey(xpub, versions).publicExtendedKey;
  } catch {
    throw new Error("Invalid extended public key");
  }
}

export function parseMultisigConfig(content: string, network: Network): ParsedDescriptor {
  let addressType = 1;
  let m = 0;
  let n = 0;
  let derivationPath: string | undefined;
  const signers: string[] = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    if (line.match(NAME_REGEX)) {
      continue;
    }
    const policyMatch = line.match(POLICY_REGEX);
    if (policyMatch) {
      const [, parsedM, , parsedN] = policyMatch;
      m = parseInt(parsedM, 10);
      n = parseInt(parsedN, 10);
      continue;
    }
    const formatMatch = line.match(FORMAT_REGEX);
    if (formatMatch) {
      addressType = parseMultisigConfigFormat(formatMatch[1]);
      continue;
    }
    const derivationMatch = line.match(DERIVATION_REGEX);
    if (derivationMatch) {
      const candidate = derivationMatch[1].trim();
      if (!isValidDerivationPath(candidate)) {
        throw new Error("Invalid derivation path");
      }
      derivationPath = formalizePath(candidate);
      continue;
    }
    const signerMatch = line.match(XFP_REGEX);
    if (signerMatch) {
      if (derivationPath == null) {
        throw new Error("Invalid derivation path");
      }

      const fingerprint = signerMatch[1].toLowerCase();
      const xpub = validateExtendedPublicKeyForNetwork(signerMatch[2], network);
      signers.push(`[${fingerprint}${derivationPath}]${xpub}`);
      continue;
    }
  }

  if (n <= 0) n = signers.length;
  if (m <= 0) m = n;
  if (n <= 0 || m <= 0 || m > n || n !== signers.length) {
    throw new Error("Invalid parameters n, m");
  }

  return { m, n, addressType, signers };
}
