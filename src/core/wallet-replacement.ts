import { parseDescriptor, parseSignerDescriptor } from "./descriptor.js";
import type { AddressType } from "./address-type.js";
import type { WalletPlatformKeyConfig } from "./platform-key.js";
import type { WalletData } from "./storage.js";
import { isRecord } from "./utils.js";

export const DEPRECATED_WALLET_PREFIX = "[DEPRECATED] ";

export interface ReplacementGroupDetails {
  name: string;
  m: number;
  n: number;
  addressType: AddressType;
  signers: string[];
  miniscriptTemplate: string;
  platformKeySlots: string[];
}

export function getGroupReplaceWalletId(group: Record<string, unknown>): unknown {
  const phaseData = isRecord(group.init)
    ? group.init
    : isRecord(group.finalize)
      ? group.finalize
      : {};
  const extra = isRecord(phaseData.extra) ? phaseData.extra : {};
  return (
    group.replace_wallet_id ??
    group.replaceWalletId ??
    extra.replace_wallet_id ??
    extra.replaceWalletId
  );
}

export function getDeprecatedWalletName(name: string): string {
  return name.startsWith(DEPRECATED_WALLET_PREFIX) ? name : `${DEPRECATED_WALLET_PREFIX}${name}`;
}

function signerFingerprint(signer: string): string {
  return parseSignerDescriptor(signer).masterFingerprint.toLowerCase();
}

function getReplacementPlatformKeySlots(
  signers: string[],
  config: WalletPlatformKeyConfig,
): string[] {
  if (!config.platformKey || !config.platformKeyFingerprint) {
    return [];
  }

  const platformKeyFingerprint = config.platformKeyFingerprint.toLowerCase();
  return signers.flatMap((signer, index) =>
    signerFingerprint(signer) === platformKeyFingerprint ? [`key_${index}`] : [],
  );
}

function clearReplacementPlatformSigners(
  signers: string[],
  kind: "miniscript" | "multisig",
  config: WalletPlatformKeyConfig,
): { signers: string[]; platformKeySlots: string[] } {
  const replacementSigners = [...signers];
  if (!config.platformKey) {
    return { signers: replacementSigners, platformKeySlots: [] };
  }

  if (kind === "multisig") {
    if (replacementSigners.length > 0) {
      replacementSigners[replacementSigners.length - 1] = "[]";
    }
    return { signers: replacementSigners, platformKeySlots: [] };
  }

  const platformKeySlots = getReplacementPlatformKeySlots(replacementSigners, config);
  for (const slot of platformKeySlots) {
    const match = slot.match(/^key_(\d+)$/);
    if (!match) {
      continue;
    }
    const index = Number(match[1]);
    if (index >= 0 && index < replacementSigners.length) {
      replacementSigners[index] = "[]";
    }
  }

  return { signers: replacementSigners, platformKeySlots };
}

function buildReplacementMiniscriptTemplate(miniscript: string, signers: string[]): string {
  const signerEntries = signers
    .map((signer, index) => ({ signer, index }))
    .sort((a, b) => b.signer.length - a.signer.length);

  let template = miniscript;
  for (const { signer, index } of signerEntries) {
    const keyName = `key_${index}`;
    for (const suffix of ["/<0;1>/*", "/0/*", "/*", ""]) {
      template = template.split(`${signer}${suffix}`).join(keyName);
    }
  }
  return template;
}

export function getReplacementGroupDetails(
  wallet: WalletData,
  config: WalletPlatformKeyConfig = {},
): ReplacementGroupDetails {
  const parsed = parseDescriptor(wallet.descriptor);
  const { signers, platformKeySlots } = clearReplacementPlatformSigners(
    parsed.signers,
    parsed.kind,
    config,
  );

  if (parsed.kind === "multisig") {
    return {
      name: wallet.name,
      m: parsed.m,
      n: parsed.n,
      addressType: parsed.addressType,
      signers,
      miniscriptTemplate: "",
      platformKeySlots,
    };
  }

  if (!parsed.miniscript) {
    throw new Error("Missing miniscript descriptor body");
  }

  return {
    name: wallet.name,
    m: parsed.m,
    n: parsed.n,
    addressType: parsed.addressType,
    signers,
    miniscriptTemplate: buildReplacementMiniscriptTemplate(parsed.miniscript, parsed.signers),
    platformKeySlots,
  };
}

export function getReplacementAcceptSigners(
  wallet: WalletData,
  config: WalletPlatformKeyConfig = {},
): string[] {
  const parsed = parseDescriptor(wallet.descriptor);
  return clearReplacementPlatformSigners(parsed.signers, parsed.kind, config).signers;
}
