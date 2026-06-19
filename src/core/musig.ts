import type { ParsedDescriptor } from "./descriptor.js";
import { isValidMusigTemplate, parseTapscriptTemplate } from "./miniscript.js";

export const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a;
export const PSBT_IN_MUSIG2_PUB_NONCE = 0x1b;
export const PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c;

export function descriptorHasMusig2Path(parsed: ParsedDescriptor): boolean {
  if (parsed.addressType !== "TAPROOT") {
    return false;
  }

  if (parsed.kind === "multisig") {
    return parsed.taprootWalletTemplate === "DEFAULT" || parsed.n <= 5 || parsed.n === parsed.m;
  }

  if (parsed.kind !== "miniscript") {
    return false;
  }

  if (parsed.m > 1) {
    return true;
  }

  if (!parsed.miniscript) {
    return false;
  }

  try {
    return parseTapscriptTemplate(parsed.miniscript).subscripts.some(isValidMusigTemplate);
  } catch {
    return false;
  }
}
