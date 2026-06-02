import * as musig2 from "@scure/btc-signer/musig2.js";

export function toXOnlyPubkey(
  pubkey: Uint8Array,
  errorMessage = "Invalid taproot public key",
): Uint8Array {
  if (pubkey.length === 32) {
    return pubkey;
  }
  if (pubkey.length === 33 && (pubkey[0] === 0x02 || pubkey[0] === 0x03)) {
    return pubkey.subarray(1);
  }
  throw new Error(errorMessage);
}

export function aggregateMusigPubkey(pubkeys: Uint8Array[]): Uint8Array {
  return musig2.keyAggExport(musig2.keyAggregate(musig2.sortKeys([...pubkeys])));
}

export function aggregateMusigCompressedPubkey(pubkeys: Uint8Array[]): Uint8Array {
  return musig2.keyAggregate(musig2.sortKeys([...pubkeys])).aggPublicKey.toBytes(true);
}
