import { describe, expect, it } from "vitest";
import { HDKey } from "@scure/bip32";
import { bech32 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { bip32Path } from "@scure/btc-signer";
import { Script } from "@scure/btc-signer/script.js";
import {
  TESTNET_VERSIONS,
  deriveDescriptorAddresses,
  deriveDescriptorPayment,
} from "../address.js";
import { parseSignerDescriptor } from "../descriptor.js";
import { buildMiniscriptDescriptor, MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT } from "../miniscript.js";

const TEST_SIGNERS = [
  "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
];

const MINISCRIPT_DESCRIPTOR = buildMiniscriptDescriptor(
  `and_v(v:pk(${TEST_SIGNERS[0]}/<0;1>/*),pk(${TEST_SIGNERS[1]}/<0;1>/*))`,
  MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
);

function derivePubkey(signer: string, chain: 0 | 1, index: number): Uint8Array {
  const parsed = parseSignerDescriptor(signer);
  const child = HDKey.fromExtendedKey(parsed.xpub, TESTNET_VERSIONS)
    .deriveChild(chain)
    .deriveChild(index);
  if (!child.publicKey) {
    throw new Error("Failed to derive test public key");
  }
  return child.publicKey;
}

describe("deriveDescriptorPayment", () => {
  it("derives native segwit miniscript witness scripts and addresses", () => {
    const pubkey0 = derivePubkey(TEST_SIGNERS[0], 0, 0);
    const pubkey1 = derivePubkey(TEST_SIGNERS[1], 0, 0);
    const expectedWitnessScript = Script.encode([pubkey0, "CHECKSIGVERIFY", pubkey1, "CHECKSIG"]);
    const expectedAddress = bech32.encode("tb", [
      0,
      ...bech32.toWords(sha256(expectedWitnessScript)),
    ]);

    const payment = deriveDescriptorPayment(MINISCRIPT_DESCRIPTOR, "testnet", 0, 0);

    expect(Buffer.from(payment.witnessScript!).toString("hex")).toBe(
      Buffer.from(expectedWitnessScript).toString("hex"),
    );
    expect(payment.address).toBe(expectedAddress);
    expect(payment.bip32Derivation).toEqual([
      [pubkey0, { fingerprint: parseInt("534a4a82", 16), path: bip32Path("m/48'/1'/0'/2'/0/0") }],
      [pubkey1, { fingerprint: parseInt("4bda0966", 16), path: bip32Path("m/48'/1'/0'/2'/0/0") }],
    ]);
  });

  it("derives distinct receive and change addresses for miniscript descriptors", () => {
    const receive = deriveDescriptorAddresses(MINISCRIPT_DESCRIPTOR, "testnet", 0, 0, 2);
    const change = deriveDescriptorAddresses(MINISCRIPT_DESCRIPTOR, "testnet", 1, 0, 1);

    expect(receive[0]).not.toBe(receive[1]);
    expect(receive[0]).not.toBe(change[0]);
  });
});
