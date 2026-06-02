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
import {
  buildWalletDescriptor,
  descriptorChecksum,
  getUnspendableXpub,
  parseSignerDescriptor,
} from "../descriptor.js";
import { buildMiniscriptDescriptor } from "../miniscript.js";

const TEST_SIGNERS = [
  "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
];

const MINISCRIPT_DESCRIPTOR = buildMiniscriptDescriptor(
  `and_v(v:pk(${TEST_SIGNERS[0]}/<0;1>/*),pk(${TEST_SIGNERS[1]}/<0;1>/*))`,
  "NATIVE_SEGWIT",
);

function makeTaprootSigner(seedByte: number): string {
  const root = HDKey.fromMasterSeed(new Uint8Array(32).fill(seedByte), TESTNET_VERSIONS);
  const account = root.derive("m/87'/1'/0'");
  const fingerprint = root.fingerprint.toString(16).padStart(8, "0");
  return `[${fingerprint}/87'/1'/0']${account.publicExtendedKey}`;
}

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

  it("derives libnunchuk taproot multisig musig-leaf payments", () => {
    const descriptor = buildWalletDescriptor(TEST_SIGNERS, 2, "TAPROOT");
    const payment = deriveDescriptorPayment(descriptor, "testnet", 0, 0);

    expect(payment.address).toMatch(/^tb1p/);
    expect(payment.tapInternalKey).toHaveLength(32);
    expect(payment.tapMerkleRoot).toHaveLength(32);
    expect(payment.tapLeafScript).toHaveLength(1);
    expect(payment.tapBip32Derivation).toHaveLength(2);
    expect(payment.tapBip32Derivation?.[0][1].hashes).toHaveLength(1);
  });

  it("derives libnunchuk default taproot key-path musig addresses", () => {
    const disableKeyPathDescriptor = buildWalletDescriptor(TEST_SIGNERS, 2, "TAPROOT");
    const defaultDescriptor = buildWalletDescriptor(TEST_SIGNERS, 2, "TAPROOT", "DEFAULT");
    const payment = deriveDescriptorPayment(defaultDescriptor, "testnet", 0, 0);

    expect(defaultDescriptor).not.toBe(disableKeyPathDescriptor);
    expect(payment.address).toMatch(/^tb1p/);
    expect(payment.tapInternalKey).toHaveLength(32);
    expect(payment.tapMerkleRoot).toBeUndefined();
    expect(payment.tapLeafScript).toBeUndefined();
    expect(payment.address).not.toBe(
      deriveDescriptorPayment(disableKeyPathDescriptor, "testnet", 0, 0).address,
    );
  });

  it("derives libnunchuk taproot miniscript disable-key-path payments", () => {
    const unspendableXpub = getUnspendableXpub(TEST_SIGNERS);
    const body = `tr(${unspendableXpub}/<0;1>/*,and_v(v:pk(${TEST_SIGNERS[0]}/<0;1>/*),pk(${TEST_SIGNERS[1]}/<0;1>/*)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const payment = deriveDescriptorPayment(descriptor, "testnet", 0, 0);

    expect(payment.address).toMatch(/^tb1p/);
    expect(payment.witnessScript).toBeUndefined();
    expect(payment.tapInternalKey).toHaveLength(32);
    expect(payment.tapMerkleRoot).toHaveLength(32);
    expect(payment.tapLeafScript).toHaveLength(1);
    expect(payment.tapBip32Derivation).toHaveLength(2);
  });

  it("derives taproot miniscript multi_a payments", () => {
    const unspendableXpub = getUnspendableXpub(TEST_SIGNERS);
    const body = `tr(${unspendableXpub}/<0;1>/*,{multi_a(2,${TEST_SIGNERS[0]}/<0;1>/*,${TEST_SIGNERS[1]}/<0;1>/*),pk(${TEST_SIGNERS[0]}/<0;1>/*)})`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const payment = deriveDescriptorPayment(descriptor, "testnet", 0, 0);

    expect(payment.address).toMatch(/^tb1p/);
    expect(payment.tapLeafScript).toHaveLength(2);
    expect(payment.tapBip32Derivation).toHaveLength(2);
    expect(payment.bip32Derivation).toEqual([]);
  });

  it("derives taproot miniscript payments with timelock leaves", () => {
    const signers = Array.from({ length: 4 }, (_, index) => makeTaprootSigner(index + 1));
    const unspendableXpub = getUnspendableXpub(signers);
    const body = `tr(${unspendableXpub}/<0;1>/*,thresh(3,pk(${signers[0]}/<0;1>/*),s:pk(${signers[1]}/<0;1>/*),s:pk(${signers[2]}/<0;1>/*),s:pk(${signers[3]}/<0;1>/*),sln:after(1842652800),sln:after(1937260800)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const payment = deriveDescriptorPayment(descriptor, "testnet", 0, 0);

    expect(payment.address).toMatch(/^tb1p/);
    expect(payment.witnessScript).toBeUndefined();
    expect(payment.tapInternalKey).toHaveLength(32);
    expect(payment.tapMerkleRoot).toHaveLength(32);
    expect(payment.tapLeafScript).toHaveLength(1);
    expect(payment.tapBip32Derivation).toHaveLength(4);
    expect(deriveDescriptorAddresses(descriptor, "testnet", 0, 0, 1)).toEqual([payment.address]);
  });

  it("derives taproot sortedmulti_a metadata for large libnunchuk multisig fallback", () => {
    const signers = Array.from({ length: 6 }, (_, index) => makeTaprootSigner(index + 1));
    const descriptor = buildWalletDescriptor(signers, 2, "TAPROOT");
    const receive = deriveDescriptorAddresses(descriptor, "testnet", 0, 0, 2);
    const change = deriveDescriptorAddresses(descriptor, "testnet", 1, 0, 1);
    const payment = deriveDescriptorPayment(descriptor, "testnet", 0, 0);

    expect(receive[0]).toMatch(/^tb1p/);
    expect(receive[0]).not.toBe(receive[1]);
    expect(receive[0]).not.toBe(change[0]);
    expect(payment.tapLeafScript).toHaveLength(1);
    expect(payment.tapBip32Derivation).toHaveLength(6);
    expect(payment.bip32Derivation).toEqual([]);
  });
});
