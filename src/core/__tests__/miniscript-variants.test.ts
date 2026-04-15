import { describe, expect, it, vi } from "vitest";
import { HDKey } from "@scure/bip32";
import { Transaction, TEST_NETWORK } from "@scure/btc-signer";
import { deriveDescriptorAddresses, TESTNET_VERSIONS } from "../address.js";
import { addressToScripthash } from "../electrum.js";
import { finalizeMiniscriptPsbt } from "../miniscript-finalize.js";
import { withDescriptorChecksum } from "../miniscript.js";
import { signWalletPsbtWithKey } from "../psbt-sign.js";
import { createTransaction } from "../transaction.js";
import type { ElectrumClient } from "../electrum.js";
import type { WalletData } from "../storage.js";

interface VariantSigner {
  descriptor: string;
  fingerprint: string;
  xprv: string;
}

interface VariantBranch {
  index: number;
  lockTime: number;
  requiredSignatures: number;
  signerIndexes: number[];
  sequence: number;
  txSequence: number;
}

interface VariantCase {
  changeAddresses: string[];
  miniscriptTemplate: string;
  name: string;
  primary: VariantBranch;
  receiveAddresses: string[];
  timelocked: VariantBranch;
  walletDescriptor: string;
}

const TEST_RECIPIENT = "tb1qwxgcncwed6hplwhhal7a5mu98ga9r5dqthj5ge84rqzz407887aq3srgkz";

const LOCAL_KEY_DESCRIPTORS = [
  "[94334c52/48'/1'/0'/2']tpubDELqhHfquXR4mjoSjBm7FCyaMcd6zFoCiFSpvEQPwXr4oULNz9SozPgQvQGk3Sc8VxNtSbczDjhYQv95cpKR9FeCqWHEeL3395FohnX8KyD",
  "[9b701d82/48'/1'/0'/2']tpubDEM4H9JMeDYxoj12zsMnfp4ESDkD6k4RBD7SBibX4Wk6Mme96633gfHkyhqHFewrHGoTbcEQ517STcEKBBg36o4D7BK6NCqTHmMoM7nUkRq",
  "[a3fdcdd5/48'/1'/0'/2']tpubDEDtkrUUpfLYxoRG3NnwNYRB2V3ebaQFCYY9KyoPmaGHjY8vp2iwWiAJsNrV5PUTVvahfDvWK935T7hcjeHBNw9cJ2PmDKtueGuCykNEAr1",
  "[ec91de54/48'/1'/0'/2']tpubDE3GDWuTypP7WhPPzV75DJmt5fkUwAA2NUC1HkxQfu8HU1aP8grzSDRJKj35J8igq7dYGFKhN7k9NiHjvGVSaPHfyjNToDpTm15FMLyBKr2",
];

const TEST_SIGNERS: VariantSigner[] = [
  {
    descriptor:
      "[96eca294/48'/1'/0'/2']tpubDFPj9hqgQDd6XmwP6rFLyfan3WwEXgAvWWwCAyTVfqegGX6FBofdCagNzn6FveEnaqa9k3sHdAX9Styj4LXVdT9FGiZcRhKE8pMEvZoSn7Y",
    fingerprint: "96eca294",
    xprv: "tprv8ihh1HoSFqwReJubDCakaFvfUVRJNLz1wDLQtTRCFZrHS2qUZQr3264Wpcbv8CxAYKYV2ZuucLntw96V9X1ZFeuoRQqdPcz3PACnJeHX5Eq",
  },
  {
    descriptor:
      "[e442ae1d/48'/1'/0'/2']tpubDFUQmRE5eeoBnPfjy3RkqCfGdzsbnTzJHqM7ioNrFspMUrgvBMJkUurg9dCmeb9zd9rTaVoNkMzPku6VsopVnhAPMyQs95KoK8Q1zUCtX2B",
    fingerprint: "e442ae1d",
    xprv: "tprv8inNd1BqWH7Wtvdx5PmARo1A4yMfd8oPiXkLSHLYqc1xeNS9YxVAJREoyUJpUAqJbY9EMeALmYe3dXPBtAMqpwuZeXv4WAgEMfDs48TyMk9",
  },
  {
    descriptor:
      "[dd38da6b/48'/1'/0'/2']tpubDFJiyLvovM1LQjFEiPb4Mbwc1RwksKEhaik61g4ayMUF2TjwqFBpKYh53cNCnxNiuzmpxjJ9UiTGJMKQ8RVCTv2bV4xv9FcaMmPhLjYPx7b",
    fingerprint: "dd38da6b",
    xprv: "tprv8icgpvtZmyKfXGDSpjvTxCHVSQRphz3o1R9JjA2HZ5frByVBCrNE945CsV8Z1xgqsBC7BQHMKcrWH4zSreE4RLsjRxNHg4d6ULj75y6xskC",
  },
  {
    descriptor:
      "[17e0c79d/48'/1'/0'/2']tpubDEJSWaFTtafGWu216Aj3JSL9ViZL1a6na8nDYofwqroUuyQUcPUv6zyuFUGavMUyuNuTB2452mwBiLqVnj1PtBJRod6MnwXySozdJanP7LK",
    fingerprint: "17e0c79d",
    xprv: "tprv8hcQNADDkCybdRzDCX4Su2g2vh3PrEuszqBSGHdeRb165V9hyzfKvWN35NmmsVGmqNh6cEVZ81UZqTmqUMRYQDAPqhs1PM1B1ugLVCY1Ar7",
  },
];

const TEST_SIGNER_DESCRIPTORS = TEST_SIGNERS.map((signer) => signer.descriptor);

function materializeMiniscriptTemplate(template: string, descriptors: readonly string[]): string {
  let result = template;
  for (const [index, descriptor] of descriptors.entries()) {
    result = result.replaceAll(`key_${index}`, `${descriptor}/<0;1>/*`);
  }
  return result;
}

function buildWalletDescriptorFromTemplate(
  template: string,
  descriptors: readonly string[],
): string {
  return withDescriptorChecksum(`wsh(${materializeMiniscriptTemplate(template, descriptors)})`);
}

const VARIANTS: VariantCase[] = [
  {
    name: "relative 2-of-3 threshold to single-key absolute fallback",
    miniscriptTemplate:
      "or_i(and_v(v:older(10),multi(2,key_0,key_1,key_2)),and_v(v:pk(key_3),after(144)))",
    walletDescriptor:
      "wsh(or_i(and_v(v:older(10),multi(2,[94334c52/48'/1'/0'/2']tpubDELqhHfquXR4mjoSjBm7FCyaMcd6zFoCiFSpvEQPwXr4oULNz9SozPgQvQGk3Sc8VxNtSbczDjhYQv95cpKR9FeCqWHEeL3395FohnX8KyD/<0;1>/*,[9b701d82/48'/1'/0'/2']tpubDEM4H9JMeDYxoj12zsMnfp4ESDkD6k4RBD7SBibX4Wk6Mme96633gfHkyhqHFewrHGoTbcEQ517STcEKBBg36o4D7BK6NCqTHmMoM7nUkRq/<0;1>/*,[a3fdcdd5/48'/1'/0'/2']tpubDEDtkrUUpfLYxoRG3NnwNYRB2V3ebaQFCYY9KyoPmaGHjY8vp2iwWiAJsNrV5PUTVvahfDvWK935T7hcjeHBNw9cJ2PmDKtueGuCykNEAr1/<0;1>/*)),and_v(v:pk([ec91de54/48'/1'/0'/2']tpubDE3GDWuTypP7WhPPzV75DJmt5fkUwAA2NUC1HkxQfu8HU1aP8grzSDRJKj35J8igq7dYGFKhN7k9NiHjvGVSaPHfyjNToDpTm15FMLyBKr2/<0;1>/*),after(144))))#7nrretyx",
    receiveAddresses: [
      "tb1qynzs7dnetqzsq0pdhh5f9y92zz6dy2d98wnudf3yr2ahn2f6n7tqzzh9zz",
      "tb1qpue7dxp6gm2j8k0583mkgymjnepk859xch2cvjv52x9leykc8t9q8ca89e",
    ],
    changeAddresses: ["tb1qmdd7ecn66cnwywty8ep3g88v7pawv2wesc4tjd9qtll9ldklru6s3spr27"],
    primary: {
      index: 0,
      lockTime: 0,
      requiredSignatures: 2,
      sequence: 10,
      signerIndexes: [0, 1],
      txSequence: 10,
    },
    timelocked: {
      index: 1,
      lockTime: 144,
      requiredSignatures: 1,
      sequence: 0,
      signerIndexes: [3],
      txSequence: 0xfffffffd,
    },
  },
  {
    name: "2-of-3 threshold to absolute 1-of-3 fallback",
    miniscriptTemplate:
      "or_i(multi(2,key_0,key_1,key_2),and_v(v:after(144),multi(1,key_1,key_2,key_3)))",
    walletDescriptor:
      "wsh(or_i(multi(2,[94334c52/48'/1'/0'/2']tpubDELqhHfquXR4mjoSjBm7FCyaMcd6zFoCiFSpvEQPwXr4oULNz9SozPgQvQGk3Sc8VxNtSbczDjhYQv95cpKR9FeCqWHEeL3395FohnX8KyD/<0;1>/*,[9b701d82/48'/1'/0'/2']tpubDEM4H9JMeDYxoj12zsMnfp4ESDkD6k4RBD7SBibX4Wk6Mme96633gfHkyhqHFewrHGoTbcEQ517STcEKBBg36o4D7BK6NCqTHmMoM7nUkRq/<0;1>/*,[a3fdcdd5/48'/1'/0'/2']tpubDEDtkrUUpfLYxoRG3NnwNYRB2V3ebaQFCYY9KyoPmaGHjY8vp2iwWiAJsNrV5PUTVvahfDvWK935T7hcjeHBNw9cJ2PmDKtueGuCykNEAr1/<0;1>/*),and_v(v:after(144),multi(1,[9b701d82/48'/1'/0'/2']tpubDEM4H9JMeDYxoj12zsMnfp4ESDkD6k4RBD7SBibX4Wk6Mme96633gfHkyhqHFewrHGoTbcEQ517STcEKBBg36o4D7BK6NCqTHmMoM7nUkRq/<0;1>/*,[a3fdcdd5/48'/1'/0'/2']tpubDEDtkrUUpfLYxoRG3NnwNYRB2V3ebaQFCYY9KyoPmaGHjY8vp2iwWiAJsNrV5PUTVvahfDvWK935T7hcjeHBNw9cJ2PmDKtueGuCykNEAr1/<0;1>/*,[ec91de54/48'/1'/0'/2']tpubDE3GDWuTypP7WhPPzV75DJmt5fkUwAA2NUC1HkxQfu8HU1aP8grzSDRJKj35J8igq7dYGFKhN7k9NiHjvGVSaPHfyjNToDpTm15FMLyBKr2/<0;1>/*))))#9nggh5n8",
    receiveAddresses: [
      "tb1q6turu58xkdcy9r2x2ape6wuyfx4f399k0gl0fsl3pxazk80kr2hqzlgt92",
      "tb1q3glt7545s2qh6ldzt42744grxhg6kggqpn7ta5dzkfk3ggklg7wq89jmr4",
    ],
    changeAddresses: ["tb1qxvmew8nyqg306svy0p8tyh8v3cwzr6mekx3e9xkxfcvs9c0650tql34y0z"],
    primary: {
      index: 0,
      lockTime: 0,
      requiredSignatures: 2,
      sequence: 0,
      signerIndexes: [0, 1],
      txSequence: 0xfffffffd,
    },
    timelocked: {
      index: 1,
      lockTime: 144,
      requiredSignatures: 1,
      sequence: 0,
      signerIndexes: [1],
      txSequence: 0xfffffffd,
    },
  },
  {
    name: "2-of-3 threshold to absolute 3-of-3 fallback",
    miniscriptTemplate:
      "or_i(and_v(v:after(200),multi(2,key_0,key_1,key_2)),and_v(v:after(144),multi(3,key_1,key_2,key_3)))",
    walletDescriptor:
      "wsh(or_i(and_v(v:after(200),multi(2,[94334c52/48'/1'/0'/2']tpubDELqhHfquXR4mjoSjBm7FCyaMcd6zFoCiFSpvEQPwXr4oULNz9SozPgQvQGk3Sc8VxNtSbczDjhYQv95cpKR9FeCqWHEeL3395FohnX8KyD/<0;1>/*,[9b701d82/48'/1'/0'/2']tpubDEM4H9JMeDYxoj12zsMnfp4ESDkD6k4RBD7SBibX4Wk6Mme96633gfHkyhqHFewrHGoTbcEQ517STcEKBBg36o4D7BK6NCqTHmMoM7nUkRq/<0;1>/*,[a3fdcdd5/48'/1'/0'/2']tpubDEDtkrUUpfLYxoRG3NnwNYRB2V3ebaQFCYY9KyoPmaGHjY8vp2iwWiAJsNrV5PUTVvahfDvWK935T7hcjeHBNw9cJ2PmDKtueGuCykNEAr1/<0;1>/*)),and_v(v:after(144),multi(3,[9b701d82/48'/1'/0'/2']tpubDEM4H9JMeDYxoj12zsMnfp4ESDkD6k4RBD7SBibX4Wk6Mme96633gfHkyhqHFewrHGoTbcEQ517STcEKBBg36o4D7BK6NCqTHmMoM7nUkRq/<0;1>/*,[a3fdcdd5/48'/1'/0'/2']tpubDEDtkrUUpfLYxoRG3NnwNYRB2V3ebaQFCYY9KyoPmaGHjY8vp2iwWiAJsNrV5PUTVvahfDvWK935T7hcjeHBNw9cJ2PmDKtueGuCykNEAr1/<0;1>/*,[ec91de54/48'/1'/0'/2']tpubDE3GDWuTypP7WhPPzV75DJmt5fkUwAA2NUC1HkxQfu8HU1aP8grzSDRJKj35J8igq7dYGFKhN7k9NiHjvGVSaPHfyjNToDpTm15FMLyBKr2/<0;1>/*))))#2k8mllpw",
    receiveAddresses: [
      "tb1qs2ds2r5w04n6uhs3z9jlj8aygx0wkzquzlq3jngkjscrtr056ues3tzcup",
      "tb1q3xpzxqmrcx9gagwlxjtgqx839kyq2g3gwt686harjdgyc6nny7rqjcpkhl",
    ],
    changeAddresses: ["tb1qzfe2sjtp9mmwa7rncq5mflgkjrkg8mclauawcfy6tm030d2hc4nqn3vlf2"],
    primary: {
      index: 0,
      lockTime: 200,
      requiredSignatures: 2,
      sequence: 0,
      signerIndexes: [0, 1],
      txSequence: 0xfffffffd,
    },
    timelocked: {
      index: 1,
      lockTime: 144,
      requiredSignatures: 3,
      sequence: 0,
      signerIndexes: [1, 2, 3],
      txSequence: 0xfffffffd,
    },
  },
  {
    name: "2-of-4 threshold to relative 2-of-2 fallback",
    miniscriptTemplate:
      "or_i(and_v(v:after(200),multi(2,key_0,key_1,key_2,key_3)),and_v(v:older(10),and_v(v:pk(key_0),pk(key_3))))",
    walletDescriptor:
      "wsh(or_i(and_v(v:after(200),multi(2,[94334c52/48'/1'/0'/2']tpubDELqhHfquXR4mjoSjBm7FCyaMcd6zFoCiFSpvEQPwXr4oULNz9SozPgQvQGk3Sc8VxNtSbczDjhYQv95cpKR9FeCqWHEeL3395FohnX8KyD/<0;1>/*,[9b701d82/48'/1'/0'/2']tpubDEM4H9JMeDYxoj12zsMnfp4ESDkD6k4RBD7SBibX4Wk6Mme96633gfHkyhqHFewrHGoTbcEQ517STcEKBBg36o4D7BK6NCqTHmMoM7nUkRq/<0;1>/*,[a3fdcdd5/48'/1'/0'/2']tpubDEDtkrUUpfLYxoRG3NnwNYRB2V3ebaQFCYY9KyoPmaGHjY8vp2iwWiAJsNrV5PUTVvahfDvWK935T7hcjeHBNw9cJ2PmDKtueGuCykNEAr1/<0;1>/*,[ec91de54/48'/1'/0'/2']tpubDE3GDWuTypP7WhPPzV75DJmt5fkUwAA2NUC1HkxQfu8HU1aP8grzSDRJKj35J8igq7dYGFKhN7k9NiHjvGVSaPHfyjNToDpTm15FMLyBKr2/<0;1>/*)),and_v(v:older(10),and_v(v:pk([94334c52/48'/1'/0'/2']tpubDELqhHfquXR4mjoSjBm7FCyaMcd6zFoCiFSpvEQPwXr4oULNz9SozPgQvQGk3Sc8VxNtSbczDjhYQv95cpKR9FeCqWHEeL3395FohnX8KyD/<0;1>/*),pk([ec91de54/48'/1'/0'/2']tpubDE3GDWuTypP7WhPPzV75DJmt5fkUwAA2NUC1HkxQfu8HU1aP8grzSDRJKj35J8igq7dYGFKhN7k9NiHjvGVSaPHfyjNToDpTm15FMLyBKr2/<0;1>/*)))))#vwhuueun",
    receiveAddresses: [
      "tb1qmrfyls2zrfzr4mdwh8hxwhtg4cyqlpx90958vcxjckwlt3ue9k6sy9mmkx",
      "tb1q7t0u03hwz856gm9hc0d3xzpgl7svhj7u8y3l97my99jc4srf8qysfk9tfs",
    ],
    changeAddresses: ["tb1qkchu3s5vdkxe8mr5kmrry6206yssjeg3zrwntl4nxkdugchm2l9scq4efd"],
    primary: {
      index: 0,
      lockTime: 200,
      requiredSignatures: 2,
      sequence: 0,
      signerIndexes: [0, 1],
      txSequence: 0xfffffffd,
    },
    timelocked: {
      index: 1,
      lockTime: 0,
      requiredSignatures: 2,
      sequence: 10,
      signerIndexes: [0, 3],
      txSequence: 10,
    },
  },
];

function createFundingHex(address: string, amount: bigint): { rawHex: string; txid: string } {
  const tx = new Transaction();
  tx.addInput({ txid: "00".repeat(32), index: 0, sequence: 0xfffffffd });
  tx.addOutputAddress(address, amount, TEST_NETWORK);
  return {
    rawHex: Buffer.from(tx.unsignedTx).toString("hex"),
    txid: tx.id,
  };
}

function createMiniscriptElectrumMock(
  descriptor: string,
  fundingAmount: bigint,
  height = 200,
): ElectrumClient {
  const receiveAddress = deriveDescriptorAddresses(descriptor, "testnet", 0, 0, 1)[0];
  const { rawHex, txid } = createFundingHex(receiveAddress, fundingAmount);
  const scripthash = addressToScripthash(receiveAddress, "testnet");
  const getTransaction = vi.fn(async (hash: string) => {
    if (hash !== txid) {
      throw new Error("unknown tx");
    }
    return rawHex;
  });
  const listUnspent = vi.fn(async (hash: string) =>
    hash === scripthash ? [{ tx_hash: txid, tx_pos: 0, height, value: Number(fundingAmount) }] : [],
  );
  const getHistory = vi.fn(async (hash: string) =>
    hash === scripthash ? [{ tx_hash: txid, height }] : [],
  );

  return {
    estimateFee: vi.fn(async () => 0.00001),
    getTransaction,
    getTransactionBatch: vi.fn(async (hashes: string[]) => Promise.all(hashes.map(getTransaction))),
    listUnspent,
    listUnspentBatch: vi.fn(async (hashes: string[]) => Promise.all(hashes.map(listUnspent))),
    getHistory,
    getHistoryBatch: vi.fn(async (hashes: string[]) => Promise.all(hashes.map(getHistory))),
  } as unknown as ElectrumClient;
}

function createWallet(descriptor: string): WalletData {
  return {
    walletId: "four-key-miniscript",
    groupId: "test-group",
    gid: "test-gid",
    name: "Four-key miniscript",
    m: 0,
    n: TEST_SIGNERS.length,
    addressType: "NATIVE_SEGWIT",
    descriptor,
    signers: TEST_SIGNERS.map((signer) => signer.descriptor),
    secretboxKey: "test",
    createdAt: "2026-04-14T00:00:00.000Z",
  };
}

function signWithVariantSigner(tx: Transaction, signer: VariantSigner, descriptor: string): number {
  return signWalletPsbtWithKey(
    tx,
    HDKey.fromExtendedKey(signer.xprv, TESTNET_VERSIONS),
    parseInt(signer.fingerprint, 16),
    descriptor,
  );
}

async function createAndFinalize(
  variant: VariantCase,
  branch: VariantBranch,
  miniscriptPath?: number,
): Promise<void> {
  const signingWalletDescriptor = buildWalletDescriptorFromTemplate(
    variant.miniscriptTemplate,
    TEST_SIGNER_DESCRIPTORS,
  );
  const wallet = createWallet(signingWalletDescriptor);
  const electrum = createMiniscriptElectrumMock(signingWalletDescriptor, 80_000n);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = vi.fn(async () => {
    throw new Error("offline");
  }) as typeof fetch;

  try {
    const result = await createTransaction({
      wallet,
      network: "testnet",
      electrum,
      toAddress: TEST_RECIPIENT,
      amount: 10_000n,
      miniscriptPath,
    });
    const tx = Transaction.fromPSBT(Buffer.from(result.psbtB64, "base64"));

    expect(result.miniscriptPath).toMatchObject({
      index: branch.index,
      lockTime: branch.lockTime,
      requiredSignatures: branch.requiredSignatures,
      sequence: branch.sequence,
    });
    expect(tx.lockTime).toBe(branch.lockTime);
    expect(tx.getInput(0).sequence).toBe(branch.txSequence);

    for (const signerIndex of branch.signerIndexes) {
      expect(signWithVariantSigner(tx, TEST_SIGNERS[signerIndex], signingWalletDescriptor)).toBe(1);
    }

    expect(finalizeMiniscriptPsbt(tx, signingWalletDescriptor, "testnet")).toMatchObject({
      requiredSignatures: branch.requiredSignatures,
    });
    expect(tx.isFinal).toBe(true);
    expect(() => tx.extract()).not.toThrow();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

describe("four-key miniscript variants", () => {
  it.each(VARIANTS)("$name derives deterministic local-key addresses", (variant) => {
    expect(variant.walletDescriptor).toContain(
      `wsh(${materializeMiniscriptTemplate(variant.miniscriptTemplate, LOCAL_KEY_DESCRIPTORS)})#`,
    );
    expect(deriveDescriptorAddresses(variant.walletDescriptor, "testnet", 0, 0, 2)).toEqual(
      variant.receiveAddresses,
    );
    expect(deriveDescriptorAddresses(variant.walletDescriptor, "testnet", 1, 0, 1)).toEqual(
      variant.changeAddresses,
    );
  });

  it.each(VARIANTS)(
    "$name signs and finalizes its default branch",
    async (variant) => createAndFinalize(variant, variant.primary),
    10_000,
  );

  it.each(VARIANTS)(
    "$name signs and finalizes its timelocked branch",
    async (variant) => createAndFinalize(variant, variant.timelocked, variant.timelocked.index),
    10_000,
  );
});
