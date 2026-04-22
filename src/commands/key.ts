import { Command } from "commander";
import { HDKey } from "@scure/bip32";
import { print, printError, printTable } from "../output.js";
import { requireEmail, getNetwork } from "../core/config.js";
import { ADDRESS_TYPES, parseAddressTypeInput, type AddressType } from "../core/address-type.js";
import {
  generateMnemonic24,
  generateMnemonic12,
  checkMnemonic,
  mnemonicToRootKey,
  getMasterFingerprint,
  getSignerInfo,
  getXpubAtPath,
} from "../core/keygen.js";
import { MAINNET_VERSIONS, TESTNET_VERSIONS } from "../core/address.js";
import { saveKey, listKeys } from "../core/storage.js";

export const keyCommand = new Command("key").description("Key generation and derivation");

keyCommand
  .command("generate")
  .description("Generate a new BIP39 mnemonic and save to local storage")
  .option("--name <name>", "Name for the key (default: My key #N)")
  .option("--words <count>", "Number of words (12 or 24)", "24")
  .action((options, cmd) => {
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const email = requireEmail();

    const words = parseInt(options.words, 10);
    if (words !== 12 && words !== 24) {
      printError({ error: "INVALID_PARAM", message: "--words must be 12 or 24" }, cmd);
      return;
    }

    const name = options.name || `My key #${listKeys(email, network).length + 1}`;
    const mnemonic = words === 24 ? generateMnemonic24() : generateMnemonic12();
    const rootKey = mnemonicToRootKey(mnemonic, network);
    const fingerprint = getMasterFingerprint(rootKey);

    saveKey(email, network, {
      name,
      mnemonic,
      fingerprint,
      createdAt: new Date().toISOString(),
    });

    if (globals.json) {
      print({ mnemonic, name, fingerprint }, cmd);
    } else {
      console.log("");
      console.log("MNEMONIC (back up these words securely!):");
      console.log(`  ${mnemonic}`);
      console.log("");
      console.log(`Name:          ${name}`);
      console.log(`Fingerprint:   ${fingerprint}`);
      console.log("");
    }
  });

// key info — derive signer info from a stored key, provided mnemonic, or master xprv.
//
// Use cases:
//   1. Derive info from a stored key by fingerprint:
//        nunchuk key info --fingerprint 73c5da0a
//
//   2. Derive info from a provided mnemonic:
//        nunchuk key info --mnemonic "word1 word2 ... word24"
//
//   3. Import a mnemonic that was created with a BIP39 passphrase:
//        nunchuk key info --mnemonic "word1 ..." --passphrase "secret"
//
//   4. Derive info from a master xprv (e.g. exported from another tool):
//        nunchuk key info --xprv xprv...
//
//   5. Derive at a custom path instead of the default multi-sig path:
//        nunchuk key info --fingerprint 73c5da0a --path "m/48'/0'/1'/2'"
keyCommand
  .command("info")
  .description("Derive signer info from a stored key, mnemonic, or master xprv")
  .option("--fingerprint <xfp>", "Fingerprint of a stored key")
  .option("--mnemonic <words>", "BIP39 mnemonic (space-separated, wrap in quotes)")
  .option("--xprv <xprv>", "BIP32 master extended private key (depth-0)")
  .option("--passphrase <passphrase>", "BIP39 passphrase (only with --mnemonic)")
  .option("--address-type <type>", `Address type: ${ADDRESS_TYPES.join(", ")}`, "NATIVE_SEGWIT")
  .option("--path <path>", "Custom derivation path (overrides --address-type)")
  .action((options, cmd) => {
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const email = requireEmail();

    // Resolve root key from one of: --fingerprint, --mnemonic, --xprv
    const sourceCount = [options.fingerprint, options.mnemonic, options.xprv].filter(
      Boolean,
    ).length;
    if (sourceCount === 0) {
      printError(
        { error: "MISSING_PARAM", message: "Provide --fingerprint, --mnemonic, or --xprv" },
        cmd,
      );
      return;
    }
    if (sourceCount > 1) {
      printError(
        {
          error: "INVALID_PARAM",
          message: "Provide only one of --fingerprint, --mnemonic, or --xprv",
        },
        cmd,
      );
      return;
    }

    let rootKey: HDKey;

    if (options.fingerprint) {
      const stored = listKeys(email, network).find((k) => k.fingerprint === options.fingerprint);
      if (!stored) {
        printError({ error: "NOT_FOUND", message: `Key ${options.fingerprint} not found` }, cmd);
        return;
      }
      rootKey = mnemonicToRootKey(stored.mnemonic, network);
    } else if (options.mnemonic) {
      if (!checkMnemonic(options.mnemonic)) {
        printError({ error: "INVALID_MNEMONIC", message: "Invalid BIP39 mnemonic" }, cmd);
        return;
      }
      rootKey = mnemonicToRootKey(options.mnemonic, network, options.passphrase);
    } else {
      try {
        const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
        rootKey = HDKey.fromExtendedKey(options.xprv, versions);
      } catch {
        printError({ error: "INVALID_XPRV", message: "Invalid BIP32 extended private key" }, cmd);
        return;
      }
    }

    const fingerprint = getMasterFingerprint(rootKey);

    if (options.path) {
      // Custom path mode
      const xpub = getXpubAtPath(rootKey, options.path);
      const normalizedPath = options.path.replace(/^m/, "");
      const descriptor = `[${fingerprint}${normalizedPath}]${xpub}`;

      if (globals.json) {
        print({ fingerprint, network, path: options.path, xpub, descriptor }, cmd);
      } else {
        console.log("");
        console.log(`Fingerprint:   ${fingerprint}`);
        console.log(`Network:       ${network}`);
        console.log(`Path:          ${options.path}`);
        console.log(`Xpub:          ${xpub}`);
        console.log(`Descriptor:    ${descriptor}`);
        console.log("");
      }
    } else {
      // Standard multi-sig path
      const addressType = parseAddressTypeInput(options.addressType);
      const info = getSignerInfo(rootKey, network, addressType);

      if (globals.json) {
        print(
          {
            fingerprint: info.fingerprint,
            network,
            addressType,
            path: info.path,
            xpub: info.xpub,
            descriptor: info.descriptor,
          },
          cmd,
        );
      } else {
        console.log("");
        console.log(`Fingerprint:   ${info.fingerprint}`);
        console.log(`Network:       ${network}`);
        console.log(`Address Type:  ${addressType}`);
        console.log(`Path:          ${info.path}`);
        console.log(`Xpub:          ${info.xpub}`);
        console.log(`Descriptor:    ${info.descriptor}`);
        console.log("");
      }
    }
  });

keyCommand
  .command("list")
  .description("List locally stored keys")
  .action((_options, cmd) => {
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const email = requireEmail();
    const keys = listKeys(email, network);

    if (keys.length === 0) {
      print({ message: "No keys found" }, cmd);
      return;
    }

    const rows = keys.map((k) => ({
      name: k.name,
      fingerprint: k.fingerprint,
      createdAt: k.createdAt,
    }));

    if (globals.json) {
      print(rows, cmd);
    } else {
      printTable(rows);
    }
  });
