import { Command } from "commander";
import { HDKey } from "@scure/bip32";
import { print, printError, printTable } from "../output.js";
import { requireEmail, getNetwork } from "../core/config.js";
import { ADDRESS_TYPES, parseAddressTypeInput } from "../core/address-type.js";
import {
  generateMnemonic24,
  generateMnemonic12,
  checkMnemonic,
  mnemonicToRootKey,
  getMasterFingerprint,
  getSignerInfo,
  getXpubAtPath,
  normalizeDerivationPath,
} from "../core/keygen.js";
import { MAINNET_VERSIONS, TESTNET_VERSIONS } from "../core/address.js";
import { saveKey, listKeys } from "../core/storage.js";
import {
  isInteractiveInput,
  isInteractiveOutput,
  promptSecret,
  readSecretFromFile,
  readStdinLines,
  warnSecretsOnCommandLine,
} from "../core/prompt.js";

function normalizeMnemonic(words: string): string {
  return words.trim().replace(/\s+/g, " ");
}

export const keyCommand = new Command("key").description("Key generation and derivation");

keyCommand
  .command("generate")
  .description("Generate a new BIP39 mnemonic and save to local storage")
  .option("--name <name>", "Name for the key (default: My key #N)")
  .option("--words <count>", "Number of words (12 or 24)", "24")
  .option(
    "--show-mnemonic",
    "Print the seed words even when output is not a terminal (a pipe, a file, an agent)",
  )
  .action((options, cmd) => {
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const email = requireEmail();

    const words = parseInt(options.words, 10);
    if (words !== 12 && words !== 24) {
      printError({ error: "INVALID_PARAM", message: "--words must be 12 or 24" }, cmd);
      return;
    }

    // The seed words are printed exactly once, at generation, and are the only
    // way to back the key up. When output is a pipe nobody may be reading them,
    // so refuse (before creating anything) unless the caller opts in.
    if (!options.showMnemonic && !isInteractiveOutput()) {
      printError(
        {
          error: "NOT_INTERACTIVE",
          message:
            "key generate prints seed words that must be backed up. Run it at a terminal, or pass --show-mnemonic if you accept the words going to this output.",
        },
        cmd,
      );
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

keyCommand
  .command("import")
  .description("Import an existing BIP39 mnemonic and save to local storage")
  .argument("[words...]", "BIP39 mnemonic words (omit to be prompted, or use --stdin / --file)")
  .option("--name <name>", "Name for the key (default: My key #N)")
  .option("--stdin", "Read the mnemonic from the first line of standard input")
  .option("--file <path>", "Read the mnemonic from a file")
  .action(async (words: string[], options, cmd) => {
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const email = requireEmail(globals.network);

    const sourceCount = [words.length > 0, Boolean(options.stdin), Boolean(options.file)].filter(
      Boolean,
    ).length;
    if (sourceCount > 1) {
      printError(
        {
          error: "INVALID_PARAM",
          message: "Provide the seed words in one way only: as arguments, --stdin, or --file",
        },
        cmd,
      );
      return;
    }

    let rawMnemonic: string;
    try {
      if (words.length > 0) {
        warnSecretsOnCommandLine(["seed words"], "nunchuk key import (prompt), --stdin, or --file");
        rawMnemonic = words.join(" ");
      } else if (options.stdin) {
        rawMnemonic = (await readStdinLines(1))[0];
      } else if (options.file) {
        rawMnemonic = readSecretFromFile(options.file);
      } else if (isInteractiveInput()) {
        rawMnemonic = await promptSecret("Enter seed words: ");
      } else {
        printError(
          {
            error: "MISSING_PARAM",
            message:
              "No seed words given and standard input is not a terminal. Use --stdin or --file.",
          },
          cmd,
        );
        return;
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
      return;
    }
    const mnemonic = normalizeMnemonic(rawMnemonic);

    if (!checkMnemonic(mnemonic)) {
      printError({ error: "INVALID_MNEMONIC", message: "Invalid BIP39 mnemonic" }, cmd);
      return;
    }

    const rootKey = mnemonicToRootKey(mnemonic, network);
    const fingerprint = getMasterFingerprint(rootKey);
    const keys = listKeys(email, network);

    if (keys.some((key) => key.fingerprint.toLowerCase() === fingerprint)) {
      printError({ error: "ALREADY_EXISTS", message: `Key ${fingerprint} already exists` }, cmd);
      return;
    }

    const name = options.name || `My key #${keys.length + 1}`;
    saveKey(email, network, {
      name,
      mnemonic,
      fingerprint,
      createdAt: new Date().toISOString(),
    });

    if (globals.json) {
      print({ status: "imported", name, fingerprint }, cmd);
    } else {
      console.log("");
      console.log("Key imported to local storage.");
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
  .option("--passphrase <passphrase>", "BIP39 passphrase (only with a mnemonic)")
  .option("--mnemonic-stdin", "Read the mnemonic from standard input (line 1)")
  .option("--xprv-stdin", "Read the master xprv from standard input (line 1)")
  .option(
    "--passphrase-stdin",
    "Read the BIP39 passphrase from standard input (line 2 when the key also comes from stdin)",
  )
  .option("--passphrase-prompt", "Ask for the BIP39 passphrase at a masked prompt")
  .option("--address-type <type>", `Address type: ${ADDRESS_TYPES.join(", ")}`, "NATIVE_SEGWIT")
  .option("--path <path>", "Custom derivation path (overrides --address-type)")
  .action(async (options, cmd) => {
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const email = requireEmail();

    const usesStdin = Boolean(
      options.mnemonicStdin || options.xprvStdin || options.passphraseStdin,
    );
    if (options.passphrasePrompt && usesStdin) {
      printError(
        {
          error: "INVALID_PARAM",
          message:
            "--passphrase-prompt needs the keyboard; use --passphrase-stdin when the seed words come from standard input",
        },
        cmd,
      );
      return;
    }
    if (
      [options.passphrase, options.passphraseStdin, options.passphrasePrompt].filter(Boolean)
        .length > 1
    ) {
      printError(
        {
          error: "INVALID_PARAM",
          message:
            "Provide the passphrase in one way only: --passphrase, --passphrase-stdin, or --passphrase-prompt",
        },
        cmd,
      );
      return;
    }

    // Resolve the key source: --fingerprint, --mnemonic, --mnemonic-stdin, --xprv, --xprv-stdin,
    // or (at a terminal) a masked prompt for the mnemonic.
    const sourceCount = [
      options.fingerprint,
      options.mnemonic,
      options.mnemonicStdin,
      options.xprv,
      options.xprvStdin,
    ].filter(Boolean).length;
    if (sourceCount > 1) {
      printError(
        {
          error: "INVALID_PARAM",
          message:
            "Provide only one of --fingerprint, --mnemonic, --mnemonic-stdin, --xprv, or --xprv-stdin",
        },
        cmd,
      );
      return;
    }

    const onCommandLine: string[] = [];
    if (options.mnemonic) onCommandLine.push("--mnemonic");
    if (options.xprv) onCommandLine.push("--xprv");
    if (options.passphrase) onCommandLine.push("--passphrase");
    warnSecretsOnCommandLine(onCommandLine, "the -stdin options or the prompt");

    let mnemonic: string | undefined = options.mnemonic;
    let xprv: string | undefined = options.xprv;
    let passphrase: string | undefined = options.passphrase;
    try {
      const lineCount =
        (options.mnemonicStdin || options.xprvStdin ? 1 : 0) + (options.passphraseStdin ? 1 : 0);
      if (lineCount > 0) {
        const lines = await readStdinLines(lineCount);
        let i = 0;
        if (options.mnemonicStdin) mnemonic = lines[i++];
        if (options.xprvStdin) xprv = lines[i++];
        if (options.passphraseStdin) passphrase = lines[i++];
      }
      if (sourceCount === 0) {
        if (!isInteractiveInput()) {
          printError(
            {
              error: "MISSING_PARAM",
              message:
                "Provide --fingerprint, --mnemonic, --mnemonic-stdin, --xprv, or --xprv-stdin",
            },
            cmd,
          );
          return;
        }
        mnemonic = await promptSecret("Enter seed words: ");
      }
      if (options.passphrasePrompt) {
        if (!isInteractiveInput()) {
          printError(
            {
              error: "INVALID_PARAM",
              message: "--passphrase-prompt needs an interactive terminal; use --passphrase-stdin",
            },
            cmd,
          );
          return;
        }
        passphrase = await promptSecret("Enter BIP39 passphrase: ");
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
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
    } else if (mnemonic !== undefined) {
      mnemonic = normalizeMnemonic(mnemonic);
      if (!checkMnemonic(mnemonic)) {
        printError({ error: "INVALID_MNEMONIC", message: "Invalid BIP39 mnemonic" }, cmd);
        return;
      }
      rootKey = mnemonicToRootKey(mnemonic, network, passphrase);
    } else {
      try {
        const versions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
        rootKey = HDKey.fromExtendedKey(xprv ?? "", versions);
      } catch {
        printError({ error: "INVALID_XPRV", message: "Invalid BIP32 extended private key" }, cmd);
        return;
      }
    }

    const fingerprint = getMasterFingerprint(rootKey);

    if (options.path) {
      // Custom path mode
      const path = normalizeDerivationPath(options.path);
      let xpub: string;
      try {
        xpub = getXpubAtPath(rootKey, path);
      } catch {
        printError(
          { error: "INVALID_PATH", message: `Invalid derivation path: ${options.path}` },
          cmd,
        );
        return;
      }
      const normalizedPath = path.replace(/^m/, "");
      const descriptor = `[${fingerprint}${normalizedPath}]${xpub}`;

      if (globals.json) {
        print({ fingerprint, network, path, xpub, descriptor }, cmd);
      } else {
        console.log("");
        console.log(`Fingerprint:   ${fingerprint}`);
        console.log(`Network:       ${network}`);
        console.log(`Path:          ${path}`);
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
