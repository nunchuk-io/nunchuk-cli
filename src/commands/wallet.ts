import fs from "node:fs";
import { Command, InvalidArgumentError } from "commander";
import { requireApiKey, requireEmail, getNetwork, getElectrumServer } from "../core/config.js";
import type { Network } from "../core/config.js";
import { ApiClient } from "../core/api-client.js";
import { formatAddressType } from "../core/address-type.js";
import { listWallets, loadWallet, removeWallet, saveWallet } from "../core/storage.js";
import type { WalletData } from "../core/storage.js";
import { print, printError, printTable, printWalletResult } from "../output.js";
import {
  buildWalletDescriptorForParsed,
  buildExternalDescriptorForParsed,
  buildAnyDescriptorForParsed,
  parseDescriptor,
  parseBsmsRecord,
} from "../core/descriptor.js";
import { buildMultisigConfig, parseMultisigConfig } from "../core/multisig-config.js";
import { deriveFirstAddress } from "../core/address.js";
import {
  MINISCRIPT_ADDRESS_TYPE_ANY,
  MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
  MINISCRIPT_ADDRESS_TYPE_TAPROOT,
  buildMiniscriptDescriptor,
  type MiniscriptAddressType,
  validateMiniscriptTemplate,
} from "../core/miniscript.js";
import {
  formatMiniscriptPreimageRequirement,
  type MiniscriptPreimageRequirement,
} from "../core/miniscript-preimage.js";
import { describeMiniscriptSpendingPlans } from "../core/miniscript-spend.js";
import { resolveSignerKeys } from "../core/signer-key.js";
import { recoverWallet } from "../core/wallet.js";
import { ElectrumClient } from "../core/electrum.js";
import { getNextReceiveAddress, getWalletBalance } from "../core/transaction.js";
import { formatBtc } from "../core/format.js";
import { signWalletPsbtWithKey } from "../core/psbt-sign.js";
import {
  getWalletPlatformKeyConfig,
  buildGlobalPolicyFromFlags,
  buildSignerPolicyFromFlags,
  mergePolicies,
  parseSigningDelayInput,
  parsePolicyJson,
  validateWalletPolicies,
  type PlatformKeyPolicies,
  type PolicyFlagOptions,
  requestPlatformKeyPolicyUpdate,
  fetchDummyTransactions,
  fetchDummyTransaction,
  signDummyTransaction,
  cancelDummyTransaction,
  createDummyPsbt,
  extractPartialSignature,
  formatPoliciesText,
} from "../core/platform-key.js";

export const walletCommand = new Command("wallet").description("Manage finalized group wallets");

function parseSigningDelayOption(value: string): number {
  try {
    return parseSigningDelayInput(value);
  } catch (err) {
    throw new InvalidArgumentError((err as Error).message);
  }
}

function looksLikeMultisigConfig(content: string): boolean {
  return (
    /(^|\n)\s*(name|policy|format|derivation)\s*:/i.test(content) ||
    /(^|\n)\s*[0-9a-fA-F]{8}\s*:/i.test(content)
  );
}
function parseMiniscriptAddressTypeOption(value: string): MiniscriptAddressType {
  const upper = value.toUpperCase().replace(/-/g, "_");

  if (upper === "ANY") {
    return MINISCRIPT_ADDRESS_TYPE_ANY;
  }
  if (upper === "NATIVE_SEGWIT") {
    return MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT;
  }
  if (upper === "TAPROOT") {
    return MINISCRIPT_ADDRESS_TYPE_TAPROOT;
  }

  throw new InvalidArgumentError(
    `Invalid miniscript address type: ${value}. Use ANY, NATIVE_SEGWIT, or TAPROOT`,
  );
}

function parseNonNegativeIntegerOption(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new InvalidArgumentError(`${label} must be a non-negative integer`);
  }
  return parsed;
}

function parseMiniscriptTimelockOption(value: string): number {
  return parseNonNegativeIntegerOption(value, "--locktime");
}

function parseMiniscriptSequenceOption(value: string): number {
  return parseNonNegativeIntegerOption(value, "--sequence");
}
function formatWalletOutput<T extends { addressType?: number }>(
  wallet: T,
):
  | T
  | (Omit<T, "addressType"> & {
      addressType?: number | string;
    }) {
  if (wallet.addressType == null) {
    return wallet;
  }

  return {
    ...wallet,
    addressType: formatAddressType(wallet.addressType),
  };
}

function parseWalletDescriptor(wallet: WalletData) {
  return parseDescriptor(wallet.descriptor);
}

function getWalletTypeLabel(wallet: WalletData): string {
  return parseWalletDescriptor(wallet).kind === "miniscript"
    ? "MINISCRIPT"
    : `${wallet.m}-of-${wallet.n}`;
}

function toWalletView(wallet: WalletData) {
  const { gid: _gid, secretboxKey: _secretboxKey, descriptor: _descriptor, ...walletView } = wallet;

  return { ...walletView, typeLabel: getWalletTypeLabel(wallet) };
}

function formatMiniscriptSignerName(value: string): string {
  const match = value.match(/^\[([0-9a-fA-F]{8})/);
  return match ? match[1].toLowerCase() : value;
}

function printMiniscriptPlanTable(
  plans: Array<{
    index: number;
    supported: boolean;
    satisfiable: boolean;
    preimageRequirements: MiniscriptPreimageRequirement[];
    requiredSignatures: number;
    lockTime: number;
    sequence: number;
    signerNames: string[];
    unsupportedReason?: string;
  }>,
): void {
  printTable(
    plans.map((plan) => ({
      path: plan.index,
      supported: plan.supported ? "yes" : "no",
      satisfiable: plan.satisfiable ? "yes" : "no",
      required: plan.requiredSignatures,
      lockTime: plan.lockTime,
      sequence: plan.sequence,
      preimages:
        plan.preimageRequirements.length > 0
          ? plan.preimageRequirements.map(formatMiniscriptPreimageRequirement).join(",")
          : "(none)",
      signers:
        plan.signerNames.length > 0
          ? plan.signerNames.map(formatMiniscriptSignerName).join(",")
          : "(none)",
      reason: plan.unsupportedReason ?? "",
    })),
  );
}

walletCommand
  .command("list")
  .description("List wallets")
  .option("--no-balance", "Skip balance lookup")
  .action(async (options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const wallets = listWallets(email, network);
      if (wallets.length === 0) {
        print({ message: "No wallets found" }, cmd);
        return;
      }

      if (options.balance !== false) {
        const server = getElectrumServer(network);
        const electrum = new ElectrumClient();
        try {
          await electrum.connect(server.host, server.port, server.protocol);
          await electrum.serverVersion("nunchuk-cli", "1.4");

          const results = [];
          for (const w of wallets) {
            results.push({
              walletId: w.walletId,
              name: w.name,
              type: getWalletTypeLabel(w),
              balance: formatBtc(await getWalletBalance(w, network, electrum)),
              createdAt: w.createdAt,
            });
          }
          if (globals.json) {
            print(results, cmd);
          } else {
            printTable(results);
          }
        } finally {
          electrum.close();
        }
        return;
      }

      const results = wallets.map((w) => ({
        walletId: w.walletId,
        name: w.name,
        type: getWalletTypeLabel(w),
        createdAt: w.createdAt,
      }));
      if (globals.json) {
        print(results, cmd);
      } else {
        printTable(results);
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

walletCommand
  .command("get")
  .description("Get wallet details")
  .argument("<wallet-id>", "Wallet ID")
  .option("--no-balance", "Skip balance lookup")
  .action(async (walletId, options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const wallet = loadWallet(email, network, walletId);
      if (!wallet) {
        printError({ error: "NOT_FOUND", message: `Wallet ${walletId} not found locally` }, cmd);
        return;
      }

      const walletView = toWalletView(wallet);
      const client = new ApiClient(requireApiKey(globals.apiKey, globals.network), network);
      const pkConfig = await getWalletPlatformKeyConfig(client, wallet);

      if (options.balance !== false) {
        const server = getElectrumServer(network);
        const electrum = new ElectrumClient();
        try {
          await electrum.connect(server.host, server.port, server.protocol);
          await electrum.serverVersion("nunchuk-cli", "1.4");
          const balance = await getWalletBalance(wallet, network, electrum);
          printWalletResult(
            {
              ...walletView,
              balance: formatBtc(balance),
              platformKey: pkConfig.platformKey ?? undefined,
            },
            cmd,
          );
        } finally {
          electrum.close();
        }
        return;
      }

      printWalletResult({ ...walletView, platformKey: pkConfig.platformKey ?? undefined }, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

walletCommand
  .command("address")
  .description("Wallet address operations")
  .command("get")
  .description("Get a new receive address")
  .argument("<wallet-id>", "Wallet ID")
  .action(async (walletId, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const wallet = loadWallet(email, network, walletId);
      if (!wallet) {
        printError({ error: "NOT_FOUND", message: `Wallet ${walletId} not found locally` }, cmd);
        return;
      }

      const server = getElectrumServer(network);
      const electrum = new ElectrumClient();
      try {
        await electrum.connect(server.host, server.port, server.protocol);
        await electrum.serverVersion("nunchuk-cli", "1.4");
        print(await getNextReceiveAddress(wallet, network, electrum), cmd);
      } finally {
        electrum.close();
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

walletCommand
  .command("export")
  .description("Export wallet descriptor, multisig config, or BSMS record")
  .argument("<wallet-id>", "Local wallet ID")
  .option(
    "--type <type>",
    "Export type: descriptor (default), multisig-config, or bsms",
    "descriptor",
  )
  .option(
    "--format <format>",
    "Descriptor format: internal (default, BIP-389) or all (/0/*)",
    "internal",
  )
  .action(async (walletId, options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const wallet = loadWallet(email, network, walletId);
      if (!wallet) {
        printError({ error: "NOT_FOUND", message: `Wallet ${walletId} not found locally` }, cmd);
        return;
      }

      const type = options.type as string;
      const format = options.format as string;

      if (!["descriptor", "multisig-config", "bsms"].includes(type)) {
        printError(
          {
            error: "INVALID_TYPE",
            message: `Unknown type: ${type}. Use descriptor, multisig-config, or bsms`,
          },
          cmd,
        );
        return;
      }
      if (!["internal", "all"].includes(format)) {
        printError(
          { error: "INVALID_FORMAT", message: `Unknown format: ${format}. Use internal or all` },
          cmd,
        );
        return;
      }
      if (type !== "descriptor" && format !== "internal") {
        printError(
          { error: "INVALID_OPTION", message: "--format is only valid with --type descriptor" },
          cmd,
        );
        return;
      }

      const parsed = parseWalletDescriptor(wallet);

      if (type === "descriptor") {
        const descriptor =
          format === "all"
            ? buildExternalDescriptorForParsed(parsed)
            : buildWalletDescriptorForParsed(parsed);

        if (globals.json) {
          print({ descriptor }, cmd);
        } else {
          console.log(descriptor);
          console.error(
            "\nTip: Save to file for recovery: nunchuk wallet export <id> > wallet-backup.txt",
          );
        }
      } else if (type === "multisig-config") {
        const multisigConfig = buildMultisigConfig(
          wallet.name,
          wallet.signers,
          wallet.m,
          wallet.n,
          wallet.addressType,
        );

        if (globals.json) {
          print({ multisigConfig }, cmd);
        } else {
          console.log(multisigConfig);
          console.error(
            "\nTip: Save to file for multisig config import: nunchuk wallet export <id> --type multisig-config > wallet-backup.txt",
          );
        }
      } else {
        if (parsed.kind !== "multisig") {
          printError(
            {
              error: "UNSUPPORTED",
              message: "BSMS export is only supported for multisig wallets",
            },
            cmd,
          );
          return;
        }

        const bsms = {
          version: "BSMS 1.0",
          descriptor: buildAnyDescriptorForParsed(parsed),
          pathRestrictions: "No path restrictions",
          firstAddress: deriveFirstAddress(wallet.signers, wallet.m, wallet.addressType, network),
        };

        if (globals.json) {
          print(bsms, cmd);
        } else {
          console.log(bsms.version);
          console.log(bsms.descriptor);
          console.log(bsms.pathRestrictions);
          console.log(bsms.firstAddress);
          console.error(
            "\nTip: Save to file for recovery: nunchuk wallet export <id> --type bsms > wallet-backup.bsms",
          );
        }
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

const miniscriptCommand = walletCommand
  .command("miniscript")
  .description("Inspect and validate miniscript wallets and descriptors");

miniscriptCommand
  .command("inspect")
  .description("Inspect miniscript signing paths for a wallet")
  .argument("<wallet-id>", "Wallet ID")
  .option(
    "--locktime <value>",
    "Evaluate satisfiability at this locktime",
    parseMiniscriptTimelockOption,
  )
  .option(
    "--sequence <value>",
    "Evaluate satisfiability at this input sequence",
    parseMiniscriptSequenceOption,
  )
  .action((walletId, options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const wallet = loadWallet(email, network, walletId);
      if (!wallet) {
        printError({ error: "NOT_FOUND", message: `Wallet ${walletId} not found locally` }, cmd);
        return;
      }

      const parsed = parseWalletDescriptor(wallet);
      if (parsed.kind !== "miniscript" || !parsed.miniscript) {
        printError(
          {
            error: "UNSUPPORTED",
            message: "Wallet is not a miniscript wallet",
          },
          cmd,
        );
        return;
      }

      const hasTxState = options.locktime != null || options.sequence != null;
      const txState = hasTxState
        ? {
            lockTime: options.locktime ?? 0,
            inputs: [{ nSequence: options.sequence ?? 0 }],
          }
        : undefined;
      const plans = describeMiniscriptSpendingPlans(parsed.miniscript, txState);
      const result = {
        walletId: wallet.walletId,
        name: wallet.name,
        addressType: formatAddressType(parsed.addressType),
        miniscript: parsed.miniscript,
        txState: txState
          ? { lockTime: txState.lockTime, sequence: txState.inputs[0].nSequence }
          : undefined,
        paths: plans.map((plan) => ({
          index: plan.index,
          supported: plan.supported,
          satisfiable: plan.satisfiable,
          preimageRequirements: plan.preimageRequirements,
          requiredSignatures: plan.requiredSignatures,
          lockTime: plan.lockTime,
          sequence: plan.sequence,
          signerNames: plan.signerNames,
          unsupportedReason: plan.unsupportedReason,
        })),
      };

      if (globals.json) {
        print(result, cmd);
        return;
      }

      console.log(`Wallet: ${wallet.name} (${wallet.walletId})`);
      console.log(`Address Type: ${formatAddressType(parsed.addressType)}`);
      console.log(`Miniscript: ${parsed.miniscript}`);
      if (txState) {
        console.log(
          `Tx State: locktime=${txState.lockTime} sequence=${txState.inputs[0].nSequence}`,
        );
      }
      console.log("");
      printMiniscriptPlanTable(plans);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

miniscriptCommand
  .command("validate")
  .description("Validate a miniscript wallet, descriptor, or expression")
  .option("--wallet <wallet-id>", "Local wallet ID")
  .option("--descriptor <descriptor>", "Miniscript descriptor to validate")
  .option("--miniscript <expression>", "Bare miniscript expression to validate")
  .option(
    "--address-type <type>",
    "Address type for --miniscript (ANY, NATIVE_SEGWIT, TAPROOT)",
    parseMiniscriptAddressTypeOption,
    MINISCRIPT_ADDRESS_TYPE_NATIVE_SEGWIT,
  )
  .action((options, cmd) => {
    try {
      const sources = [options.wallet, options.descriptor, options.miniscript].filter(
        (value) => typeof value === "string" && value.trim().length > 0,
      );
      if (sources.length !== 1) {
        printError(
          {
            error: "INVALID_PARAM",
            message: "Provide exactly one of --wallet, --descriptor, or --miniscript",
          },
          cmd,
        );
        return;
      }

      let miniscript: string;
      let addressType: MiniscriptAddressType;
      let descriptor: string | undefined;
      let walletId: string | undefined;

      if (options.wallet) {
        const globals = cmd.optsWithGlobals();
        const network = getNetwork(globals.network);
        const email = requireEmail(globals.network);
        const wallet = loadWallet(email, network, options.wallet);
        if (!wallet) {
          printError(
            { error: "NOT_FOUND", message: `Wallet ${options.wallet} not found locally` },
            cmd,
          );
          return;
        }

        const parsed = parseWalletDescriptor(wallet);
        if (parsed.kind !== "miniscript" || !parsed.miniscript) {
          printError(
            {
              error: "UNSUPPORTED",
              message: "Wallet is not a miniscript wallet",
            },
            cmd,
          );
          return;
        }

        miniscript = parsed.miniscript;
        addressType = parsed.addressType as MiniscriptAddressType;
        descriptor = buildWalletDescriptorForParsed(parsed);
        walletId = wallet.walletId;
      } else if (options.descriptor) {
        const parsed = parseDescriptor(options.descriptor);
        if (parsed.kind !== "miniscript" || !parsed.miniscript) {
          printError(
            {
              error: "UNSUPPORTED",
              message: "Descriptor is not a miniscript descriptor",
            },
            cmd,
          );
          return;
        }

        miniscript = parsed.miniscript;
        addressType = parsed.addressType as MiniscriptAddressType;
        descriptor = buildWalletDescriptorForParsed(parsed);
      } else {
        miniscript = String(options.miniscript).trim();
        addressType = options.addressType;
        const validation = validateMiniscriptTemplate(miniscript, addressType);
        if (!validation.ok) {
          printError(
            {
              error: "INVALID_MINISCRIPT",
              message: validation.error ?? "Invalid miniscript expression",
            },
            cmd,
          );
          return;
        }
        if (addressType !== MINISCRIPT_ADDRESS_TYPE_ANY) {
          descriptor = buildMiniscriptDescriptor(miniscript, addressType);
        }
      }

      const plans = describeMiniscriptSpendingPlans(miniscript);
      const result = {
        ok: true,
        walletId,
        addressType:
          addressType === MINISCRIPT_ADDRESS_TYPE_ANY ? "ANY" : formatAddressType(addressType),
        miniscript,
        descriptor,
        pathCount: plans.length,
        paths: plans.map((plan) => ({
          index: plan.index,
          supported: plan.supported,
          preimageRequirements: plan.preimageRequirements,
          requiredSignatures: plan.requiredSignatures,
          lockTime: plan.lockTime,
          sequence: plan.sequence,
          signerNames: plan.signerNames,
          unsupportedReason: plan.unsupportedReason,
        })),
      };

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(result, cmd);
        return;
      }

      console.log("Miniscript is valid.");
      if (walletId) {
        console.log(`Wallet: ${walletId}`);
      }
      console.log(
        `Address Type: ${addressType === MINISCRIPT_ADDRESS_TYPE_ANY ? "ANY" : formatAddressType(addressType)}`,
      );
      console.log(`Miniscript: ${miniscript}`);
      if (descriptor) {
        console.log(`Descriptor: ${descriptor}`);
      }
      console.log(`Paths: ${plans.length}`);
      console.log("");
      printMiniscriptPlanTable(plans);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

walletCommand
  .command("delete")
  .description("Delete a wallet")
  .argument("<wallet-id>", "Wallet ID")
  .action(async (walletId, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const apiKey = requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const wallet = loadWallet(email, network, walletId);
      if (!wallet) {
        printError({ error: "NOT_FOUND", message: `Wallet ${walletId} not found locally` }, cmd);
        return;
      }

      const client = new ApiClient(apiKey, network);
      const result = await client.del(`/v1.1/shared-wallets/wallets/${wallet.gid}`);
      removeWallet(email, network, walletId);
      print(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

walletCommand
  .command("rename")
  .description("Rename a wallet locally")
  .argument("<wallet-id>", "Wallet ID")
  .requiredOption("--name <name>", "New wallet name")
  .action(async (walletId, options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const wallet = loadWallet(email, network, walletId);
      if (!wallet) {
        printError({ error: "NOT_FOUND", message: `Wallet ${walletId} not found locally` }, cmd);
        return;
      }

      wallet.name = options.name;
      saveWallet(email, network, wallet);
      const walletView = toWalletView(wallet);
      const client = new ApiClient(requireApiKey(globals.apiKey, globals.network), network);
      const pkConfig = await getWalletPlatformKeyConfig(client, wallet);
      printWalletResult({ ...walletView, platformKey: pkConfig.platformKey ?? undefined }, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

// wallet recover — Recover a group wallet from a descriptor/BSMS/multisig config backup file
// Reference: libnunchuk RecoverGroupWallet (nunchukgroupwallet.cpp:539-552)
walletCommand
  .command("recover")
  .description("Recover a group wallet from a descriptor, multisig config, or BSMS backup file")
  .requiredOption("--file <path>", "Path to BSMS, descriptor, or multisig config backup file")
  .option("--name <name>", "Wallet name", "Group wallet")
  .action(async (options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const apiKey = requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);

      // Read and parse the file
      let fileContent: string;
      try {
        fileContent = fs.readFileSync(options.file, "utf-8").trim();
      } catch {
        printError(
          { error: "FILE_NOT_FOUND", message: `Could not read file: ${options.file}` },
          cmd,
        );
        return;
      }

      const parsed = await (async () => {
        if (fileContent.startsWith("BSMS 1.0")) {
          return parseBsmsRecord(fileContent, network);
        }

        if (looksLikeMultisigConfig(fileContent)) {
          return parseMultisigConfig(fileContent, network);
        }

        return parseDescriptor(fileContent);
      })();

      const client = new ApiClient(apiKey, network);
      const result = await recoverWallet({
        client,
        parsed,
        network,
        email,
        name: options.name,
      });

      print(
        {
          ...result,
          wallet: formatWalletOutput({
            ...result.wallet,
            typeLabel: getWalletTypeLabel(result.wallet),
          }),
        },
        cmd,
      );
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

// -- Helpers --

function getGlobals(cmd: Command): { apiKey: string; network: Network; email: string } {
  const globals = cmd.optsWithGlobals();
  return {
    apiKey: requireApiKey(globals.apiKey, globals.network),
    network: getNetwork(globals.network),
    email: requireEmail(globals.network),
  };
}

function requireWallet(email: string, network: Network, walletId: string): WalletData {
  const wallet = loadWallet(email, network, walletId);
  if (!wallet) {
    console.error(`Error: Wallet ${walletId} not found locally`);
    process.exit(1);
  }
  return wallet;
}

function parsePlatformKeyPoliciesFromOptions(
  options: {
    signer?: string;
    autoBroadcast?: boolean;
    signingDelay?: number;
    limitAmount?: string;
    limitCurrency?: string;
    limitInterval?: string;
    policyJson?: string;
    policyFile?: string;
  },
  existingPolicies: PlatformKeyPolicies | undefined,
): PlatformKeyPolicies {
  if (options.signer && !/^[0-9a-fA-F]{8}$/.test(options.signer)) {
    throw new Error("Signer fingerprint must be 8 hex characters");
  }

  const hasJson = typeof options.policyJson === "string";
  const hasFile = typeof options.policyFile === "string";
  const hasPolicyFlags =
    options.autoBroadcast === true ||
    options.signingDelay != null ||
    options.limitAmount ||
    options.limitCurrency ||
    options.limitInterval;
  const hasSigner = typeof options.signer === "string";

  if (hasSigner && (hasJson || hasFile)) {
    throw new Error(
      "--signer can only be used with flag-based input, not --policy-json or --policy-file",
    );
  }

  const flagMode = hasPolicyFlags || hasSigner;
  const modeCount = [flagMode, hasJson, hasFile].filter(Boolean).length;
  if (modeCount === 0) {
    throw new Error(
      "Provide policy via flags (--auto-broadcast, --signing-delay, etc.), --policy-json, or --policy-file",
    );
  }
  if (modeCount > 1) {
    throw new Error("Use only one input mode: flags, --policy-json, or --policy-file");
  }

  let policies: PlatformKeyPolicies;
  if (hasJson) {
    policies = parsePolicyJson(options.policyJson!);
  } else if (hasFile) {
    policies = parsePolicyJson(fs.readFileSync(options.policyFile!, "utf8"));
  } else {
    const flagOpts: PolicyFlagOptions = {
      autoBroadcast: options.autoBroadcast ?? false,
      signingDelay: options.signingDelay,
      limitAmount: options.limitAmount,
      limitCurrency: options.limitCurrency,
      limitInterval: options.limitInterval,
    };
    policies = hasSigner
      ? buildSignerPolicyFromFlags(options.signer!, flagOpts)
      : buildGlobalPolicyFromFlags(flagOpts);
  }

  if (flagMode && hasSigner) {
    policies = mergePolicies(existingPolicies, policies, options.signer);
  }

  return policies;
}

// -- Platform Key subcommands --

const platformKeyCommand = walletCommand
  .command("platform-key")
  .description("Platform key operations for finalized wallets");

// wallet platform-key get <wallet-id>
platformKeyCommand
  .command("get")
  .description("Get current platform key config")
  .argument("<wallet-id>", "Wallet ID")
  .action(async (walletId, _options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, walletId);
      const client = new ApiClient(apiKey, network);
      const config = await getWalletPlatformKeyConfig(client, wallet);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(config, cmd);
      } else {
        if (!config.platformKey) {
          console.log("Platform Key:    Not configured");
        } else {
          for (const line of formatPoliciesText(config.platformKey.policies)) {
            console.log(line);
          }
        }
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

platformKeyCommand
  .command("update")
  .description("Request a platform key policy update")
  .argument("<wallet-id>", "Wallet ID")
  .option("--signer <xfp>", "Target signer fingerprint (per-key policy)")
  .option("--auto-broadcast", "Auto-broadcast after signing")
  .option(
    "--signing-delay <duration>",
    "Delay before signing (seconds, or 30s/15m/24h/7d)",
    parseSigningDelayOption,
  )
  .option("--limit-amount <amount>", "Spending limit amount")
  .option("--limit-currency <currency>", "Spending limit currency (USD, BTC, sat)")
  .option("--limit-interval <interval>", "Spending limit interval (DAILY, WEEKLY, MONTHLY, YEARLY)")
  .option("--policy-json <json>", "Full policy as JSON string")
  .option("--policy-file <path>", "Path to policy JSON file")
  .action(async (walletId, options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, walletId);
      const client = new ApiClient(apiKey, network);
      const config = await getWalletPlatformKeyConfig(client, wallet);

      if (!config.platformKey) {
        printError({ error: "INVALID_STATE", message: "Platform key is not enabled" }, cmd);
        return;
      }

      const policies = parsePlatformKeyPoliciesFromOptions(options, config.platformKey.policies);
      validateWalletPolicies(policies, wallet.signers, config.platformKeyFingerprint);

      const result = await requestPlatformKeyPolicyUpdate(client, wallet, policies);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(result, cmd);
      } else {
        console.log(`Success:                    ${result.success}`);
        console.log(`Delay Apply:                ${result.delayApplyInSeconds}s`);
        console.log(`Requires Dummy Transaction: ${result.requiresDummyTransaction}`);
        if (result.dummyTransaction) {
          console.log("");
          console.log(`Dummy Transaction ID:       ${result.dummyTransaction.id}`);
          console.log(`Type:                       ${result.dummyTransaction.type}`);
          console.log(`Status:                     ${result.dummyTransaction.status}`);
          console.log(
            `Signatures:                 ${result.dummyTransaction.requiredSignatures - result.dummyTransaction.pendingSignatures}/${result.dummyTransaction.requiredSignatures}`,
          );
        }
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

// -- Dummy transaction subcommands --

const dummyTxCommand = walletCommand
  .command("dummy-tx")
  .description("Manage wallet dummy transactions");

// wallet dummy-tx list <wallet-id>
dummyTxCommand
  .command("list")
  .description("List pending dummy transactions")
  .argument("<wallet-id>", "Wallet ID")
  .action(async (walletId, _options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, walletId);
      const client = new ApiClient(apiKey, network);
      const txs = await fetchDummyTransactions(client, wallet);

      if (txs.length === 0) {
        print({ message: "No pending dummy transactions" }, cmd);
        return;
      }

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(txs, cmd);
      } else {
        printTable(
          txs.map((tx) => ({
            id: tx.id,
            type: tx.type,
            status: tx.status,
            signatures: `${tx.requiredSignatures - tx.pendingSignatures}/${tx.requiredSignatures}`,
          })),
        );
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

// wallet dummy-tx get <wallet-id> --dummy-tx-id <id>
dummyTxCommand
  .command("get")
  .description("Get details of a dummy transaction")
  .argument("<wallet-id>", "Wallet ID")
  .requiredOption("--dummy-tx-id <id>", "Dummy transaction ID")
  .action(async (walletId, options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, walletId);
      const client = new ApiClient(apiKey, network);
      const tx = await fetchDummyTransaction(client, wallet, options.dummyTxId);

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(tx, cmd);
      } else {
        console.log(`ID:              ${tx.id}`);
        console.log(`Type:            ${tx.type}`);
        console.log(`Status:          ${tx.status}`);
        console.log(
          `Signatures:      ${tx.requiredSignatures - tx.pendingSignatures}/${tx.requiredSignatures}`,
        );

        if (tx.payload) {
          console.log("");
          console.log("Old Policies:");
          for (const line of formatPoliciesText(tx.payload.oldPolicies)) {
            console.log(`  ${line}`);
          }
          console.log("");
          console.log("New Policies:");
          for (const line of formatPoliciesText(tx.payload.newPolicies)) {
            console.log(`  ${line}`);
          }
        }
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

// wallet platform-key dummy-tx sign <wallet-id> --tx-id <id>
dummyTxCommand
  .command("sign")
  .description("Sign a dummy transaction")
  .argument("<wallet-id>", "Wallet ID")
  .requiredOption("--dummy-tx-id <id>", "Dummy transaction ID")
  .option("--xprv <xprv>", "Extended private key for signing")
  .option("--fingerprint <xfp>", "Fingerprint of a stored key")
  .action(async (walletId, options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, walletId);
      const client = new ApiClient(apiKey, network);

      const resolved = resolveSignerKeys(options, email, network, wallet.signers);
      if ("error" in resolved) {
        printError({ error: "INVALID_PARAM", message: resolved.error }, cmd);
        return;
      }

      // Fetch the dummy transaction to get requestBody
      const dummyTx = await fetchDummyTransaction(client, wallet, options.dummyTxId);
      if (!dummyTx.requestBody) {
        printError(
          { error: "INVALID_STATE", message: "Dummy transaction has no requestBody" },
          cmd,
        );
        return;
      }

      // Filter out signers that already signed this dummy tx
      const alreadySignedXfps = new Set(
        dummyTx.signatures.map((s) => s.masterFingerprint.toLowerCase()),
      );
      const toSign = resolved.matched.filter((m) => !alreadySignedXfps.has(m.signerXfp));

      if (toSign.length === 0) {
        const names = resolved.matched
          .map((m) => (m.keyName ? `${m.keyName} (${m.signerXfp})` : m.signerXfp))
          .join(", ");
        printError({ error: "ALREADY_SIGNED", message: `Already signed by: ${names}` }, cmd);
        return;
      }

      // Sign with each matched key and collect request tokens
      const requestTokens: string[] = [];
      for (const matched of toSign) {
        const dummyPsbt = createDummyPsbt(wallet, dummyTx.requestBody, network);
        const xfpInt = parseInt(matched.signerXfp, 16);
        signWalletPsbtWithKey(dummyPsbt, matched.signerKey, xfpInt, wallet.descriptor);

        const signature = extractPartialSignature(dummyPsbt, xfpInt);
        requestTokens.push(`${matched.signerXfp}.${signature}`);
      }

      // Submit all signatures
      await signDummyTransaction(client, wallet, options.dummyTxId, requestTokens);

      // Try to fetch updated dummy tx (still exists if more signatures needed)
      // If deleted (enough signatures collected), fetch updated policy instead
      let updated: Awaited<ReturnType<typeof fetchDummyTransaction>> | null = null;
      try {
        updated = await fetchDummyTransaction(client, wallet, options.dummyTxId);
      } catch {
        // Dummy tx deleted — policy applied
      }

      const globals = cmd.optsWithGlobals();
      if (updated) {
        if (globals.json) {
          print(updated, cmd);
        } else {
          console.log("Signed successfully.");
          console.log(`Status:          ${updated.status}`);
          console.log(
            `Signatures:      ${updated.requiredSignatures - updated.pendingSignatures}/${updated.requiredSignatures}`,
          );
        }
      } else {
        const config = await getWalletPlatformKeyConfig(client, wallet);
        if (globals.json) {
          print(config, cmd);
        } else {
          console.log("Signed successfully. Policy updated.");
          console.log("");
          if (!config.platformKey) {
            console.log("Platform Key:    Not configured");
          } else {
            for (const line of formatPoliciesText(config.platformKey.policies)) {
              console.log(line);
            }
          }
        }
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

// wallet dummy-tx cancel <wallet-id> --dummy-tx-id <id>
dummyTxCommand
  .command("cancel")
  .description("Cancel a pending dummy transaction")
  .argument("<wallet-id>", "Wallet ID")
  .requiredOption("--dummy-tx-id <id>", "Dummy transaction ID")
  .action(async (walletId, options, cmd) => {
    try {
      const { apiKey, network, email } = getGlobals(cmd);
      const wallet = requireWallet(email, network, walletId);
      const client = new ApiClient(apiKey, network);
      await cancelDummyTransaction(client, wallet, options.dummyTxId);
      print({ message: `Dummy transaction ${options.dummyTxId} cancelled` }, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
