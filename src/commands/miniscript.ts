import { Command, InvalidArgumentError, Option } from "commander";
import { getNetwork, requireEmail } from "../core/config.js";
import { parseAddressTypeInput, type AddressType } from "../core/address-type.js";
import { loadWallet } from "../core/storage.js";
import { buildWalletDescriptorForParsed, parseDescriptor } from "../core/descriptor.js";
import { buildMiniscriptDescriptor, validateMiniscriptTemplate } from "../core/miniscript.js";
import {
  formatMiniscriptPreimageRequirement,
  type MiniscriptPreimageRequirement,
} from "../core/miniscript-preimage.js";
import { describeMiniscriptSpendingPlans } from "../core/miniscript-spend.js";
import { print, printError, printTable } from "../output.js";

export const miniscriptCommand = new Command("miniscript").description(
  "Inspect and validate miniscript wallets and descriptors",
);

function parseAddressTypeOption(value: string): AddressType {
  const addressType = parseAddressTypeInput(value);
  if (addressType === "NATIVE_SEGWIT") {
    return addressType;
  }

  throw new InvalidArgumentError(
    `Invalid miniscript address type: ${value}. Miniscript currently supports NATIVE_SEGWIT only`,
  );
}

function miniscriptAddressTypeOption(): Option {
  return new Option("--address-type <type>", "Address type for --miniscript (NATIVE_SEGWIT only)")
    .argParser(parseAddressTypeOption)
    .default("NATIVE_SEGWIT" satisfies AddressType, "NATIVE_SEGWIT");
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

type MiniscriptSourceOptions = {
  addressType?: AddressType;
  descriptor?: string;
  miniscript?: string;
  wallet?: string;
};

function requireMiniscriptAddressType(addressType: AddressType): AddressType {
  if (addressType !== "NATIVE_SEGWIT") {
    throw new Error("Only native segwit miniscript descriptors are supported");
  }
  return addressType;
}

function getMiniscriptSource(
  options: MiniscriptSourceOptions,
  cmd: Command,
): {
  addressType?: AddressType;
  descriptor?: string;
  miniscript: string;
  walletId?: string;
  walletName?: string;
} | null {
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
    return null;
  }

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
      return null;
    }

    const parsed = parseDescriptor(wallet.descriptor);
    if (parsed.kind !== "miniscript" || !parsed.miniscript) {
      printError(
        {
          error: "UNSUPPORTED",
          message: "Wallet is not a miniscript wallet",
        },
        cmd,
      );
      return null;
    }

    return {
      addressType: requireMiniscriptAddressType(parsed.addressType),
      descriptor: buildWalletDescriptorForParsed(parsed),
      miniscript: parsed.miniscript,
      walletId: wallet.walletId,
      walletName: wallet.name,
    };
  }

  if (options.descriptor) {
    const parsed = parseDescriptor(options.descriptor);
    if (parsed.kind !== "miniscript" || !parsed.miniscript) {
      printError(
        {
          error: "UNSUPPORTED",
          message: "Descriptor is not a miniscript descriptor",
        },
        cmd,
      );
      return null;
    }

    return {
      addressType: requireMiniscriptAddressType(parsed.addressType),
      descriptor: buildWalletDescriptorForParsed(parsed),
      miniscript: parsed.miniscript,
    };
  }

  const miniscript = String(options.miniscript).trim();
  const addressType = options.addressType;
  const validation = validateMiniscriptTemplate(miniscript, addressType);
  if (!validation.ok) {
    printError(
      {
        error: "INVALID_MINISCRIPT",
        message: validation.error ?? "Invalid miniscript expression",
      },
      cmd,
    );
    return null;
  }

  return {
    addressType,
    descriptor:
      addressType === undefined ? undefined : buildMiniscriptDescriptor(miniscript, addressType),
    miniscript,
  };
}

function formatAddressTypeLabel(addressType: AddressType | undefined): string {
  return addressType ?? "NATIVE_SEGWIT";
}

miniscriptCommand
  .command("inspect")
  .description("Inspect miniscript signing paths")
  .option("--wallet <wallet-id>", "Local wallet ID")
  .option("--descriptor <descriptor>", "Miniscript descriptor to inspect")
  .option("--miniscript <expression>", "Bare miniscript expression to inspect")
  .addOption(miniscriptAddressTypeOption())
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
  .action((options, cmd) => {
    try {
      const source = getMiniscriptSource(options, cmd);
      if (!source) return;

      const hasTxState = options.locktime != null || options.sequence != null;
      const txState = hasTxState
        ? {
            lockTime: options.locktime ?? 0,
            inputs: [{ nSequence: options.sequence ?? 0 }],
          }
        : undefined;
      const plans = describeMiniscriptSpendingPlans(source.miniscript, txState);
      const result = {
        walletId: source.walletId,
        name: source.walletName,
        addressType: formatAddressTypeLabel(source.addressType),
        miniscript: source.miniscript,
        descriptor: source.descriptor,
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

      const globals = cmd.optsWithGlobals();
      if (globals.json) {
        print(result, cmd);
        return;
      }

      if (source.walletId) {
        console.log(`Wallet: ${source.walletName} (${source.walletId})`);
      }
      console.log(`Address Type: ${formatAddressTypeLabel(source.addressType)}`);
      console.log(`Miniscript: ${source.miniscript}`);
      if (source.descriptor) {
        console.log(`Descriptor: ${source.descriptor}`);
      }
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
  .addOption(miniscriptAddressTypeOption())
  .action((options, cmd) => {
    try {
      const source = getMiniscriptSource(options, cmd);
      if (!source) return;

      const plans = describeMiniscriptSpendingPlans(source.miniscript);
      const result = {
        ok: true,
        walletId: source.walletId,
        addressType: formatAddressTypeLabel(source.addressType),
        miniscript: source.miniscript,
        descriptor: source.descriptor,
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
      if (source.walletId) {
        console.log(`Wallet: ${source.walletId}`);
      }
      console.log(`Address Type: ${formatAddressTypeLabel(source.addressType)}`);
      console.log(`Miniscript: ${source.miniscript}`);
      if (source.descriptor) {
        console.log(`Descriptor: ${source.descriptor}`);
      }
      console.log(`Paths: ${plans.length}`);
      console.log("");
      printMiniscriptPlanTable(plans);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
