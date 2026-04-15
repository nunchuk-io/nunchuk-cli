import { Command, InvalidArgumentError } from "commander";
import { HDKey } from "@scure/bip32";
import {
  requireApiKey,
  requireEmail,
  getEphemeralKeypair,
  getNetwork,
  loadConfig,
} from "../core/config.js";
import { ApiClient } from "../core/api-client.js";
import { ADDRESS_TYPES, numberToAddressType, type AddressType } from "../core/address-type.js";
import {
  buildCreateGroupBody,
  buildJoinGroupEvent,
  buildAddKeyBody,
  buildFinalizeBody,
  buildSignerDescriptor,
  getGroupDisplayState,
  isGroupFinalized,
  recoverFinalizedGroup,
  buildEnablePlatformKeyBody,
  buildDisablePlatformKeyBody,
  buildSetPlatformKeyPolicyBody,
  getGroupPlatformKeyState,
} from "../core/sandbox.js";
import {
  addSandboxId,
  removeSandboxId,
  getSandboxIds,
  saveWallet,
  loadKey,
  type WalletData,
} from "../core/storage.js";
import { print, printError, printSandboxResult } from "../output.js";
import { parseSignerDescriptor } from "../core/descriptor.js";
import { mnemonicToRootKey, getSignerInfo } from "../core/keygen.js";
import { MAINNET_VERSIONS, TESTNET_VERSIONS } from "../core/address.js";
import {
  buildGlobalPolicyFromFlags,
  buildSignerPolicyFromFlags,
  mergePolicies,
  parseSigningDelayInput,
  parsePolicyJson,
  validatePolicies,
  fetchBackendPubkey,
  formatPoliciesText,
  type PlatformKeyPolicies,
  type PolicyFlagOptions,
} from "../core/platform-key.js";
import { readFileSync } from "node:fs";

function requireEphemeralKeys(flagNetwork?: string): { pub: string; priv: string } {
  const config = loadConfig();
  const network = getNetwork(flagNetwork);
  const keys = getEphemeralKeypair(config, network);
  if (!keys?.pub || !keys?.priv) {
    console.error('Error: No ephemeral keys. Run "nunchuk auth login" first.');
    process.exit(1);
  }
  return { pub: keys.pub, priv: keys.priv };
}

function looksLikeJoinUrl(input: string): boolean {
  return (
    input.includes("://") || input.startsWith("nunchuk.io/") || input.includes("/wallet/join/")
  );
}

function isSignerDescriptor(value: string): boolean {
  return /^\[[0-9a-fA-F]{8}(\/[^\]]*)\].+$/.test(value);
}

function normalizeExtendedPublicKeyForNetwork(
  xpub: string,
  network: "mainnet" | "testnet",
): string {
  const sourceVersions = xpub.startsWith("xpub")
    ? MAINNET_VERSIONS
    : xpub.startsWith("tpub")
      ? TESTNET_VERSIONS
      : null;

  if (!sourceVersions) {
    return xpub;
  }

  const targetVersions = network === "mainnet" ? MAINNET_VERSIONS : TESTNET_VERSIONS;
  if (sourceVersions.public === targetVersions.public) {
    return xpub;
  }

  const key = HDKey.fromExtendedKey(xpub, sourceVersions);
  return new HDKey({
    versions: targetVersions,
    depth: key.depth,
    index: key.index,
    parentFingerprint: key.parentFingerprint,
    chainCode: key.chainCode ?? undefined,
    publicKey: key.publicKey ?? undefined,
  }).publicExtendedKey;
}

function parseSigningDelayOption(value: string): number {
  try {
    return parseSigningDelayInput(value);
  } catch (err) {
    throw new InvalidArgumentError((err as Error).message);
  }
}

function parseSlotListOption(value: string, previous: string[]): string[] {
  const next = value
    .split(",")
    .map((slot) => slot.trim())
    .filter((slot) => slot.length > 0);
  return [...previous, ...next];
}

async function resolveSandboxId(client: ApiClient, input: string): Promise<string> {
  if (!looksLikeJoinUrl(input)) {
    return input;
  }

  const parsed = await client.post<{ group_id: string; redirect_url?: string }>(
    "/v1.1/shared-wallets/url/parse",
    JSON.stringify({ url: input }),
  );
  return parsed.group_id;
}

function createClient(cmd: Command): ApiClient {
  const globals = cmd.optsWithGlobals();
  return new ApiClient(requireApiKey(globals.apiKey, globals.network), getNetwork(globals.network));
}

export const sandboxCommand = new Command("sandbox").description("Manage group wallet sandboxes");

sandboxCommand
  .command("create")
  .description("Create a new group wallet sandbox")
  .requiredOption("--name <name>", "Wallet name")
  .option("--m <number>", "Required signatures", parseInt)
  .option("--n <number>", "Total signers", parseInt)
  .option("--miniscript-template <template>", "Miniscript template for a wsh(miniscript) sandbox")
  .option(
    "--address-type <type>",
    "Address type (NATIVE_SEGWIT, NESTED_SEGWIT, LEGACY, TAPROOT)",
    "NATIVE_SEGWIT",
  )
  .action(async (options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const { pub, priv } = requireEphemeralKeys(globals.network);
      const miniscriptTemplate =
        typeof options.miniscriptTemplate === "string" ? options.miniscriptTemplate.trim() : "";

      if (miniscriptTemplate.length > 0 && (options.m != null || options.n != null)) {
        printError(
          {
            error: "INVALID_PARAM",
            message: "Use either --miniscript-template or --m/--n, not both",
          },
          cmd,
        );
        return;
      }
      if (miniscriptTemplate.length === 0 && (options.m == null || options.n == null)) {
        printError(
          {
            error: "MISSING_PARAM",
            message: "Provide --m and --n for multisig, or use --miniscript-template",
          },
          cmd,
        );
        return;
      }
      if (miniscriptTemplate.length > 0 && options.addressType !== "NATIVE_SEGWIT") {
        printError(
          {
            error: "INVALID_PARAM",
            message: "Miniscript sandboxes currently support NATIVE_SEGWIT only",
          },
          cmd,
        );
        return;
      }

      if (miniscriptTemplate.length === 0 && options.m > options.n) {
        printError({ error: "INVALID_PARAM", message: "m must be <= n" }, cmd);
        return;
      }
      if (miniscriptTemplate.length === 0 && options.n < 2) {
        printError(
          {
            error: "INVALID_PARAM",
            message: "Group wallet must have at least 2 signers",
          },
          cmd,
        );
        return;
      }
      if (!ADDRESS_TYPES.includes(options.addressType)) {
        printError(
          {
            error: "INVALID_PARAM",
            message: `Invalid address type. Use: ${ADDRESS_TYPES.join(", ")}`,
          },
          cmd,
        );
        return;
      }

      const body = buildCreateGroupBody(
        options.name,
        options.m ?? 0,
        options.n ?? 0,
        options.addressType as AddressType,
        pub,
        priv,
        miniscriptTemplate,
      );

      const apiKey = requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const client = new ApiClient(apiKey, network);
      const result = await client.post<{ group: { id: string } }>(
        "/v1.1/shared-wallets/groups",
        body,
      );
      addSandboxId(email, network, result.group.id);
      printSandboxResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

sandboxCommand
  .command("list")
  .description("List all sandboxes")
  .action(async (_options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const ids = getSandboxIds(email, network);
      print({ "Sandbox IDs": ids }, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

sandboxCommand
  .command("get")
  .description("Get sandbox details")
  .argument("<sandbox-id>", "Sandbox ID")
  .action(async (sandboxId, _options, cmd) => {
    try {
      const client = createClient(cmd);

      const result = await client.get(`/v1.1/shared-wallets/groups/${sandboxId}`);
      printSandboxResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

sandboxCommand
  .command("join")
  .description("Join an existing sandbox")
  .argument("<sandbox-id-or-url>", "Sandbox ID or join URL")
  .action(async (sandboxIdOrUrl, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const client = createClient(cmd);
      const sandboxId = await resolveSandboxId(client, sandboxIdOrUrl);

      // Fetch current group state, build join event, POST to correct endpoint
      const groupData = await client.get<{ group: Record<string, unknown> }>(
        `/v1.1/shared-wallets/groups/${sandboxId}`,
      );
      const { pub } = requireEphemeralKeys(globals.network);
      const body = buildJoinGroupEvent(sandboxId, groupData.group, pub);
      await client.post("/v1.1/shared-wallets/groups/join", body);

      addSandboxId(email, network, sandboxId);
      const result = await client.get(`/v1.1/shared-wallets/groups/${sandboxId}`);
      printSandboxResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

sandboxCommand
  .command("add-key")
  .description("Add a signer key to a specific slot")
  .argument("<sandbox-id>", "Sandbox ID")
  .requiredOption("--slot <slot>", "Slot index or miniscript signer name")
  .option("--fingerprint <xfp>", "Master fingerprint (8 hex chars)")
  .option("--descriptor <descriptor>", "Full signer descriptor [xfp/path]xpub (supports h or ')")
  .option("--xpub <xpub>", "Extended public key")
  .option("--path <path>", "Derivation path (e.g. m/48h/0h/0h/2h)")
  .action(async (sandboxId, options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const { pub, priv } = requireEphemeralKeys(globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail();
      const client = createClient(cmd);

      const hasFingerprint = Boolean(options.fingerprint);
      const hasDescriptor = typeof options.descriptor === "string" && options.descriptor.length > 0;
      const hasManualParts = Boolean(options.xpub || options.path);

      // --fingerprint + --xpub + --path = manual descriptor mode
      // --fingerprint alone = stored key lookup
      // --descriptor = full descriptor string
      const isStoredKeyMode = hasFingerprint && !hasManualParts && !hasDescriptor;

      if (!hasFingerprint && !hasDescriptor && !hasManualParts) {
        printError(
          {
            error: "MISSING_PARAM",
            message: "Provide --fingerprint, --descriptor, or --fingerprint with --xpub and --path",
          },
          cmd,
        );
        return;
      }
      if (hasDescriptor && (hasManualParts || hasFingerprint)) {
        printError(
          {
            error: "INVALID_PARAM",
            message:
              "Use --descriptor alone, or --fingerprint alone (stored key), or --fingerprint with --xpub and --path",
          },
          cmd,
        );
        return;
      }
      if (hasManualParts && !hasFingerprint) {
        printError(
          {
            error: "MISSING_PARAM",
            message: "--xpub and --path require --fingerprint",
          },
          cmd,
        );
        return;
      }

      // 1. Fetch latest sandbox state from server
      const groupData = await client.get<{ group: Record<string, unknown> }>(
        `/v1.1/shared-wallets/groups/${sandboxId}`,
      );
      const state = getGroupDisplayState(groupData.group, pub, priv);

      let slot: number;
      if (/^\d+$/.test(String(options.slot))) {
        slot = Number(options.slot);
      } else if (state.kind === "miniscript") {
        slot = state.slotNames.indexOf(String(options.slot));
        if (slot === -1) {
          printError(
            {
              error: "INVALID_PARAM",
              message: `Unknown miniscript signer slot: ${options.slot}`,
            },
            cmd,
          );
          return;
        }
      } else {
        printError(
          {
            error: "INVALID_PARAM",
            message: "--slot must be a numeric index for multisig sandboxes",
          },
          cmd,
        );
        return;
      }

      if (slot < 0 || slot >= state.n) {
        printError(
          {
            error: "INVALID_PARAM",
            message: `Slot ${options.slot} is out of range`,
          },
          cmd,
        );
        return;
      }

      let descriptor: string;
      if (isStoredKeyMode) {
        // Derive descriptor from stored mnemonic
        const stored = loadKey(email, network, options.fingerprint);
        if (!stored) {
          printError(
            {
              error: "NOT_FOUND",
              message: `Key ${options.fingerprint} not found`,
            },
            cmd,
          );
          return;
        }

        // Get sandbox address type to derive correct path
        const state = getGroupDisplayState(groupData.group, pub, priv);
        let addressType: AddressType;
        try {
          addressType = numberToAddressType(state.addressType);
        } catch {
          printError(
            {
              error: "INVALID_STATE",
              message: `Unknown sandbox address type: ${state.addressType}`,
            },
            cmd,
          );
          return;
        }

        const rootKey = mnemonicToRootKey(stored.mnemonic, network);
        const info = getSignerInfo(rootKey, network, addressType);
        descriptor = info.descriptor;
      } else if (hasDescriptor) {
        if (!isSignerDescriptor(options.descriptor)) {
          printError(
            {
              error: "INVALID_PARAM",
              message: "Descriptor must be in the format [xfp/path]xpub",
            },
            cmd,
          );
          return;
        }
        const parsed = parseSignerDescriptor(options.descriptor);
        descriptor = buildSignerDescriptor(
          parsed.masterFingerprint,
          parsed.derivationPath,
          normalizeExtendedPublicKeyForNetwork(parsed.xpub, network),
        );
      } else {
        if (!options.xpub || !options.path) {
          printError(
            {
              error: "MISSING_PARAM",
              message: "--fingerprint, --xpub, and --path are all required for manual mode",
            },
            cmd,
          );
          return;
        }

        // Build signer descriptor: [xfp/path]xpub
        descriptor = buildSignerDescriptor(
          options.fingerprint,
          options.path,
          normalizeExtendedPublicKeyForNetwork(options.xpub, network),
        );
      }

      // 3. Build encrypted event body
      const body = buildAddKeyBody(sandboxId, groupData.group, slot, descriptor, pub, priv);

      // 4. Send event
      await client.post("/v1.1/shared-wallets/events/send", body);

      // 5. Fetch and print updated sandbox state
      const result = await client.get(`/v1.1/shared-wallets/groups/${sandboxId}`);
      printSandboxResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

sandboxCommand
  .command("finalize")
  .description("Finalize sandbox into an active wallet")
  .argument("<sandbox-id>", "Sandbox ID")
  .action(async (sandboxId, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const { pub, priv } = requireEphemeralKeys(globals.network);
      const apiKey = requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const client = new ApiClient(apiKey, network);

      // 1. Fetch latest sandbox state
      const groupData = await client.get<{ group: Record<string, unknown> }>(
        `/v1.1/shared-wallets/groups/${sandboxId}`,
      );

      const alreadyFinalized = isGroupFinalized(groupData.group);

      // 2-7. Build descriptor, derive keys, build finalize event or recover finalized wallet
      const result = alreadyFinalized
        ? await recoverFinalizedGroup(groupData.group, pub, priv, network)
        : await buildFinalizeBody(sandboxId, groupData.group, pub, priv, network);

      // 8. Send finalize event only when the sandbox is still pending
      if (!alreadyFinalized) {
        await client.post("/v1.1/shared-wallets/events/send", result.body);
      }

      // 9. Update local storage
      removeSandboxId(email, network, sandboxId);

      const wallet: WalletData = {
        walletId: result.walletId,
        groupId: sandboxId,
        gid: result.gid,
        name: result.name,
        m: result.m,
        n: result.n,
        addressType: result.addressType,
        descriptor: result.descriptor,
        signers: result.signers,
        secretboxKey: Buffer.from(result.secretboxKey).toString("base64"),
        createdAt: new Date().toISOString(),
      };
      saveWallet(email, network, wallet);

      print(
        {
          status: alreadyFinalized ? "already_finalized" : "finalized",
          walletId: result.walletId,
          descriptor: result.descriptor,
        },
        cmd,
      );
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

sandboxCommand
  .command("delete")
  .description("Delete a sandbox")
  .argument("<sandbox-id>", "Sandbox ID")
  .action(async (sandboxId, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const apiKey = requireApiKey(globals.apiKey, globals.network);
      const network = getNetwork(globals.network);
      const email = requireEmail(globals.network);
      const client = new ApiClient(apiKey, network);

      const result = await client.del(`/v1.1/shared-wallets/groups/${sandboxId}`);
      removeSandboxId(email, network, sandboxId);
      print(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

// -- Platform Key subcommands --

const platformKeyCommand = sandboxCommand
  .command("platform-key")
  .description("Manage platform key for a sandbox");

platformKeyCommand
  .command("enable")
  .description("Enable platform key on a sandbox")
  .argument("<sandbox-id>", "Sandbox ID")
  .option(
    "--slot <slot>",
    "Miniscript signer slot name (repeatable or comma-separated)",
    parseSlotListOption,
    [],
  )
  .action(async (sandboxId, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const { pub, priv } = requireEphemeralKeys(globals.network);
      const client = createClient(cmd);

      const backendPubkey = await fetchBackendPubkey(client);

      const groupData = await client.get<{ group: Record<string, unknown> }>(
        `/v1.1/shared-wallets/groups/${sandboxId}`,
      );
      const display = getGroupDisplayState(groupData.group, pub, priv);
      const options = _options as { slot?: string[] };
      const slots = Array.from(new Set(options.slot ?? []));

      if (display.kind === "multisig" && slots.length > 0) {
        printError(
          {
            error: "INVALID_PARAM",
            message: "Platform key slots must be empty for multisig sandboxes",
          },
          cmd,
        );
        return;
      }
      if (display.kind === "miniscript" && slots.length === 0) {
        printError(
          {
            error: "MISSING_PARAM",
            message: "Miniscript platform key enable requires at least one --slot",
          },
          cmd,
        );
        return;
      }
      for (const slot of slots) {
        if (!display.slotNames.includes(slot)) {
          printError(
            {
              error: "INVALID_PARAM",
              message: `Unknown miniscript platform key slot: ${slot}`,
            },
            cmd,
          );
          return;
        }
      }

      const body = buildEnablePlatformKeyBody(
        sandboxId,
        groupData.group,
        backendPubkey,
        pub,
        priv,
        slots,
      );

      await client.post("/v1.1/shared-wallets/events/send", body);

      const result = await client.get(`/v1.1/shared-wallets/groups/${sandboxId}`);
      printSandboxResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

platformKeyCommand
  .command("disable")
  .description("Disable platform key on a sandbox")
  .argument("<sandbox-id>", "Sandbox ID")
  .action(async (sandboxId, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const { pub, priv } = requireEphemeralKeys(globals.network);
      const client = createClient(cmd);

      const backendPubkey = await fetchBackendPubkey(client);

      const groupData = await client.get<{ group: Record<string, unknown> }>(
        `/v1.1/shared-wallets/groups/${sandboxId}`,
      );

      const body = buildDisablePlatformKeyBody(
        sandboxId,
        groupData.group,
        backendPubkey,
        pub,
        priv,
      );

      await client.post("/v1.1/shared-wallets/events/send", body);

      const result = await client.get(`/v1.1/shared-wallets/groups/${sandboxId}`);
      printSandboxResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

platformKeyCommand
  .command("set-policy")
  .description("Set platform key policies on a sandbox")
  .argument("<sandbox-id>", "Sandbox ID")
  .option("--signer <xfp>", "Target signer fingerprint (per-signer policy)")
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
  .action(async (sandboxId, options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const { pub, priv } = requireEphemeralKeys(globals.network);
      const client = createClient(cmd);

      // Validate --signer format
      if (options.signer && !/^[0-9a-fA-F]{8}$/.test(options.signer)) {
        printError(
          {
            error: "INVALID_PARAM",
            message: "Signer fingerprint must be 8 hex characters",
          },
          cmd,
        );
        return;
      }

      // Determine input mode
      const hasJson = typeof options.policyJson === "string";
      const hasFile = typeof options.policyFile === "string";
      const hasPolicyFlags =
        options.autoBroadcast === true ||
        options.signingDelay != null ||
        options.limitAmount ||
        options.limitCurrency ||
        options.limitInterval;
      const hasSigner = typeof options.signer === "string";

      // --signer can only be used with flag mode
      if (hasSigner && (hasJson || hasFile)) {
        printError(
          {
            error: "INVALID_PARAM",
            message:
              "--signer can only be used with flag-based input, not --policy-json or --policy-file",
          },
          cmd,
        );
        return;
      }

      const flagMode = hasPolicyFlags || hasSigner;
      const modeCount = [flagMode, hasJson, hasFile].filter(Boolean).length;

      if (modeCount === 0) {
        printError(
          {
            error: "MISSING_PARAM",
            message:
              "Provide policy via flags (--auto-broadcast, --signing-delay, etc.), --policy-json, or --policy-file",
          },
          cmd,
        );
        return;
      }
      if (modeCount > 1) {
        printError(
          {
            error: "INVALID_PARAM",
            message: "Use only one input mode: flags, --policy-json, or --policy-file",
          },
          cmd,
        );
        return;
      }

      let policies: PlatformKeyPolicies;

      if (hasJson) {
        policies = parsePolicyJson(options.policyJson);
      } else if (hasFile) {
        const content = readFileSync(options.policyFile, "utf8");
        policies = parsePolicyJson(content);
      } else {
        const flagOpts: PolicyFlagOptions = {
          autoBroadcast: options.autoBroadcast ?? false,
          signingDelay: options.signingDelay,
          limitAmount: options.limitAmount,
          limitCurrency: options.limitCurrency,
          limitInterval: options.limitInterval,
        };

        if (hasSigner) {
          policies = buildSignerPolicyFromFlags(options.signer, flagOpts);
        } else {
          policies = buildGlobalPolicyFromFlags(flagOpts);
        }
      }

      // Fetch current state
      const groupData = await client.get<{ group: Record<string, unknown> }>(
        `/v1.1/shared-wallets/groups/${sandboxId}`,
      );

      // Smart merge for --signer flag mode
      if (flagMode && hasSigner) {
        const existingConfig = getGroupPlatformKeyState(groupData.group, pub, priv);
        const existingPolicies = existingConfig?.policies;
        policies = mergePolicies(existingPolicies, policies, options.signer);
      }

      validatePolicies(policies);

      const body = buildSetPlatformKeyPolicyBody(sandboxId, groupData.group, policies, pub, priv);

      await client.post("/v1.1/shared-wallets/events/send", body);

      const result = await client.get(`/v1.1/shared-wallets/groups/${sandboxId}`);
      printSandboxResult(result, cmd);
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });

platformKeyCommand
  .command("get")
  .description("Get platform key status and policies")
  .argument("<sandbox-id>", "Sandbox ID")
  .action(async (sandboxId, _options, cmd) => {
    try {
      const globals = cmd.optsWithGlobals();
      const { pub, priv } = requireEphemeralKeys(globals.network);
      const client = createClient(cmd);

      const groupData = await client.get<{ group: Record<string, unknown> }>(
        `/v1.1/shared-wallets/groups/${sandboxId}`,
      );

      const config = getGroupPlatformKeyState(groupData.group, pub, priv);

      if (globals.json) {
        if (!config) {
          print({ status: "disabled" }, cmd);
        } else {
          print({ status: "enabled", policies: config.policies, slots: config.slots }, cmd);
        }
      } else {
        if (!config) {
          console.log("Platform Key:    Disabled");
        } else {
          console.log("Platform Key:    Enabled");
          if (config.slots && config.slots.length > 0) {
            console.log(`Slots:           ${config.slots.join(", ")}`);
          }
          for (const line of formatPoliciesText(config.policies)) {
            console.log(line);
          }
        }
      }
    } catch (err) {
      printError(err as { error: string; message: string }, cmd);
    }
  });
