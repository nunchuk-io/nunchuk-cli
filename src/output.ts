import { Command } from "commander";
import { formatPoliciesText, type PlatformKeyPolicies } from "./core/platform-key.js";
import { getGroupDisplayState, getGroupPlatformKeyState } from "./core/sandbox.js";
import { formatAddressType } from "./core/address-type.js";
import { loadConfig, getEphemeralKeypair, getNetwork } from "./core/config.js";
import { isRecord } from "./core/utils.js";

export function print(data: unknown, cmd: Command): void {
  if (cmd.optsWithGlobals().json) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    printHuman(data);
  }
}

export function printError(error: { error: string; message: string }, cmd: Command): void {
  if (cmd.optsWithGlobals().json) {
    console.error(JSON.stringify(error));
  } else {
    console.error(`Error: ${error.message}`);
  }
  process.exit(1);
}

function isPlatformKeyPolicies(value: unknown): value is PlatformKeyPolicies {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const obj = value as Record<string, unknown>;
  return Object.keys(obj).length === 0 || "global" in obj || "signers" in obj;
}

export function printHuman(data: unknown, indent = ""): void {
  if (Array.isArray(data)) {
    if (data.length === 0) {
      console.log(`${indent}[]`);
      return;
    }
    data.forEach((item, i) => {
      if (typeof item === "object" && item !== null) {
        console.log(`${indent}${i}: ${formatItem(item)}`);
      } else {
        console.log(`${indent}${i}: ${item}`);
      }
    });
  } else if (typeof data === "object" && data !== null) {
    for (const [key, value] of Object.entries(data)) {
      if (key === "policies" && isPlatformKeyPolicies(value)) {
        console.log(`${indent}${key}:`);
        for (const line of formatPoliciesText(value)) {
          console.log(`${indent}  ${line}`);
        }
        continue;
      }
      if (typeof value === "object" && value !== null) {
        console.log(`${indent}${key}:`);
        printHuman(value, indent + "  ");
      } else {
        console.log(`${indent}${key}: ${value}`);
      }
    }
  } else {
    console.log(`${indent}${data}`);
  }
}

function formatItem(item: Record<string, unknown>): string {
  const id = item.id ?? item.walletId ?? item.groupId ?? item.txId ?? "";
  const name = item.name ?? item.title ?? "";
  return `[${id}] ${name}`;
}

/** Convert camelCase key to UPPER CASE header (e.g. "walletId" → "WALLET ID") */
function formatHeader(key: string): string {
  return key.replace(/([a-z])([A-Z])/g, "$1 $2").toUpperCase();
}

/**
 * Print an array of objects as a formatted table with column headers.
 * Columns are auto-sized to fit the widest value in each column.
 */
export function printTable(rows: Record<string, unknown>[]): void {
  if (rows.length === 0) return;

  const keys = Object.keys(rows[0]);
  const headers = keys.map(formatHeader);
  const widths = keys.map((key, i) => {
    const values = rows.map((r) => String(r[key] ?? ""));
    return Math.max(headers[i].length, ...values.map((v) => v.length));
  });

  const header = headers.map((h, i) => h.padEnd(widths[i])).join("  ");
  const separator = widths.map((w) => "─".repeat(w)).join("──");

  console.log(header);
  console.log(separator);
  for (const row of rows) {
    const line = keys.map((k, i) => String(row[k] ?? "").padEnd(widths[i])).join("  ");
    console.log(line);
  }
}

// -- Sandbox display helpers (shared by sandbox.ts and invitation.ts) --

function displaySignerDescriptor(value: string): string {
  return value.replaceAll("'", "h");
}

export interface SandboxSummary {
  id: unknown;
  url: string;
  status: string;
  name: string;
  typeLabel: string;
  miniscriptTemplate: string;
  m: number;
  n: number;
  addressType: string;
  participants: number;
  occupied: Array<{ slot: number; ts: number; uid: string }>;
  added: number[];
  signers: Record<string, string> | unknown[];
  slotNames: string[];
  platformKey: { status: string; policies?: PlatformKeyPolicies; slots?: string[] };
}

export function summarizeGroup(
  group: Record<string, unknown>,
  ephemeralKeys?: { pub: string; priv: string },
): SandboxSummary | Record<string, unknown> {
  if (!ephemeralKeys) {
    return group;
  }

  const display = getGroupDisplayState(group, ephemeralKeys.pub, ephemeralKeys.priv);
  const platformKey = getGroupPlatformKeyState(group, ephemeralKeys.pub, ephemeralKeys.priv);
  const visibleSigners = Object.fromEntries(
    display.signers
      .map((signer, index) => [String(index), displaySignerDescriptor(signer)] as const)
      .filter(([, signer]) => signer !== "[]"),
  );

  return {
    id: group.id ?? "",
    url: display.url,
    status: display.status,
    name: display.name,
    typeLabel: display.typeLabel,
    miniscriptTemplate: display.miniscriptTemplate,
    m: display.m,
    n: display.n,
    addressType: formatAddressType(display.addressType),
    participants: display.participants,
    occupied: display.occupied,
    added: display.added,
    signers: Object.keys(visibleSigners).length > 0 ? visibleSigners : [],
    slotNames: display.slotNames,
    platformKey: platformKey
      ? { status: "enabled", policies: platformKey.policies, slots: platformKey.slots }
      : { status: "disabled" },
  };
}

export function printSandboxResult(data: unknown, cmd: Command): void {
  if (isRecord(data) && isRecord(data.group)) {
    const config = loadConfig();
    const globals = cmd.optsWithGlobals();
    const network = getNetwork(globals.network);
    const keys = getEphemeralKeypair(config, network);
    const ephemeralKeys = keys?.pub && keys?.priv ? { pub: keys.pub, priv: keys.priv } : undefined;
    const summary = summarizeGroup(data.group, ephemeralKeys);

    if (cmd.optsWithGlobals().json) {
      console.log(JSON.stringify({ group: summary }, null, 2));
    } else {
      printSandboxHuman(summary as SandboxSummary);
    }
    return;
  }

  print(data, cmd);
}

function printSandboxHuman(group: SandboxSummary): void {
  const name = String(group.name || "Sandbox");
  const separator = "─".repeat(Math.max(name.length + 10, 40));

  console.log(`Sandbox: ${name}`);
  console.log(separator);
  console.log(`ID:            ${group.id}`);
  console.log(`Link:          ${group.url}`);
  console.log(`Status:        ${group.status}`);
  console.log(`Type:          ${group.typeLabel}`);
  console.log(`Address Type:  ${group.addressType}`);
  if (group.miniscriptTemplate) {
    console.log(`Miniscript:    ${group.miniscriptTemplate}`);
  }
  console.log(`Participants:  ${group.participants}`);
  console.log();

  const n = Number(group.n);
  const signers = group.signers as Record<string, string> | unknown[];
  const slotNames = Array.isArray(group.slotNames) ? group.slotNames : [];
  console.log("Signers:");
  for (let i = 0; i < n; i++) {
    const key = String(i);
    const descriptor = !Array.isArray(signers) && signers[key] ? signers[key] : null;
    const label = slotNames[i] && slotNames[i] !== key ? ` (${slotNames[i]})` : "";
    if (descriptor) {
      const match = descriptor.match(/^\[([0-9a-fA-F]{8})/);
      const xfp = match ? match[1] : "";
      console.log(`  Slot ${i}${label}:  ${xfp}  ${descriptor}`);
    } else {
      console.log(`  Slot ${i}${label}:  (empty)`);
    }
  }

  console.log();
  const pk = group.platformKey;
  if (pk.status === "enabled" && pk.policies) {
    console.log("Platform Key:  Enabled");
    if (pk.slots && pk.slots.length > 0) {
      console.log(`  Slots: ${pk.slots.join(", ")}`);
    }
    for (const line of formatPoliciesText(pk.policies)) {
      console.log(`  ${line}`);
    }
  } else {
    console.log("Platform Key:  Disabled");
  }
}

// -- Wallet display helpers --

export interface WalletView {
  walletId: string;
  groupId: string;
  name: string;
  m: number;
  n: number;
  addressType: number;
  signers: string[];
  createdAt: string;
  balance?: string;
  typeLabel?: string;
  platformKey?: { policies: PlatformKeyPolicies };
}

export function printWalletResult(wallet: WalletView, cmd: Command): void {
  if (cmd.optsWithGlobals().json) {
    print({ ...wallet, addressType: formatAddressType(wallet.addressType) }, cmd);
  } else {
    printWalletHuman(wallet);
  }
}

function printWalletHuman(wallet: WalletView): void {
  const name = wallet.name || "Wallet";
  const separator = "─".repeat(Math.max(name.length + 10, 40));

  console.log(`Wallet: ${name}`);
  console.log(separator);
  console.log(`ID:            ${wallet.walletId}`);
  console.log(`Group ID:      ${wallet.groupId}`);
  console.log(`Type:          ${wallet.typeLabel ?? `${wallet.m}-of-${wallet.n}`}`);
  console.log(`Address Type:  ${formatAddressType(wallet.addressType)}`);
  if (wallet.balance != null) {
    console.log(`Balance:       ${wallet.balance}`);
  }
  console.log(`Created:       ${wallet.createdAt}`);
  console.log();

  console.log("Signers:");
  for (let i = 0; i < wallet.signers.length; i++) {
    const descriptor = wallet.signers[i];
    const match = descriptor.match(/^\[([0-9a-fA-F]{8})/);
    const xfp = match ? match[1] : "";
    console.log(`  ${i}:  ${xfp}  ${descriptor}`);
  }

  console.log();
  if (wallet.platformKey) {
    console.log("Platform Key:  Enabled");
    for (const line of formatPoliciesText(wallet.platformKey.policies)) {
      console.log(`  ${line}`);
    }
  } else {
    console.log("Platform Key:  Not configured");
  }
}
