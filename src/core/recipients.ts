// Recipient lists for `tx create` / `tx draft`: parse the `--recipient
// <address>:<amount>[:<currency>]` flag and CSV/JSON recipient files, then
// resolve every row to a validated { address, amount(sats) } in input order.
//
// Errors are plain `{ error, message }` objects (like psbt-import.ts) so the
// command layer can print them as structured JSON.

import fs from "node:fs";
import { NETWORK, TEST_NETWORK, Transaction } from "@scure/btc-signer";
import type { Network } from "./config.js";
import {
  convertAmountInputToSats,
  fetchMarketRates,
  normalizeCurrency,
  type MarketRates,
} from "./currency.js";
import type { TxRecipient } from "./transaction.js";

export interface RecipientsError {
  error: "INVALID_PARAM" | "FILE_NOT_FOUND";
  message: string;
}

// A recipient as written by the user, before amount conversion and address
// validation. `source` labels the row/flag in error messages
// ("--recipient #2", "payouts.csv line 4", "payouts.json item 3").
export interface RawRecipient {
  address: string;
  amountInput: string;
  currency?: string;
  source: string;
}

function invalid(message: string): RecipientsError {
  return { error: "INVALID_PARAM", message };
}

// -- --recipient <address>:<amount>[:<currency>] --

const RECIPIENT_SHAPE = "<address>:<amount>[:<currency>]";

// Parse one `--recipient` value. `ordinal` is 1-based and only used for the
// error label. A BIP-21 `bitcoin:` URI or any other shape fails here.
export function parseRecipientOption(value: string, ordinal: number): RawRecipient {
  const parts = value.split(":").map((p) => p.trim());
  if (/^bitcoin$/i.test(parts[0] ?? "")) {
    throw invalid(
      `Invalid --recipient "${value}": expected ${RECIPIENT_SHAPE} (BIP-21 "bitcoin:" URIs are not accepted).`,
    );
  }
  if ((parts.length !== 2 && parts.length !== 3) || parts.some((p) => p.length === 0)) {
    throw invalid(`Invalid --recipient "${value}": expected ${RECIPIENT_SHAPE}.`);
  }
  const [address, amountInput, currency] = parts;
  return { address, amountInput, currency, source: `--recipient #${ordinal}` };
}

// -- Recipients file (CSV or JSON, detected by content) --

export function parseRecipientsFile(filePath: string): RawRecipient[] {
  let text: string;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch {
    throw {
      error: "FILE_NOT_FOUND",
      message: `Could not read file: ${filePath}`,
    } as RecipientsError;
  }
  const trimmed = text.replace(/^\uFEFF/, "").trim();
  const rows =
    trimmed.startsWith("[") || trimmed.startsWith("{")
      ? parseJsonRecipients(trimmed, filePath)
      : parseCsvRecipients(trimmed, filePath);
  if (rows.length === 0) {
    throw invalid(`Recipients file ${filePath} is empty.`);
  }
  return rows;
}

function parseCsvRecipients(text: string, filePath: string): RawRecipient[] {
  const rows: RawRecipient[] = [];
  const lines = text.split(/\r?\n/);
  let headerSeen = false;
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = lines[i].trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const fields = line.split(",").map((f) => f.trim());
    if (
      !headerSeen &&
      rows.length === 0 &&
      fields[0]?.toLowerCase() === "address" &&
      fields[1]?.toLowerCase() === "amount"
    ) {
      headerSeen = true;
      continue;
    }
    if (
      (fields.length !== 2 && fields.length !== 3) ||
      fields[0].length === 0 ||
      fields[1].length === 0
    ) {
      throw invalid(
        `Recipients file ${filePath} line ${lineNo}: expected address,amount[,currency].`,
      );
    }
    rows.push({
      address: fields[0],
      amountInput: fields[1],
      currency: fields[2] ? fields[2] : undefined,
      source: `${filePath} line ${lineNo}`,
    });
  }
  return rows;
}

function parseJsonRecipients(text: string, filePath: string): RawRecipient[] {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw invalid(`Recipients file ${filePath} is not valid JSON.`);
  }
  if (!Array.isArray(data)) {
    throw invalid(
      `Recipients file ${filePath}: expected a JSON array of { "address", "amount" } objects.`,
    );
  }
  return data.map((item, i) => {
    const source = `${filePath} item ${i + 1}`;
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw invalid(`${source}: expected an object with "address" and "amount".`);
    }
    const { address, amount, currency } = item as Record<string, unknown>;
    if (typeof address !== "string" || address.trim().length === 0) {
      throw invalid(`${source}: "address" must be a non-empty string.`);
    }
    let amountInput: string;
    if (typeof amount === "string" && amount.trim().length > 0) {
      amountInput = amount.trim();
    } else if (typeof amount === "number" && Number.isFinite(amount)) {
      // Stringify so the amount goes through the same exact-decimal parsers as
      // a CSV field; floats never reach the sat arithmetic.
      amountInput = String(amount);
    } else {
      throw invalid(`${source}: "amount" must be a number or a numeric string.`);
    }
    if (currency !== undefined && (typeof currency !== "string" || currency.trim() === "")) {
      throw invalid(`${source}: "currency" must be a non-empty string when present.`);
    }
    return {
      address: address.trim(),
      amountInput,
      currency: typeof currency === "string" ? currency.trim() : undefined,
      source,
    };
  });
}

// -- Resolution: units, amounts, addresses, duplicates --

// scriptPubKey for an address on the given network; throws for a malformed or
// wrong-network address. Same check createTransaction performs, done earlier
// so the error can name the row.
function outputScriptForAddress(address: string, network: Network): Uint8Array {
  const btcNet = network === "mainnet" ? NETWORK : TEST_NETWORK;
  const tx = new Transaction({ allowUnknownInputs: true, disableScriptCheck: true });
  tx.addOutputAddress(address, 1n, btcNet);
  const script = tx.getOutput(0).script;
  if (!script) throw new Error("no script");
  return script;
}

export interface ResolveRecipientsOptions {
  // Unit for rows that carry none (the invocation's --currency). Default "sat".
  defaultCurrency?: string;
  // Injectable for tests; fetched at most once per call, only when needed.
  fetchRates?: () => Promise<MarketRates>;
}

// Turn raw rows into validated recipients, in input order. Unit precedence per
// row: the row's own currency, then `defaultCurrency`, then sat. Rejects an
// unknown currency, an amount below 1 sat, an invalid address for the network,
// and a duplicate address (compared by output script).
export async function resolveRecipients(
  raw: RawRecipient[],
  network: Network,
  options: ResolveRecipientsOptions = {},
): Promise<TxRecipient[]> {
  if (raw.length === 0) {
    throw invalid("At least one recipient is required.");
  }
  const defaultUnit = options.defaultCurrency ?? "sat";
  const units = raw.map((r) => {
    try {
      return normalizeCurrency(r.currency ?? defaultUnit);
    } catch (err) {
      throw invalid(`${(err as Error).message} (${r.source}).`);
    }
  });

  const needsRates = units.some((u) => u !== "sat" && u !== "BTC");
  const rates = needsRates ? await (options.fetchRates ?? fetchMarketRates)() : undefined;

  const seenScripts = new Map<string, string>();
  const recipients: TxRecipient[] = [];
  for (let i = 0; i < raw.length; i++) {
    const row = raw[i];
    let amount: bigint;
    try {
      amount = convertAmountInputToSats(row.amountInput, units[i], rates);
    } catch (err) {
      throw invalid(`${(err as Error).message.replace(/\.$/, "")} (${row.source}).`);
    }
    if (amount < 1n) {
      throw invalid(`Amount "${row.amountInput}" (${row.source}) must convert to at least 1 sat.`);
    }

    let script: Uint8Array;
    try {
      script = outputScriptForAddress(row.address, network);
    } catch {
      throw invalid(`Invalid address "${row.address}" (${row.source}).`);
    }
    const key = Buffer.from(script).toString("hex");
    if (seenScripts.has(key)) {
      throw invalid(
        `Duplicate recipient ${row.address} (${row.source}); merge the amounts into one row.`,
      );
    }
    seenScripts.set(key, row.source);

    recipients.push({ address: row.address, amount });
  }
  return recipients;
}
