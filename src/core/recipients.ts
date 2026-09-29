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

// -- BIP-21 payment URIs: bitcoin:<address>[?amount=<btc>&label=…&message=…] --

export interface ParsedBtcUri {
  address: string;
  // The `amount` parameter, always in BTC per BIP-21; absent when not given.
  amountBtc?: string;
}

export function isBtcUri(value: string): boolean {
  return /^bitcoin:/i.test(value.trim());
}

// Parse a BIP-21 URI. `label` and `message` are ignored; an unknown `req-`
// parameter is rejected, as the standard requires.
export function parseBtcUri(value: string, source: string): ParsedBtcUri {
  const match = /^bitcoin:([^?#]*)(?:\?([^#]*))?/i.exec(value.trim());
  if (!match) {
    throw invalid(`Invalid BIP-21 URI "${value}" (${source}).`);
  }
  const address = decodeURIComponent(match[1]).trim();
  if (address.length === 0) {
    throw invalid(`Invalid BIP-21 URI "${value}" (${source}): missing address.`);
  }
  let amountBtc: string | undefined;
  for (const pair of (match[2] ?? "").split("&").filter((p) => p.length > 0)) {
    const eq = pair.indexOf("=");
    const key = decodeURIComponent(eq < 0 ? pair : pair.slice(0, eq));
    const val = eq < 0 ? "" : decodeURIComponent(pair.slice(eq + 1));
    if (key === "amount") {
      if (amountBtc !== undefined) {
        throw invalid(`Invalid BIP-21 URI "${value}" (${source}): duplicate amount parameter.`);
      }
      if (val.trim().length === 0) {
        throw invalid(`Invalid BIP-21 URI "${value}" (${source}): empty amount parameter.`);
      }
      amountBtc = val.trim();
    } else if (/^req-/i.test(key)) {
      throw invalid(
        `Invalid BIP-21 URI "${value}" (${source}): unsupported required parameter "${key}".`,
      );
    }
    // label, message, and other optional parameters are ignored.
  }
  return { address, amountBtc };
}

// Combine a possibly-URI address with a row's own amount/currency into a raw
// recipient. A URI amount is BTC and must be the only amount for the row.
function rowFromAddressField(
  addressField: string,
  amountInput: string | undefined,
  currency: string | undefined,
  source: string,
  shapeHint: string,
): RawRecipient {
  if (!isBtcUri(addressField)) {
    if (amountInput === undefined || amountInput.length === 0) {
      throw invalid(`${source}: expected ${shapeHint}.`);
    }
    return { address: addressField, amountInput, currency, source };
  }
  const uri = parseBtcUri(addressField, source);
  if (uri.amountBtc !== undefined) {
    if ((amountInput !== undefined && amountInput.length > 0) || currency) {
      throw invalid(
        `${source}: the bitcoin: URI already carries an amount (in BTC); remove the row's amount and currency.`,
      );
    }
    return { address: uri.address, amountInput: uri.amountBtc, currency: "BTC", source };
  }
  if (amountInput === undefined || amountInput.length === 0) {
    throw invalid(
      `${source}: the bitcoin: URI has no amount; add ?amount=<btc> to it or give an amount.`,
    );
  }
  return { address: uri.address, amountInput, currency, source };
}

// -- --recipient <address>:<amount>[:<currency>] | <bitcoin: URI> --

const RECIPIENT_SHAPE = "<address>:<amount>[:<currency>] or a bitcoin: URI with ?amount=";

// Parse one `--recipient` value. `ordinal` is 1-based and only used for the
// error label. A BIP-21 URI is taken whole (it contains ':' itself) and must
// carry its own amount.
export function parseRecipientOption(value: string, ordinal: number): RawRecipient {
  const source = `--recipient #${ordinal}`;
  if (isBtcUri(value)) {
    return rowFromAddressField(value.trim(), undefined, undefined, source, RECIPIENT_SHAPE);
  }
  const parts = value.split(":").map((p) => p.trim());
  if ((parts.length !== 2 && parts.length !== 3) || parts.some((p) => p.length === 0)) {
    throw invalid(`Invalid --recipient "${value}": expected ${RECIPIENT_SHAPE}.`);
  }
  const [address, amountInput, currency] = parts;
  return { address, amountInput, currency, source };
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
    // 1 column is allowed only for a bitcoin: URI that carries its amount.
    if (
      fields.length > 3 ||
      fields[0].length === 0 ||
      (!isBtcUri(fields[0]) && (fields.length < 2 || fields[1].length === 0))
    ) {
      throw invalid(
        `Recipients file ${filePath} line ${lineNo}: expected address,amount[,currency].`,
      );
    }
    rows.push(
      rowFromAddressField(
        fields[0],
        fields[1],
        fields[2] ? fields[2] : undefined,
        `${filePath} line ${lineNo}`,
        "address,amount[,currency]",
      ),
    );
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
    let amountInput: string | undefined;
    if (typeof amount === "string" && amount.trim().length > 0) {
      amountInput = amount.trim();
    } else if (typeof amount === "number" && Number.isFinite(amount)) {
      // Stringify so the amount goes through the same exact-decimal parsers as
      // a CSV field; floats never reach the sat arithmetic.
      amountInput = String(amount);
    } else if (amount === undefined && isBtcUri(address)) {
      amountInput = undefined; // may come from the URI
    } else {
      throw invalid(`${source}: "amount" must be a number or a numeric string.`);
    }
    if (currency !== undefined && (typeof currency !== "string" || currency.trim() === "")) {
      throw invalid(`${source}: "currency" must be a non-empty string when present.`);
    }
    return rowFromAddressField(
      address.trim(),
      amountInput,
      typeof currency === "string" ? currency.trim() : undefined,
      source,
      '"address" plus "amount" (or a bitcoin: URI with ?amount=)',
    );
  });
}

// -- Resolution: units, amounts, addresses, duplicates --

// scriptPubKey for an address; throws for a malformed or wrong-network address.
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

// Validate raw rows into recipients, in input order. Unit per row: the row's
// currency, else `defaultCurrency`, else sat. Duplicates are compared by script.
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
