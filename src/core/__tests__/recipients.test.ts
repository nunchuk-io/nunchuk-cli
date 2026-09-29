import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseRecipientOption, parseRecipientsFile, resolveRecipients } from "../recipients.js";
import type { MarketRates } from "../currency.js";

// Valid mainnet addresses of different script types (BIP-173 / well-known vectors).
const P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const P2WSH = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
const P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
const P2PKH = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
const TESTNET_P2WPKH = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

const RATES: MarketRates = { btcUsd: 100_000, forexRates: { EUR: 0.5 } };

const tempDirs: string[] = [];
function writeTemp(name: string, content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nunchuk-recipients-"));
  tempDirs.push(dir);
  const file = path.join(dir, name);
  fs.writeFileSync(file, content);
  return file;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("parseRecipientOption", () => {
  it("parses address:amount and address:amount:currency", () => {
    expect(parseRecipientOption(`${P2WPKH}:100000`, 1)).toEqual({
      address: P2WPKH,
      amountInput: "100000",
      currency: undefined,
      source: "--recipient #1",
    });
    expect(parseRecipientOption(` ${P2WPKH} : 25.50 : usd `, 2)).toEqual({
      address: P2WPKH,
      amountInput: "25.50",
      currency: "usd",
      source: "--recipient #2",
    });
  });

  it("rejects a missing amount, an empty part, and a BIP-21 URI by shape", () => {
    const expected = /expected <address>:<amount>\[:<currency>\]/;
    expect(() => parseRecipientOption(P2WPKH, 1)).toThrow(expected);
    expect(() => parseRecipientOption(":5", 1)).toThrow(expected);
    expect(() => parseRecipientOption(`${P2WPKH}:100:`, 1)).toThrow(expected);
    expect(() => parseRecipientOption(`bitcoin:${P2WPKH}?amount=0.01`, 1)).toThrow(expected);
    expect(() => parseRecipientOption(`${P2WPKH}:1:usd:extra`, 1)).toThrow(expected);
  });

  it("throws a structured INVALID_PARAM error", () => {
    try {
      parseRecipientOption("nope", 3);
      expect.unreachable();
    } catch (err) {
      expect(err).toEqual({
        error: "INVALID_PARAM",
        message: 'Invalid --recipient "nope": expected <address>:<amount>[:<currency>].',
      });
    }
  });
});

describe("parseRecipientsFile", () => {
  it("parses CSV with comments, a header, CRLF, blank lines, whitespace, and an optional currency column", () => {
    const file = writeTemp(
      "payouts.csv",
      `# Q3 payouts\r\nAddress,Amount,Currency\r\n\r\n ${P2WPKH} , 100000 ,\r\n${P2WSH},250,USD\r\n${P2TR},0.5,btc\r\n`,
    );
    expect(parseRecipientsFile(file)).toEqual([
      { address: P2WPKH, amountInput: "100000", currency: undefined, source: `${file} line 4` },
      { address: P2WSH, amountInput: "250", currency: "USD", source: `${file} line 5` },
      { address: P2TR, amountInput: "0.5", currency: "btc", source: `${file} line 6` },
    ]);
  });

  it("parses CSV without a header and with two columns only", () => {
    const file = writeTemp("two.csv", `${P2WPKH},1000\n${P2WSH},2000\n`);
    expect(parseRecipientsFile(file).map((r) => r.amountInput)).toEqual(["1000", "2000"]);
  });

  it("rejects a CSV row with the wrong number of columns, naming the line", () => {
    const file = writeTemp("bad.csv", `${P2WPKH},1000\n${P2WSH}\n`);
    expect(() => parseRecipientsFile(file)).toThrow(
      expect.objectContaining({
        error: "INVALID_PARAM",
        message: `Recipients file ${file} line 2: expected address,amount[,currency].`,
      }),
    );
  });

  it("parses a JSON array with string and numeric amounts and an optional currency", () => {
    const file = writeTemp(
      "payouts.json",
      JSON.stringify([
        { address: P2WPKH, amount: "100000" },
        { address: P2WSH, amount: 250000, label: "ignored" },
        { address: P2TR, amount: 250, currency: "EUR" },
      ]),
    );
    expect(parseRecipientsFile(file)).toEqual([
      { address: P2WPKH, amountInput: "100000", currency: undefined, source: `${file} item 1` },
      { address: P2WSH, amountInput: "250000", currency: undefined, source: `${file} item 2` },
      { address: P2TR, amountInput: "250", currency: "EUR", source: `${file} item 3` },
    ]);
  });

  it("rejects JSON that is not an array, and items missing address or amount", () => {
    const notArray = writeTemp("obj.json", JSON.stringify({ address: P2WPKH, amount: 1 }));
    expect(() => parseRecipientsFile(notArray)).toThrow(/expected a JSON array/);

    const badItem = writeTemp("item.json", JSON.stringify([{ address: P2WPKH }]));
    expect(() => parseRecipientsFile(badItem)).toThrow(/item 1: "amount" must be a number/);

    const invalidJson = writeTemp("broken.json", "[ { address: oops ]");
    expect(() => parseRecipientsFile(invalidJson)).toThrow(/is not valid JSON/);
  });

  it("rejects an empty file (comments and header only)", () => {
    const file = writeTemp("empty.csv", "# nothing here\naddress,amount\n");
    expect(() => parseRecipientsFile(file)).toThrow(
      expect.objectContaining({
        error: "INVALID_PARAM",
        message: `Recipients file ${file} is empty.`,
      }),
    );
  });

  it("reports a missing file as FILE_NOT_FOUND", () => {
    const missing = path.join(os.tmpdir(), "definitely-missing-recipients.csv");
    expect(() => parseRecipientsFile(missing)).toThrow(
      expect.objectContaining({
        error: "FILE_NOT_FOUND",
        message: `Could not read file: ${missing}`,
      }),
    );
  });
});

describe("resolveRecipients", () => {
  const raw = (address: string, amountInput: string, currency?: string, source = "row") => ({
    address,
    amountInput,
    currency,
    source,
  });

  it("converts sat amounts in input order without fetching rates", async () => {
    const fetchRates = vi.fn(async () => RATES);
    const recipients = await resolveRecipients(
      [raw(P2WPKH, "100000"), raw(P2WSH, "250000"), raw(P2TR, "1"), raw(P2PKH, "546")],
      "mainnet",
      { fetchRates },
    );
    expect(recipients).toEqual([
      { address: P2WPKH, amount: 100_000n },
      { address: P2WSH, amount: 250_000n },
      { address: P2TR, amount: 1n },
      { address: P2PKH, amount: 546n },
    ]);
    expect(fetchRates).not.toHaveBeenCalled();
  });

  it("applies --currency as the default unit and lets a row unit override it", async () => {
    const fetchRates = vi.fn(async () => RATES);
    const recipients = await resolveRecipients(
      [raw(P2WPKH, "0.5"), raw(P2WSH, "100", "USD"), raw(P2TR, "100000", "sat")],
      "mainnet",
      { defaultCurrency: "BTC", fetchRates },
    );
    expect(recipients.map((r) => r.amount)).toEqual([50_000_000n, 100_000n, 100_000n]);
  });

  it("fetches market rates exactly once for mixed fiat rows", async () => {
    const fetchRates = vi.fn(async () => RATES);
    const recipients = await resolveRecipients(
      [raw(P2WPKH, "100", "usd"), raw(P2WSH, "50", "EUR"), raw(P2TR, "0.002", "btc")],
      "mainnet",
      { fetchRates },
    );
    expect(recipients.map((r) => r.amount)).toEqual([100_000n, 100_000n, 200_000n]);
    expect(fetchRates).toHaveBeenCalledTimes(1);
  });

  it("rejects an unsupported currency, naming the row", async () => {
    await expect(
      resolveRecipients([raw(P2WPKH, "100", "XYZ", "--recipient #1")], "mainnet", {
        fetchRates: async () => RATES,
      }),
    ).rejects.toEqual({
      error: "INVALID_PARAM",
      message: "Unsupported currency: XYZ (--recipient #1).",
    });
  });

  it("rejects zero, negative, and fractional-sat amounts, naming the row", async () => {
    await expect(
      resolveRecipients([raw(P2WPKH, "0", undefined, "f.csv line 2")], "mainnet"),
    ).rejects.toEqual({
      error: "INVALID_PARAM",
      message: 'Amount "0" (f.csv line 2) must convert to at least 1 sat.',
    });
    await expect(resolveRecipients([raw(P2WPKH, "-5")], "mainnet")).rejects.toMatchObject({
      error: "INVALID_PARAM",
      message: expect.stringMatching(/whole number \(row\)\.$/),
    });
    await expect(resolveRecipients([raw(P2WPKH, "0.5")], "mainnet")).rejects.toMatchObject({
      error: "INVALID_PARAM",
      message: expect.stringMatching(/whole number \(row\)\.$/),
    });
    // A fiat amount that rounds to 0 sat.
    await expect(
      resolveRecipients([raw(P2WPKH, "0.000001", "USD")], "mainnet", {
        fetchRates: async () => RATES,
      }),
    ).rejects.toMatchObject({ message: expect.stringMatching(/at least 1 sat/) });
  });

  it("rejects a malformed address and a wrong-network address, naming the row", async () => {
    await expect(
      resolveRecipients([raw("notanaddress", "1000", undefined, "--recipient #1")], "mainnet"),
    ).rejects.toEqual({
      error: "INVALID_PARAM",
      message: 'Invalid address "notanaddress" (--recipient #1).',
    });
    await expect(
      resolveRecipients([raw(TESTNET_P2WPKH, "1000", undefined, "p.csv line 3")], "mainnet"),
    ).rejects.toEqual({
      error: "INVALID_PARAM",
      message: `Invalid address "${TESTNET_P2WPKH}" (p.csv line 3).`,
    });
    // And the same address is fine on its own network.
    await expect(resolveRecipients([raw(TESTNET_P2WPKH, "1000")], "testnet")).resolves.toEqual([
      { address: TESTNET_P2WPKH, amount: 1000n },
    ]);
  });

  it("rejects duplicates by output script, including a bech32 address in another letter case", async () => {
    await expect(
      resolveRecipients(
        [
          raw(P2WPKH, "1000", undefined, "line 1"),
          raw(P2WPKH.toUpperCase(), "2000", undefined, "line 2"),
        ],
        "mainnet",
      ),
    ).rejects.toEqual({
      error: "INVALID_PARAM",
      message: `Duplicate recipient ${P2WPKH.toUpperCase()} (line 2); merge the amounts into one row.`,
    });
  });

  it("rejects an empty list", async () => {
    await expect(resolveRecipients([], "mainnet")).rejects.toMatchObject({
      error: "INVALID_PARAM",
    });
  });
});
