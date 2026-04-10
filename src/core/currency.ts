const PRICES_URL = "https://api.nunchuk.io/v1.1/prices";
const FOREX_RATES_URL = "https://api.nunchuk.io/v1.1/forex/rates";
const SATOSHIS_PER_BTC_BIGINT = 100_000_000n;
const SATOSHIS_PER_BTC = Number(SATOSHIS_PER_BTC_BIGINT);
const MAX_BTC_SUPPLY_SATS = 21_000_000n * SATOSHIS_PER_BTC_BIGINT;
const MAX_BTC_SUPPLY_SATS_NUMBER = Number(MAX_BTC_SUPPLY_SATS);

export interface MarketRates {
  btcUsd: number;
  forexRates: Record<string, number>;
}

export function normalizeCurrency(input: string): string {
  const value = input.trim();
  if (!value) {
    throw new Error("Currency is required");
  }

  const lower = value.toLowerCase();
  if (lower === "sat" || lower === "sats" || lower === "satoshi" || lower === "satoshis") {
    return "sat";
  }

  return value.toUpperCase();
}

function getForexRate(currency: string, rates: Record<string, number>): number {
  const rate = rates[currency];
  if (!Number.isFinite(rate) || rate <= 0) {
    throw new Error(`Unsupported currency: ${currency}`);
  }
  return rate;
}

function toUsd(amount: number, currency: string, rates: MarketRates): number {
  switch (currency) {
    case "USD":
      return amount;
    case "BTC":
      return amount * rates.btcUsd;
    case "sat":
      return (amount / SATOSHIS_PER_BTC) * rates.btcUsd;
    default:
      return amount / getForexRate(currency, rates.forexRates);
  }
}

function fromUsd(amountUsd: number, currency: string, rates: MarketRates): number {
  switch (currency) {
    case "USD":
      return amountUsd;
    case "BTC":
      return amountUsd / rates.btcUsd;
    case "sat":
      return (amountUsd / rates.btcUsd) * SATOSHIS_PER_BTC;
    default:
      return amountUsd * getForexRate(currency, rates.forexRates);
  }
}

export function convertAmount(
  amount: number,
  fromCurrencyInput: string,
  toCurrencyInput: string,
  rates: MarketRates,
): { from: string; to: string; converted: number } {
  if (!Number.isFinite(amount) || amount < 0) {
    throw new Error("Amount must be a non-negative number");
  }

  const from = normalizeCurrency(fromCurrencyInput);
  const to = normalizeCurrency(toCurrencyInput);

  if (from === to) {
    return { from, to, converted: amount };
  }

  const amountUsd = toUsd(amount, from, rates);
  const converted = fromUsd(amountUsd, to, rates);
  return { from, to, converted };
}

function parseSatsInput(amountInput: string): bigint {
  const value = amountInput.trim();
  if (!/^\d+$/.test(value)) {
    throw new Error("Satoshi amount must be a whole number");
  }

  return assertWithinMaxBitcoinSupply(BigInt(value));
}

function parseBtcInputToSats(amountInput: string): bigint {
  const value = amountInput.trim();
  const [wholePart = "", fractionPart = "", extraPart] = value.split(".");
  if (extraPart !== undefined || !/^\d+$/.test(wholePart + fractionPart)) {
    throw new Error("Amount must be a non-negative decimal number");
  }
  if (fractionPart.length > 8) {
    throw new Error("BTC amount supports at most 8 decimal places");
  }

  const wholeSats = BigInt(wholePart || "0") * SATOSHIS_PER_BTC_BIGINT;
  const fractionSats = BigInt(fractionPart.padEnd(8, "0") || "0");
  return assertWithinMaxBitcoinSupply(wholeSats + fractionSats);
}

function parseFiatAmount(amountInput: string): number {
  const amount = Number(amountInput);
  if (!Number.isFinite(amount) || amount < 0) {
    throw new Error("Amount must be a non-negative number");
  }
  return amount;
}

function roundedSatsToBigInt(sats: number): bigint {
  const rounded = Math.round(sats);
  if (!Number.isFinite(rounded)) {
    throw new Error("Converted satoshi amount is too large to convert safely");
  }
  if (rounded > MAX_BTC_SUPPLY_SATS_NUMBER) {
    throw new Error("Amount exceeds maximum Bitcoin supply");
  }
  return BigInt(rounded);
}

function assertWithinMaxBitcoinSupply(sats: bigint): bigint {
  if (sats > MAX_BTC_SUPPLY_SATS) {
    throw new Error("Amount exceeds maximum Bitcoin supply");
  }
  return sats;
}

export function convertAmountInputToSats(
  amountInput: string,
  currencyInput: string,
  rates?: MarketRates,
): bigint {
  const currency = normalizeCurrency(currencyInput);

  if (currency === "sat") {
    return parseSatsInput(amountInput);
  }

  if (currency === "BTC") {
    return parseBtcInputToSats(amountInput);
  }

  if (!rates) {
    throw new Error(`Market rates are required to convert ${currency} to sat`);
  }

  return roundedSatsToBigInt(
    convertAmount(parseFiatAmount(amountInput), currency, "sat", rates).converted,
  );
}

export function formatAmount(amount: number, currencyInput: string): string {
  const currency = normalizeCurrency(currencyInput);

  if (currency === "sat") {
    return String(Math.round(amount));
  }

  if (currency === "BTC") {
    return amount.toFixed(8);
  }

  return amount.toFixed(6).replace(/\.?0+$/, "");
}

export async function fetchMarketRates(): Promise<MarketRates> {
  let pricesResponse: Response;
  let forexResponse: Response;

  try {
    [pricesResponse, forexResponse] = await Promise.all([
      fetch(PRICES_URL),
      fetch(FOREX_RATES_URL),
    ]);
  } catch {
    throw new Error("Failed to fetch market rates from Nunchuk API");
  }

  const [pricesBody, forexBody] = await Promise.all([pricesResponse.text(), forexResponse.text()]);

  if (!pricesResponse.ok) {
    throw new Error(pricesBody || pricesResponse.statusText || "Failed to fetch BTC price");
  }
  if (!forexResponse.ok) {
    throw new Error(forexBody || forexResponse.statusText || "Failed to fetch forex rates");
  }

  let parsedPrices: unknown;
  let parsedForex: unknown;

  try {
    parsedPrices = pricesBody ? JSON.parse(pricesBody) : {};
    parsedForex = forexBody ? JSON.parse(forexBody) : {};
  } catch {
    throw new Error("Failed to parse market rates response");
  }

  const btcUsd =
    typeof parsedPrices === "object" &&
    parsedPrices !== null &&
    "data" in parsedPrices &&
    typeof parsedPrices.data === "object" &&
    parsedPrices.data !== null &&
    "prices" in parsedPrices.data &&
    typeof parsedPrices.data.prices === "object" &&
    parsedPrices.data.prices !== null &&
    "BTC" in parsedPrices.data.prices &&
    typeof parsedPrices.data.prices.BTC === "object" &&
    parsedPrices.data.prices.BTC !== null &&
    "USD" in parsedPrices.data.prices.BTC &&
    typeof parsedPrices.data.prices.BTC.USD === "number"
      ? parsedPrices.data.prices.BTC.USD
      : null;

  if (btcUsd == null || !Number.isFinite(btcUsd) || btcUsd <= 0) {
    throw new Error("Invalid BTC price response");
  }

  if (typeof parsedForex !== "object" || parsedForex === null || Array.isArray(parsedForex)) {
    throw new Error("Invalid forex rates response");
  }

  return {
    btcUsd,
    forexRates: parsedForex as Record<string, number>,
  };
}
