import { describe, expect, it } from "vitest";
import { convertAmount, formatAmount, normalizeCurrency, type MarketRates } from "../currency.js";

const rates: MarketRates = {
  btcUsd: 67183.745,
  forexRates: {
    USD: 1,
    EUR: 0.86804,
    VND: 26340,
  },
};

describe("normalizeCurrency", () => {
  it("normalizes sat aliases", () => {
    expect(normalizeCurrency("sats")).toBe("sat");
    expect(normalizeCurrency("Satoshi")).toBe("sat");
  });

  it("uppercases BTC and fiat currencies", () => {
    expect(normalizeCurrency("btc")).toBe("BTC");
    expect(normalizeCurrency("usd")).toBe("USD");
  });
});

describe("convertAmount", () => {
  it("converts USD to BTC", () => {
    const result = convertAmount(100, "USD", "BTC", rates);
    expect(result.converted).toBeCloseTo(100 / 67183.745, 12);
  });

  it("converts BTC to VND", () => {
    const result = convertAmount(0.01, "BTC", "VND", rates);
    expect(result.converted).toBeCloseTo(0.01 * 67183.745 * 26340, 6);
  });

  it("converts fiat through USD", () => {
    const result = convertAmount(100, "EUR", "VND", rates);
    expect(result.converted).toBeCloseTo((100 / 0.86804) * 26340, 6);
  });

  it("converts sat to USD", () => {
    const result = convertAmount(100000, "sat", "USD", rates);
    expect(result.converted).toBeCloseTo((100000 / 100_000_000) * 67183.745, 12);
  });
});

describe("formatAmount", () => {
  it("formats sat as an integer", () => {
    expect(formatAmount(1000.4, "sat")).toBe("1000");
  });

  it("keeps 8 decimals for BTC", () => {
    expect(formatAmount(0.5653337, "BTC")).toBe("0.56533370");
  });

  it("trims trailing zeros for fiat", () => {
    expect(formatAmount(1.23, "USD")).toBe("1.23");
  });
});
