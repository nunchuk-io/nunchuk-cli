import { afterEach, describe, expect, it, vi } from "vitest";
import { estimateFeeRate } from "../fees.js";
import type { ElectrumClient } from "../electrum.js";

const RECOMMENDED = {
  fastestFee: 30_000,
  halfHourFee: 20_000,
  hourFee: 10_000,
  minimumFee: 1_000,
};

function mockFetchOk(body: unknown): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: true,
      json: async () => body,
    })),
  );
}

function fakeElectrum(estimate: number): ElectrumClient {
  return { estimateFee: vi.fn(async () => estimate) } as unknown as ElectrumClient;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("estimateFeeRate", () => {
  it("maps economy → hourFee (sat/kvB → sat/vB)", async () => {
    mockFetchOk(RECOMMENDED);
    expect(await estimateFeeRate("mainnet", fakeElectrum(0), "economy")).toBe(10n);
  });

  it("maps standard → halfHourFee", async () => {
    mockFetchOk(RECOMMENDED);
    expect(await estimateFeeRate("mainnet", fakeElectrum(0), "standard")).toBe(20n);
  });

  it("maps priority → fastestFee", async () => {
    mockFetchOk(RECOMMENDED);
    expect(await estimateFeeRate("mainnet", fakeElectrum(0), "priority")).toBe(30n);
  });

  it("defaults to economy when no level is given", async () => {
    mockFetchOk(RECOMMENDED);
    expect(await estimateFeeRate("mainnet", fakeElectrum(0))).toBe(10n);
  });

  it("falls back to Electrum with the level's conf_target when the API fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) })),
    );
    const electrum = fakeElectrum(0.000_05); // 0.00005 BTC/kvB → 5 sat/vB
    expect(await estimateFeeRate("mainnet", electrum, "priority")).toBe(5n);
    expect(electrum.estimateFee).toHaveBeenCalledWith(2);
  });

  it("returns 1 sat/vB when both API and Electrum yield nothing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) })),
    );
    expect(await estimateFeeRate("mainnet", fakeElectrum(0), "economy")).toBe(1n);
  });
});
