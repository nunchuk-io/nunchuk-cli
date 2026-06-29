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

describe("estimateFeeRate (sat/kvB)", () => {
  it("maps economy → hourFee", async () => {
    mockFetchOk(RECOMMENDED);
    expect(await estimateFeeRate("mainnet", fakeElectrum(0), "economy")).toBe(10_000n);
  });

  it("maps standard → halfHourFee", async () => {
    mockFetchOk(RECOMMENDED);
    expect(await estimateFeeRate("mainnet", fakeElectrum(0), "standard")).toBe(20_000n);
  });

  it("maps priority → fastestFee", async () => {
    mockFetchOk(RECOMMENDED);
    expect(await estimateFeeRate("mainnet", fakeElectrum(0), "priority")).toBe(30_000n);
  });

  it("defaults to economy when no level is given", async () => {
    mockFetchOk(RECOMMENDED);
    expect(await estimateFeeRate("mainnet", fakeElectrum(0))).toBe(10_000n);
  });

  it("falls back to Electrum with the level's conf_target when the API fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) })),
    );
    const electrum = fakeElectrum(0.000_05); // 0.00005 BTC/kvB → 5000 sat/kvB
    expect(await estimateFeeRate("mainnet", electrum, "priority")).toBe(5_000n);
    expect(electrum.estimateFee).toHaveBeenCalledWith(2);
  });

  it("returns the 1 sat/vB floor (1000 sat/kvB) when both API and Electrum yield nothing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) })),
    );
    expect(await estimateFeeRate("mainnet", fakeElectrum(0), "economy")).toBe(1_000n);
  });
});
