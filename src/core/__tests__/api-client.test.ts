import { describe, it, expect, vi, afterEach } from "vitest";
import { ApiClient } from "../api-client.js";

describe("ApiClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("wraps fetch failures as NETWORK_ERROR", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("fetch failed")));

    const client = new ApiClient("test-key", "testnet");

    await expect(client.get("/v1.1/shared-wallets/groups")).rejects.toEqual({
      error: "NETWORK_ERROR",
      message:
        "Failed to reach Nunchuk API at https://api-testnet.nunchuk.io. Check network access and try again.",
    });
  });

  it("falls back to the raw backend body for non-standard API errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        text: vi.fn().mockResolvedValue('{"error":"Invalid API key"}'),
      } satisfies Partial<Response>),
    );

    const client = new ApiClient("bad-key", "testnet");

    await expect(client.getMe()).rejects.toEqual({
      error: "401",
      message: '{"error":"Invalid API key"}',
    });
  });
});
