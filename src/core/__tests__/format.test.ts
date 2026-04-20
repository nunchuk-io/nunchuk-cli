import { describe, expect, it } from "vitest";
import { statusFromHeight } from "../format.js";

describe("statusFromHeight", () => {
  it("maps confirmed electrum heights to CONFIRMED", () => {
    expect(statusFromHeight(1)).toBe("CONFIRMED");
  });

  it("maps unconfirmed electrum heights to PENDING_CONFIRMATION", () => {
    expect(statusFromHeight(0)).toBe("PENDING_CONFIRMATION");
    expect(statusFromHeight(-1)).toBe("PENDING_CONFIRMATION");
  });

  it("maps rejected electrum height to NETWORK_REJECTED", () => {
    expect(statusFromHeight(-2)).toBe("NETWORK_REJECTED");
  });
});
