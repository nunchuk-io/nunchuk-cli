import { describe, expect, it } from "vitest";
import { formatDateTime, statusFromHeight } from "../format.js";

describe("formatDateTime", () => {
  // Build inputs from local-time components so expectations are
  // timezone-independent.
  it("renders MM-DD-YYYY hh:mm AM/PM in local time", () => {
    const afternoon = new Date(2026, 6, 6, 14, 5); // July 6 2026, 14:05 local
    expect(formatDateTime(afternoon.getTime() / 1000)).toBe("07-06-2026 02:05 PM");

    const morning = new Date(2026, 0, 3, 9, 30);
    expect(formatDateTime(morning.getTime() / 1000)).toBe("01-03-2026 09:30 AM");
  });

  it("renders 12 AM / 12 PM at the day boundaries", () => {
    const midnight = new Date(2026, 6, 6, 0, 0);
    expect(formatDateTime(midnight.getTime() / 1000)).toBe("07-06-2026 12:00 AM");

    const noon = new Date(2026, 6, 6, 12, 0);
    expect(formatDateTime(noon.getTime() / 1000)).toBe("07-06-2026 12:00 PM");
  });
});

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
