import { describe, expect, it } from "vitest";
import { parseAddressTypeInput } from "../address-type.js";

describe("parseAddressTypeInput", () => {
  it("normalizes case, whitespace, and hyphenated values", () => {
    expect(parseAddressTypeInput(" native-segwit ")).toBe("NATIVE_SEGWIT");
    expect(parseAddressTypeInput("taproot")).toBe("TAPROOT");
  });

  it("rejects unknown address types", () => {
    expect(() => parseAddressTypeInput("anything")).toThrow(
      "Invalid address type: anything. Must be one of: NATIVE_SEGWIT, NESTED_SEGWIT, LEGACY, TAPROOT",
    );
  });
});
