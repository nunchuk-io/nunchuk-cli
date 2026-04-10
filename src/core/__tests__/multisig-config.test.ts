import { describe, expect, it } from "vitest";
import { buildWalletDescriptor, parseSignerDescriptor } from "../descriptor.js";
import { buildMultisigConfig, parseMultisigConfig } from "../multisig-config.js";

const TEST_SIGNERS = [
  "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
];
describe("buildMultisigConfig", () => {
  it("exports derivation paths with m/ prefix", () => {
    const result = buildMultisigConfig("Test Wallet", TEST_SIGNERS, 2, 2, 3);

    expect(result).toBe(
      "# Export from nunchuk-cli\n" +
        "Name: Test Wallet\n" +
        "Policy: 2 of 2\n" +
        "Format: P2WSH\n" +
        "\n" +
        "Derivation: m/48h/1h/0h/2h\n" +
        "534a4a82: tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ\n" +
        "\n" +
        "Derivation: m/48h/1h/0h/2h\n" +
        "4bda0966: tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s\n",
    );
  });

  it("truncates the name to 20 characters", () => {
    const result = buildMultisigConfig("Long Wallet Name For Coldcard", TEST_SIGNERS, 2, 2, 2);

    expect(result).toContain("Name: Long Wallet Name For");
    expect(result).not.toContain("Name: Long Wallet Name For Coldcard");
    expect(result).toContain("Format: P2WSH-P2SH");
  });

  it("exports derivation paths in h notation", () => {
    const result = buildMultisigConfig(
      "Signer Paths",
      ["[1234abcd/48h/1h/0h/2h]tpubExampleOne", "[abcd1234/48h/1h/0h/2h]tpubExampleTwo"],
      2,
      2,
      1,
    );

    expect(result).toContain("Derivation: m/48h/1h/0h/2h");
    expect(result).toContain("Format: P2SH");
  });

  it("supports taproot label parity with libnunchuk", () => {
    const result = buildMultisigConfig("Taproot", TEST_SIGNERS, 2, 2, 4);
    expect(result).toContain("Format: P2TR");
  });

  it("exports root derivation as m", () => {
    const result = buildMultisigConfig(
      "Root Path",
      [`[534a4a82]${TEST_SIGNERS[0].slice(TEST_SIGNERS[0].indexOf("]") + 1)}`],
      1,
      1,
      3,
    );

    expect(result).toContain("Derivation: m");
  });

  it("rejects unsupported address types", () => {
    expect(() => buildMultisigConfig("Bad", TEST_SIGNERS, 2, 2, 0)).toThrow(
      "Unsupported address type",
    );
  });
});

describe("parseMultisigConfig", () => {
  it("parses config exported by buildMultisigConfig", () => {
    const content = buildMultisigConfig("Test Wallet", TEST_SIGNERS, 2, 2, 3);
    const parsed = parseMultisigConfig(content, "testnet");

    expect(parsed).toEqual({
      descriptor: buildWalletDescriptor(TEST_SIGNERS, 2, 3),
      kind: "multisig",
      m: 2,
      n: 2,
      addressType: 3,
      signers: TEST_SIGNERS,
    });
  });

  it("accepts root derivation path m", () => {
    const content = [
      "# Exported from Electrum",
      "Name: Root Path",
      "Policy: 2 of 2",
      "Format: P2SH-P2WSH",
      "",
      "Derivation: m",
      `534A4A82: ${TEST_SIGNERS[0].slice(TEST_SIGNERS[0].indexOf("]") + 1)}`,
      `4BDA0966: ${TEST_SIGNERS[1].slice(TEST_SIGNERS[1].indexOf("]") + 1)}`,
      "",
    ].join("\n");

    const parsed = parseMultisigConfig(content, "testnet");

    expect(parsed.m).toBe(2);
    expect(parsed.addressType).toBe(2);
    expect(parsed.signers).toEqual([
      `[534a4a82]${TEST_SIGNERS[0].slice(TEST_SIGNERS[0].indexOf("]") + 1)}`,
      `[4bda0966]${TEST_SIGNERS[1].slice(TEST_SIGNERS[1].indexOf("]") + 1)}`,
    ]);
    expect(parseSignerDescriptor(parsed.signers[0]).derivationPath).toBe("");
  });

  it("supports a different derivation path per signer", () => {
    const content = [
      "Name: Paths",
      "Policy: 2 of 2",
      "Format: p2wsh",
      "Derivation: m/48h/1h/0h/2h",
      `534A4A82: ${TEST_SIGNERS[0].slice(TEST_SIGNERS[0].indexOf("]") + 1)}`,
      "Derivation: m/45h",
      `4BDA0966: ${TEST_SIGNERS[1].slice(TEST_SIGNERS[1].indexOf("]") + 1)}`,
    ].join("\n");

    const parsed = parseMultisigConfig(content, "testnet");

    expect(parsed.signers).toEqual([
      TEST_SIGNERS[0],
      `[4bda0966/45']${TEST_SIGNERS[1].slice(TEST_SIGNERS[1].indexOf("]") + 1)}`,
    ]);
  });

  it("accepts p2sh-p2wsh format spelling", () => {
    const content = [
      "Name: Nested",
      "Policy: 2/2",
      "Format: P2SH-P2WSH",
      "Derivation: m/48h/1h/0h/1h",
      `534A4A82: ${TEST_SIGNERS[0].slice(TEST_SIGNERS[0].indexOf("]") + 1)}`,
      `4BDA0966: ${TEST_SIGNERS[1].slice(TEST_SIGNERS[1].indexOf("]") + 1)}`,
    ].join("\n");

    const parsed = parseMultisigConfig(content, "testnet");
    expect(parsed.addressType).toBe(2);
  });

  it("rejects signer lines before derivation", () => {
    const content = [
      "Name: Invalid",
      `534A4A82: ${TEST_SIGNERS[0].slice(TEST_SIGNERS[0].indexOf("]") + 1)}`,
    ].join("\n");

    expect(() => parseMultisigConfig(content, "testnet")).toThrow("Invalid derivation path");
  });
});
