import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseDescriptor } from "../descriptor.js";
import {
  buildMiniscriptDescriptor,
  getScriptNode,
  isValidMiniscriptTemplate,
  normalizeMiniscriptTemplate,
  parseMiniscript,
  policyToMiniscript,
  scriptNodeToString,
} from "../miniscript.js";

type LibnunchukRequest = {
  action: string;
  addressType?: string;
  config?: Record<string, string>;
  descriptor?: string;
  miniscript?: string;
  policy?: string;
};
type LibnunchukResponse = {
  addressType?: number;
  descriptor?: string;
  error?: string;
  m?: number;
  miniscript?: string;
  n?: number;
  ok: boolean;
  scriptNode?: string | null;
  signers?: string[];
  walletTemplateValid?: boolean;
  walletType?: number;
} & Record<string, unknown>;
type FixtureEntry = { request: LibnunchukRequest; response: LibnunchukResponse };
type LibnunchukParityFixture = {
  descriptorChecksums: FixtureEntry[];
  descriptorMetadata: FixtureEntry[];
  invalidTemplates: FixtureEntry[];
  policyCompilation: FixtureEntry[];
  validTemplates: FixtureEntry[];
};
type TemplateCoverageCase = {
  abbreviated?: string;
  descriptor?: string;
  error?: string;
  miniscript: string;
  ok: boolean;
  sane?: boolean;
  scriptNode?: string | null;
  validTopLevel?: boolean;
  walletTemplateValid: boolean;
};
type TemplateCoverageFixture = {
  cases: TemplateCoverageCase[];
};

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/miniscript-libnunchuk-parity.json", import.meta.url), "utf8"),
) as LibnunchukParityFixture;
const templateCoverage = JSON.parse(
  readFileSync(
    new URL("./fixtures/miniscript-libnunchuk-template-coverage.json", import.meta.url),
    "utf8",
  ),
) as TemplateCoverageFixture;

describe("libnunchuk miniscript parity", () => {
  it("matches libnunchuk policy compilation for native segwit miniscript", () => {
    for (const { request, response } of fixture.policyCompilation) {
      expect(response.ok, response.error).toBe(true);
      expect(request.policy).toBeDefined();
      expect(policyToMiniscript(request.policy!, request.config ?? {}, "NATIVE_SEGWIT")).toBe(
        response.miniscript,
      );
    }
  });

  it("matches libnunchuk sane validation and script-node rendering", () => {
    for (const { request, response } of fixture.validTemplates) {
      const miniscript = request.miniscript!;
      expect(response.ok, response.error).toBe(true);
      expect(response.walletTemplateValid).toBe(true);
      expect(isValidMiniscriptTemplate(miniscript, "NATIVE_SEGWIT")).toBe(true);
      expect(scriptNodeToString(getScriptNode(miniscript).node)).toBe(response.scriptNode);
    }
  });

  it("matches libnunchuk rejection for invalid or non-sane native segwit miniscript", () => {
    for (const { request, response } of fixture.invalidTemplates) {
      const normalizedMiniscript = normalizeMiniscriptTemplate(request.miniscript!);
      if (normalizedMiniscript !== request.miniscript) {
        expect(isValidMiniscriptTemplate(normalizedMiniscript, "NATIVE_SEGWIT")).toBe(true);
        continue;
      }

      const libnunchukWalletValid = response.ok && response.walletTemplateValid === true;
      expect(libnunchukWalletValid, JSON.stringify(response)).toBe(false);
      expect(isValidMiniscriptTemplate(request.miniscript!, "NATIVE_SEGWIT")).toBe(false);
    }
  });

  it("matches libnunchuk descriptor checksums for miniscript", () => {
    for (const { request, response } of fixture.descriptorChecksums) {
      expect(response.ok, response.error).toBe(true);
      expect(buildMiniscriptDescriptor(request.miniscript!, "NATIVE_SEGWIT")).toBe(
        response.descriptor,
      );
    }
  });

  it("matches libnunchuk descriptor parsing metadata", () => {
    const [{ request, response }] = fixture.descriptorMetadata;
    const parsed = parseDescriptor(request.descriptor!);

    expect(response.ok, response.error).toBe(true);
    expect(parsed.kind).toBe("miniscript");
    expect(parsed.addressType).toBe("NATIVE_SEGWIT");
    expect(response.addressType).toBe(3);
    expect(response.walletType).toBe(3);
    expect(response.m).toBe(parsed.m);
    expect(response.n).toBe(parsed.n);
    expect(response.signers).toEqual(parsed.signers);
  });

  it("matches libnunchuk across native segwit miniscript template fragments", () => {
    for (const testCase of templateCoverage.cases) {
      if (testCase.ok) {
        expect(() => parseMiniscript(testCase.miniscript, "NATIVE_SEGWIT")).not.toThrow();
      } else {
        expect(() => parseMiniscript(testCase.miniscript, "NATIVE_SEGWIT")).toThrow();
      }

      expect(isValidMiniscriptTemplate(testCase.miniscript, "NATIVE_SEGWIT")).toBe(
        testCase.walletTemplateValid,
      );

      if (!testCase.walletTemplateValid) continue;

      expect(scriptNodeToString(getScriptNode(testCase.miniscript).node)).toBe(testCase.scriptNode);
      expect(buildMiniscriptDescriptor(testCase.miniscript, "NATIVE_SEGWIT")).toBe(
        testCase.descriptor,
      );
    }
  });
});
