import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import { getCliVersion } from "../version.js";

const requirePackage = createRequire(import.meta.url);
const packageJson = requirePackage("../../package.json") as { version: string };

describe("getCliVersion", () => {
  it("matches package.json", () => {
    expect(getCliVersion()).toBe(packageJson.version);
  });
});
