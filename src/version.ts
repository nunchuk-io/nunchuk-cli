import { createRequire } from "node:module";

const requirePackage = createRequire(import.meta.url);

type PackageMetadata = {
  version?: unknown;
};

export function getCliVersion(): string {
  const packageJson = requirePackage("../package.json") as PackageMetadata;

  if (typeof packageJson.version !== "string" || packageJson.version.length === 0) {
    throw new Error("Invalid package version");
  }

  return packageJson.version;
}
