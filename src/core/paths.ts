import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import type { Network } from "./config.js";

export function getCliHome(): string {
  return process.env.NUNCHUK_CLI_HOME || path.join(os.homedir(), ".nunchuk-cli");
}

export function getConfigFile(): string {
  return path.join(getCliHome(), "config.json");
}

export function getEmailHash(email: string): string {
  return crypto.createHash("sha256").update(email).digest("hex").slice(0, 16);
}

export function getAccountStorageDir(email: string, network: Network): string {
  return path.join(getCliHome(), "data", getEmailHash(email), network);
}

export function getMasterKeyFile(): string {
  return path.join(getCliHome(), ".master-key");
}

export function getStorageDatabaseFile(email: string, network: Network): string {
  return path.join(getAccountStorageDir(email, network), "storage.sqlite");
}
