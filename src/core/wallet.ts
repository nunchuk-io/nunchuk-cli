// Wallet business logic (importable as library)
// Reference: libnunchuk RecoverGroupWallet (nunchukgroupwallet.cpp:539-552)

import type { ApiClient } from "./api-client.js";
import type { Network } from "./config.js";
import {
  buildAnyDescriptorForParsed,
  buildWalletDescriptorForParsed,
  getWalletIdForParsed,
} from "./descriptor.js";
import type { ParsedDescriptor } from "./descriptor.js";
import { loadWallet, saveWallet } from "./storage.js";
import type { WalletData } from "./storage.js";
import { deriveRootKeyFromDescriptor, deriveSecretboxKey, deriveGID } from "./wallet-keys.js";

export interface RecoverWalletParams {
  client: ApiClient;
  parsed: ParsedDescriptor;
  network: Network;
  email: string;
  name: string;
}

export interface RecoverWalletResult {
  status: "recovered" | "already_exists";
  wallet: WalletData;
}

/**
 * Recover a group wallet from parsed descriptor data.
 *
 * Steps:
 * 1. Compute wallet ID from descriptor checksum
 * 2. Check if wallet already exists locally
 * 3. Derive GID and verify wallet exists on server (GET /v1.1/shared-wallets/wallets/{gid})
 * 4. Call recover API (POST /v1.1/shared-wallets/wallets/{gid}/recover)
 * 5. Derive encryption keys and save wallet locally
 */
export async function recoverWallet(params: RecoverWalletParams): Promise<RecoverWalletResult> {
  const { client, parsed, network, email, name } = params;

  // Step 1: Compute wallet ID
  const walletId = getWalletIdForParsed(parsed);

  // Step 2: Check if wallet already exists locally
  const existing = loadWallet(email, network, walletId);
  if (existing) {
    return { status: "already_exists", wallet: existing };
  }

  // Step 3: Derive GID and check server
  const anyDescriptor = buildAnyDescriptorForParsed(parsed);
  const rootKey = await deriveRootKeyFromDescriptor(anyDescriptor);
  const gid = deriveGID(rootKey, network);

  const data = await client.get<{ wallet: { id?: string; status?: string } }>(
    `/v1.1/shared-wallets/wallets/${gid}`,
  );

  if (!data.wallet || data.wallet.status !== "ACTIVE") {
    throw { error: "NOT_FOUND", message: "Wallet not found on server" };
  }

  // Step 4: Call recover API
  await client.post(`/v1.1/shared-wallets/wallets/${gid}/recover`, "{}");

  // Step 5: Derive encryption keys and save wallet locally
  const secretboxKey = deriveSecretboxKey(rootKey);
  const wallet: WalletData = {
    walletId,
    groupId: data.wallet.id || gid,
    gid,
    name,
    m: parsed.m,
    n: parsed.n,
    addressType: parsed.addressType,
    descriptor: buildWalletDescriptorForParsed(parsed),
    signers: parsed.signers,
    secretboxKey: Buffer.from(secretboxKey).toString("base64"),
    createdAt: new Date().toISOString(),
  };
  saveWallet(email, network, wallet);

  return { status: "recovered", wallet };
}
