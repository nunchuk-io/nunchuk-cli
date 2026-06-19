import { describe, expect, it } from "vitest";
import { generateKeypair } from "../core/crypto.js";
import { buildCreateGroupBody } from "../core/sandbox.js";
import { summarizeGroup, type SandboxSummary } from "../output.js";

function createPendingGroup(
  replaceWalletId: string,
  location: "extra" | "top-level" = "top-level",
): { group: Record<string, unknown>; keys: { pub: string; priv: string } } {
  const keys = generateKeypair();
  const body = JSON.parse(
    buildCreateGroupBody("Replacement", 2, 3, "NATIVE_SEGWIT", keys.pub, keys.priv),
  ) as { data: Record<string, unknown> };
  const group: Record<string, unknown> = {
    id: "group-1",
    status: "PENDING",
    url: "https://nunchuk.io/join/group-1",
    init: body.data,
  };

  if (location === "top-level") {
    group.replace_wallet_id = replaceWalletId;
  } else {
    body.data.extra = { replace_wallet_id: replaceWalletId };
  }

  return { group, keys };
}

describe("sandbox output", () => {
  it("maps top-level replacement wallet gid to local wallet id", () => {
    const { group, keys } = createPendingGroup("server-wallet-gid");

    const summary = summarizeGroup(group, keys, (replaceWalletId) =>
      replaceWalletId === "server-wallet-gid" ? "local-wallet-id" : replaceWalletId,
    ) as SandboxSummary;

    expect(summary.replaceWalletId).toBe("local-wallet-id");
  });

  it("maps replacement wallet gid from group extra metadata", () => {
    const { group, keys } = createPendingGroup("server-wallet-gid", "extra");

    const summary = summarizeGroup(group, keys, (replaceWalletId) =>
      replaceWalletId === "server-wallet-gid" ? "local-wallet-id" : replaceWalletId,
    ) as SandboxSummary;

    expect(summary.replaceWalletId).toBe("local-wallet-id");
  });

  it("keeps replacement id when no local wallet mapping exists", () => {
    const { group, keys } = createPendingGroup("server-wallet-gid");

    const summary = summarizeGroup(
      group,
      keys,
      (replaceWalletId) => replaceWalletId,
    ) as SandboxSummary;

    expect(summary.replaceWalletId).toBe("server-wallet-gid");
  });
});
