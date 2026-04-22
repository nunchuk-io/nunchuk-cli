import { describe, it, expect, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import Database from "better-sqlite3";
import {
  encrypt,
  decrypt,
  getOrCreateMasterKey,
  _clearMasterKeyCache,
  _closeDatabase,
  _deleteAccountData,
  emailHash,
  saveProfile,
  loadProfile,
  saveWallet,
  loadWallet,
  listWallets,
  removeWallet,
  saveKey,
  loadKey,
  listKeys,
  removeKey,
  addSandboxId,
  removeSandboxId,
  getSandboxIds,
} from "../storage.js";
import type { Profile, WalletData, StoredKey } from "../storage.js";
import { buildWalletDescriptor } from "../descriptor.js";

// ── Helpers ──────────────────────────────────────────────────────────

// Use a unique random prefix per test run to avoid collisions with real data
const TEST_RUN_ID = crypto.randomBytes(4).toString("hex");
const TEST_HOME = path.join(os.tmpdir(), "nunchuk-cli-tests", TEST_RUN_ID);
process.env.NUNCHUK_CLI_HOME = TEST_HOME;

const DATA_DIR = path.join(TEST_HOME, "data");
const MASTER_KEY_FILE = path.join(TEST_HOME, ".master-key");
const TEST_SIGNERS = [
  "[534a4a82/48'/1'/0'/2']tpubDFeha94AzbvqSzMLj6iihYeP1zwfW3KgNcmd7oXvKD9dApjWK4KT1RzzbSNUgmsgBs8sshky7pLTUZahkfPTNVck2fwS5wXyn1nTAy8jZCJ",
  "[4bda0966/48'/1'/0'/2']tpubDFTwhyhyq2m2eQGCGQvzgZocFVsQAyjYCAMdGs9ahzTsvd49M3ekAiZvpzyjXF57FpC5zm8NVEPgnptFGSdzM6aZcWVrB6cqVC7fXhXzW6s",
];

let testCounter = 0;

/** Returns a unique email for each call, ensuring test isolation. */
function uniqueEmail(prefix: string): string {
  return `${prefix}-${TEST_RUN_ID}-${++testCounter}@test.local`;
}

/** Clean up test data directories created during this test run. */
const createdEmails: string[] = [];

function trackEmail(email: string): string {
  createdEmails.push(email);
  return email;
}

function storageDbFile(email: string, network: "mainnet" | "testnet"): string {
  return path.join(DATA_DIR, emailHash(email), network, "storage.sqlite");
}

function withCliHome<T>(cliHome: string, fn: () => T): T {
  const previousHome = process.env.NUNCHUK_CLI_HOME;

  _closeDatabase();
  _clearMasterKeyCache();
  process.env.NUNCHUK_CLI_HOME = cliHome;

  try {
    return fn();
  } finally {
    _closeDatabase();
    _clearMasterKeyCache();
    if (previousHome === undefined) {
      delete process.env.NUNCHUK_CLI_HOME;
    } else {
      process.env.NUNCHUK_CLI_HOME = previousHome;
    }
  }
}

afterAll(() => {
  _closeDatabase();
  for (const email of createdEmails) {
    _deleteAccountData(email);
  }
  _closeDatabase();
  fs.rmSync(TEST_HOME, { recursive: true, force: true });
  delete process.env.NUNCHUK_CLI_HOME;
});

beforeEach(() => {
  _closeDatabase();
  _clearMasterKeyCache();
});

// ── encrypt / decrypt ────────────────────────────────────────────────

describe("encrypt / decrypt", () => {
  const key = crypto.randomBytes(32);

  it("round-trips plaintext correctly", () => {
    const plaintext = "hello, world!";
    const encrypted = encrypt(plaintext, key);
    expect(decrypt(encrypted, key)).toBe(plaintext);
  });

  it("round-trips JSON data", () => {
    const data = { email: "test@example.com", apiKey: "secret-123", nested: { a: 1 } };
    const plaintext = JSON.stringify(data);
    const encrypted = encrypt(plaintext, key);
    expect(JSON.parse(decrypt(encrypted, key))).toEqual(data);
  });

  it("round-trips empty string", () => {
    const encrypted = encrypt("", key);
    expect(decrypt(encrypted, key)).toBe("");
  });

  it("round-trips unicode and special characters", () => {
    const plaintext = "emoji: \u{1F512} accent: caf\u00E9 cjk: \u4F60\u597D newline:\n\ttab";
    const encrypted = encrypt(plaintext, key);
    expect(decrypt(encrypted, key)).toBe(plaintext);
  });

  it("produces different ciphertext each time (random IV)", () => {
    const plaintext = "same input";
    const a = encrypt(plaintext, key);
    const b = encrypt(plaintext, key);
    expect(a.equals(b)).toBe(false);
    // But both decrypt to the same value
    expect(decrypt(a, key)).toBe(plaintext);
    expect(decrypt(b, key)).toBe(plaintext);
  });

  it("starts with version byte 0x01", () => {
    const encrypted = encrypt("test", key);
    expect(encrypted[0]).toBe(0x01);
  });

  it("has correct binary layout: [1 version][12 IV][16 authTag][N ciphertext]", () => {
    const encrypted = encrypt("test", key);
    expect(encrypted.length).toBeGreaterThanOrEqual(29); // 1 + 12 + 16 = 29 minimum
  });

  it("rejects decryption with wrong key", () => {
    const encrypted = encrypt("secret data", key);
    const wrongKey = crypto.randomBytes(32);
    expect(() => decrypt(encrypted, wrongKey)).toThrow();
  });

  it("rejects tampered ciphertext (flipped byte)", () => {
    const encrypted = encrypt("secret data", key);
    const tampered = Buffer.from(encrypted);
    tampered[29] ^= 0xff;
    expect(() => decrypt(tampered, key)).toThrow();
  });

  it("rejects tampered authTag", () => {
    const encrypted = encrypt("secret data", key);
    const tampered = Buffer.from(encrypted);
    tampered[13] ^= 0xff;
    expect(() => decrypt(tampered, key)).toThrow();
  });

  it("rejects tampered IV", () => {
    const encrypted = encrypt("secret data", key);
    const tampered = Buffer.from(encrypted);
    tampered[1] ^= 0xff;
    expect(() => decrypt(tampered, key)).toThrow();
  });

  it("rejects truncated data", () => {
    expect(() => decrypt(Buffer.alloc(28), key)).toThrow("Encrypted file too short");
  });

  it("rejects wrong version byte", () => {
    const encrypted = encrypt("test", key);
    const tampered = Buffer.from(encrypted);
    tampered[0] = 0x99;
    expect(() => decrypt(tampered, key)).toThrow("Unsupported encryption version");
  });
});

// ── getOrCreateMasterKey ─────────────────────────────────────────────

describe("getOrCreateMasterKey", () => {
  it("generates a 32-byte storage key", () => {
    const key = getOrCreateMasterKey();
    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
  });

  it("returns the same key on subsequent calls (cached)", () => {
    const a = getOrCreateMasterKey();
    const b = getOrCreateMasterKey();
    expect(a.equals(b)).toBe(true);
    expect(a).toBe(b); // same reference (cached)
  });

  it("re-reads key from file after cache clear", () => {
    const a = getOrCreateMasterKey();
    _clearMasterKeyCache();
    const b = getOrCreateMasterKey();
    expect(a.equals(b)).toBe(true);
    expect(a).not.toBe(b); // different reference, same value
  });

  it("derives the storage key from the raw master key file", () => {
    const storageKey = getOrCreateMasterKey();
    const rawMasterKey = fs.readFileSync(MASTER_KEY_FILE);

    expect(rawMasterKey.length).toBe(32);
    expect(storageKey.equals(rawMasterKey)).toBe(false);
  });

  it("does not treat empty data directories as encrypted data", () => {
    const isolatedHome = path.join(TEST_HOME, "isolated-empty-data");
    fs.rmSync(isolatedHome, { recursive: true, force: true });

    withCliHome(isolatedHome, () => {
      fs.mkdirSync(path.join(isolatedHome, "data", "placeholder", "mainnet"), { recursive: true });

      expect(() => getOrCreateMasterKey()).not.toThrow();
      expect(fs.existsSync(path.join(isolatedHome, ".master-key"))).toBe(true);
    });

    fs.rmSync(isolatedHome, { recursive: true, force: true });
  });
});

// ── emailHash ────────────────────────────────────────────────────────

describe("emailHash", () => {
  it("returns 16-char hex string", () => {
    const hash = emailHash("test@example.com");
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
  });

  it("is deterministic", () => {
    expect(emailHash("user@test.com")).toBe(emailHash("user@test.com"));
  });

  it("produces different hashes for different emails", () => {
    expect(emailHash("a@b.com")).not.toBe(emailHash("c@d.com"));
  });
});

// ── Profile storage ──────────────────────────────────────────────────

describe("profile storage", () => {
  const network = "testnet" as const;

  function makeProfile(email: string): Profile {
    return {
      apiKey: "sk-test-key-12345",
      email,
      userId: "user-001",
      name: "Test User",
      ephemeralPub: "pub-hex-data",
      ephemeralPriv: "priv-hex-data",
    };
  }

  it("round-trips profile data", () => {
    const email = trackEmail(uniqueEmail("profile"));
    const profile = makeProfile(email);
    saveProfile(email, network, profile);
    const loaded = loadProfile(email, network);
    expect(loaded).toEqual(profile);
  });

  it("creates the master key before the first profile write on a fresh home", () => {
    const isolatedHome = path.join(TEST_HOME, "isolated-first-write");
    fs.rmSync(isolatedHome, { recursive: true, force: true });

    const email = uniqueEmail("profile-fresh");
    const profile = makeProfile(email);

    withCliHome(isolatedHome, () => {
      expect(() => saveProfile(email, network, profile)).not.toThrow();
      expect(loadProfile(email, network)).toEqual(profile);
      expect(fs.existsSync(path.join(isolatedHome, ".master-key"))).toBe(true);
    });

    fs.rmSync(isolatedHome, { recursive: true, force: true });
  });

  it("returns null for non-existent profile", () => {
    const email = trackEmail(uniqueEmail("profile"));
    expect(loadProfile(email, network)).toBeNull();
  });

  it("overwrites existing profile", () => {
    const email = trackEmail(uniqueEmail("profile"));
    saveProfile(email, network, makeProfile(email));
    const updated = { ...makeProfile(email), name: "Updated Name" };
    saveProfile(email, network, updated);
    expect(loadProfile(email, network)?.name).toBe("Updated Name");
  });

  it("stores profiles per-network independently", () => {
    const email = trackEmail(uniqueEmail("profile"));
    saveProfile(email, "mainnet", { ...makeProfile(email), name: "Mainnet" });
    saveProfile(email, "testnet", { ...makeProfile(email), name: "Testnet" });
    expect(loadProfile(email, "mainnet")?.name).toBe("Mainnet");
    expect(loadProfile(email, "testnet")?.name).toBe("Testnet");
  });
});

// ── Wallet storage ───────────────────────────────────────────────────

describe("wallet storage", () => {
  const network = "testnet" as const;

  function makeWallet(id: string): WalletData {
    return {
      walletId: id,
      groupId: "group-1",
      gid: "gid-1",
      name: `Wallet ${id}`,
      m: 2,
      n: 2,
      addressType: "NESTED_SEGWIT",
      descriptor: buildWalletDescriptor(TEST_SIGNERS, 2, "NESTED_SEGWIT"),
      signers: TEST_SIGNERS,
      secretboxKey: Buffer.from("a".repeat(32)).toString("base64"),
      createdAt: new Date().toISOString(),
    };
  }

  it("round-trips wallet data", () => {
    const email = trackEmail(uniqueEmail("wallet"));
    const wallet = makeWallet("w1");
    saveWallet(email, network, wallet);
    expect(loadWallet(email, network, "w1")).toEqual(wallet);
  });

  it("persists descriptor as the canonical wallet source", () => {
    const email = trackEmail(uniqueEmail("wallet"));
    const wallet = makeWallet("w1");
    saveWallet(email, network, wallet);

    const db = new Database(storageDbFile(email, network), { readonly: true });
    const row = db.prepare("SELECT encrypted FROM wallets WHERE wallet_id = ?").get("w1") as {
      encrypted: Uint8Array;
    };
    db.close();

    const stored = JSON.parse(
      decrypt(Buffer.from(row.encrypted), getOrCreateMasterKey()),
    ) as Record<string, unknown>;
    expect(stored.descriptor).toBe(wallet.descriptor);
    expect(stored.m).toBeUndefined();
    expect(stored.n).toBeUndefined();
    expect(stored.addressType).toBeUndefined();
    expect(stored.signers).toBeUndefined();
  });

  it("migrates v1 wallet rows to descriptor-only payloads", () => {
    const email = trackEmail(uniqueEmail("wallet"));
    const wallet = makeWallet("w1");
    saveWallet(email, network, wallet);
    _closeDatabase();

    const dbFile = storageDbFile(email, network);
    const legacyPayload = {
      ...wallet,
      addressType: 2,
    };
    const db = new Database(dbFile);
    db.prepare("UPDATE wallets SET encrypted = ? WHERE wallet_id = ?").run(
      encrypt(JSON.stringify(legacyPayload), getOrCreateMasterKey()),
      wallet.walletId,
    );
    db.prepare("UPDATE meta SET value = ? WHERE key = ?").run("1", "schema_version");
    db.close();

    expect(loadWallet(email, network, wallet.walletId)).toEqual(wallet);
    _closeDatabase();

    const migratedDb = new Database(dbFile, { readonly: true });
    const version = migratedDb
      .prepare("SELECT value FROM meta WHERE key = ?")
      .get("schema_version") as { value: string };
    const row = migratedDb
      .prepare("SELECT encrypted FROM wallets WHERE wallet_id = ?")
      .get(wallet.walletId) as { encrypted: Uint8Array };
    migratedDb.close();

    const stored = JSON.parse(
      decrypt(Buffer.from(row.encrypted), getOrCreateMasterKey()),
    ) as Record<string, unknown>;
    expect(version.value).toBe("2");
    expect(stored.descriptor).toBe(wallet.descriptor);
    expect(stored.m).toBeUndefined();
    expect(stored.n).toBeUndefined();
    expect(stored.addressType).toBeUndefined();
    expect(stored.signers).toBeUndefined();
  });

  it("returns null for non-existent wallet", () => {
    const email = trackEmail(uniqueEmail("wallet"));
    expect(loadWallet(email, network, "nonexistent")).toBeNull();
  });

  it("lists all wallets", () => {
    const email = trackEmail(uniqueEmail("wallet"));
    saveWallet(email, network, makeWallet("w1"));
    saveWallet(email, network, makeWallet("w2"));
    saveWallet(email, network, makeWallet("w3"));
    const wallets = listWallets(email, network);
    expect(wallets).toHaveLength(3);
    const ids = wallets.map((w) => w.walletId).sort();
    expect(ids).toEqual(["w1", "w2", "w3"]);
  });

  it("returns empty array when no wallets exist", () => {
    const email = trackEmail(uniqueEmail("wallet"));
    expect(listWallets(email, network)).toEqual([]);
  });

  it("removes a wallet", () => {
    const email = trackEmail(uniqueEmail("wallet"));
    saveWallet(email, network, makeWallet("w1"));
    removeWallet(email, network, "w1");
    expect(loadWallet(email, network, "w1")).toBeNull();
  });

  it("does not throw when removing non-existent wallet", () => {
    const email = trackEmail(uniqueEmail("wallet"));
    expect(() => removeWallet(email, network, "nonexistent")).not.toThrow();
  });
});

// ── Key storage ──────────────────────────────────────────────────────

describe("key storage", () => {
  const network = "testnet" as const;

  function makeKey(fp: string): StoredKey {
    return {
      name: `Key ${fp}`,
      mnemonic: "abandon ".repeat(11) + "about",
      fingerprint: fp,
      createdAt: new Date().toISOString(),
    };
  }

  it("round-trips key data", () => {
    const email = trackEmail(uniqueEmail("key"));
    const key = makeKey("aabbccdd");
    saveKey(email, network, key);
    expect(loadKey(email, network, "aabbccdd")).toEqual(key);
  });

  it("returns null for non-existent key", () => {
    const email = trackEmail(uniqueEmail("key"));
    expect(loadKey(email, network, "00000000")).toBeNull();
  });

  it("lists all keys", () => {
    const email = trackEmail(uniqueEmail("key"));
    saveKey(email, network, makeKey("11111111"));
    saveKey(email, network, makeKey("22222222"));
    const keys = listKeys(email, network);
    expect(keys).toHaveLength(2);
    const fps = keys.map((k) => k.fingerprint).sort();
    expect(fps).toEqual(["11111111", "22222222"]);
  });

  it("returns empty array when no keys exist", () => {
    const email = trackEmail(uniqueEmail("key"));
    expect(listKeys(email, network)).toEqual([]);
  });

  it("removes a key", () => {
    const email = trackEmail(uniqueEmail("key"));
    saveKey(email, network, makeKey("aabbccdd"));
    removeKey(email, network, "aabbccdd");
    expect(loadKey(email, network, "aabbccdd")).toBeNull();
  });

  it("does not throw when removing non-existent key", () => {
    const email = trackEmail(uniqueEmail("key"));
    expect(() => removeKey(email, network, "nonexistent")).not.toThrow();
  });
});

// ── Sandbox storage ──────────────────────────────────────────────────

describe("sandbox storage", () => {
  const network = "testnet" as const;

  it("adds and retrieves sandbox IDs", () => {
    const email = trackEmail(uniqueEmail("sandbox"));
    addSandboxId(email, network, "sb-1");
    addSandboxId(email, network, "sb-2");
    expect(getSandboxIds(email, network)).toEqual(["sb-1", "sb-2"]);
  });

  it("does not duplicate sandbox IDs", () => {
    const email = trackEmail(uniqueEmail("sandbox"));
    addSandboxId(email, network, "sb-1");
    addSandboxId(email, network, "sb-1");
    expect(getSandboxIds(email, network)).toEqual(["sb-1"]);
  });

  it("removes a sandbox ID", () => {
    const email = trackEmail(uniqueEmail("sandbox"));
    addSandboxId(email, network, "sb-1");
    addSandboxId(email, network, "sb-2");
    removeSandboxId(email, network, "sb-1");
    expect(getSandboxIds(email, network)).toEqual(["sb-2"]);
  });

  it("returns empty array when no sandboxes exist", () => {
    const email = trackEmail(uniqueEmail("sandbox"));
    expect(getSandboxIds(email, network)).toEqual([]);
  });
});

// ── Storage-level properties ─────────────────────────────────────────

describe("encrypted storage properties", () => {
  const network = "testnet" as const;

  it("stores the schema version in sqlite metadata", () => {
    const email = trackEmail(uniqueEmail("schema"));
    saveProfile(email, network, {
      apiKey: "key",
      email,
      userId: "u1",
      name: "Test",
      ephemeralPub: "pub",
      ephemeralPriv: "priv",
    });

    const db = new Database(storageDbFile(email, network));
    const row = db.prepare("SELECT value FROM meta WHERE key = ?").get("schema_version") as
      | Record<string, unknown>
      | undefined;
    db.close();

    expect(row?.value).toBe("2");
  });

  it("stores encrypted profile blobs in meta", () => {
    const email = trackEmail(uniqueEmail("fileprops"));
    saveProfile(email, network, {
      apiKey: "key",
      email,
      userId: "u1",
      name: "Test",
      ephemeralPub: "pub",
      ephemeralPriv: "priv",
    });

    const dbPath = storageDbFile(email, network);
    const db = new Database(dbPath);
    const row = db.prepare("SELECT value FROM meta WHERE key = ?").get("profile") as
      | Record<string, unknown>
      | undefined;
    db.close();

    expect(row).toBeDefined();
    expect(fs.existsSync(dbPath)).toBe(true);
    expect(typeof row?.value).toBe("string");

    const raw = Buffer.from(row!.value as string, "base64");

    // Should start with version byte 0x01, not '{' (0x7B)
    expect(raw[0]).toBe(0x01);
    expect(() => JSON.parse(raw.toString("utf8"))).toThrow();
  });

  it("does not create legacy profile files for new writes", () => {
    const email = trackEmail(uniqueEmail("fileprops"));
    saveProfile(email, network, {
      apiKey: "key",
      email,
      userId: "u1",
      name: "Test",
      ephemeralPub: "pub",
      ephemeralPriv: "priv",
    });

    const profilePath = path.join(DATA_DIR, emailHash(email), network, "profile.enc");
    expect(fs.existsSync(profilePath)).toBe(false);
  });

  it("uses separate sqlite files per account and network", () => {
    const emailA = trackEmail(uniqueEmail("db-scope"));
    const emailB = trackEmail(uniqueEmail("db-scope"));

    saveProfile(emailA, "mainnet", {
      apiKey: "key-a-main",
      email: emailA,
      userId: "u-a-main",
      name: "A Main",
      ephemeralPub: "pub-a-main",
      ephemeralPriv: "priv-a-main",
    });
    saveProfile(emailA, "testnet", {
      apiKey: "key-a-test",
      email: emailA,
      userId: "u-a-test",
      name: "A Test",
      ephemeralPub: "pub-a-test",
      ephemeralPriv: "priv-a-test",
    });
    saveProfile(emailB, "testnet", {
      apiKey: "key-b-test",
      email: emailB,
      userId: "u-b-test",
      name: "B Test",
      ephemeralPub: "pub-b-test",
      ephemeralPriv: "priv-b-test",
    });

    const aMain = storageDbFile(emailA, "mainnet");
    const aTest = storageDbFile(emailA, "testnet");
    const bTest = storageDbFile(emailB, "testnet");

    expect(aMain).not.toBe(aTest);
    expect(aTest).not.toBe(bTest);
    expect(fs.existsSync(aMain)).toBe(true);
    expect(fs.existsSync(aTest)).toBe(true);
    expect(fs.existsSync(bTest)).toBe(true);
  });
});
