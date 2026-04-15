import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import Database from "better-sqlite3";
import type { Network } from "./config.js";
import type { AddressType } from "./address-type.js";
import { parseDescriptor } from "./descriptor.js";
import {
  getAccountStorageDir,
  getCliHome,
  getEmailHash,
  getMasterKeyFile,
  getStorageDatabaseFile,
} from "./paths.js";

const ENCRYPTION_VERSION = 0x01;
const STORAGE_SCHEMA_VERSION = 2;
const STORAGE_SCHEMA_VERSION_KEY = "schema_version";
const PROFILE_META_KEY = "profile";
const HKDF_INFO = "nunchuk-cli/storage/v1";

// ── Encryption core ──────────────────────────────────────────────────

let cachedMasterKey: Buffer | null = null;
let cachedStorageKey: Buffer | null = null;
let cachedDatabase: Database.Database | null = null;
let cachedDatabasePath: string | null = null;

function loadExistingMasterKey(): Buffer | null {
  const masterKeyFile = getMasterKeyFile();
  if (cachedMasterKey) return cachedMasterKey;
  if (!fs.existsSync(masterKeyFile)) return null;

  const key = fs.readFileSync(masterKeyFile);
  if (key.length !== 32) {
    throw new Error("Corrupted master key: expected 32 bytes");
  }

  cachedMasterKey = key;
  return key;
}

function hasExistingEncryptedData(): boolean {
  const dataDir = path.join(getCliHome(), "data");
  if (!fs.existsSync(dataDir)) return false;

  try {
    const pending = [dataDir];

    while (pending.length > 0) {
      const dir = pending.pop()!;
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const entryPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          pending.push(entryPath);
          continue;
        }

        if (entry.isFile() && entry.name === "storage.sqlite") {
          return true;
        }
      }
    }

    return false;
  } catch {
    return false;
  }
}

export function getOrCreateMasterKey(): Buffer {
  if (cachedStorageKey) return cachedStorageKey;

  let masterKey = loadExistingMasterKey();
  if (!masterKey) {
    if (hasExistingEncryptedData()) {
      throw new Error(
        "Master key file is missing but encrypted data exists. " +
          "Existing data cannot be decrypted without the original key. " +
          `To start fresh, delete ${path.join(getCliHome(), "data")} and try again.`,
      );
    }

    masterKey = crypto.randomBytes(32);
    fs.mkdirSync(getCliHome(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(getMasterKeyFile(), masterKey, { mode: 0o400 });
    cachedMasterKey = masterKey;
  }

  cachedStorageKey = Buffer.from(crypto.hkdfSync("sha256", masterKey, "", HKDF_INFO, 32));
  return cachedStorageKey;
}

// Exported for testing only — clears the cached master key so tests are isolated.
export function _clearMasterKeyCache(): void {
  cachedMasterKey = null;
  cachedStorageKey = null;
}

// Exported for testing only — closes the cached database handle so tests can reset state.
export function _closeDatabase(): void {
  cachedDatabase?.close();
  cachedDatabase = null;
  cachedDatabasePath = null;
}

export function encrypt(plaintext: string, key: Buffer): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([ENCRYPTION_VERSION]), iv, authTag, encrypted]);
}

export function decrypt(data: Buffer, key: Buffer): string {
  if (data.length < 29) {
    throw new Error("Encrypted file too short");
  }

  const version = data[0];
  if (version !== ENCRYPTION_VERSION) {
    throw new Error(`Unsupported encryption version: ${version}`);
  }

  const iv = data.subarray(1, 13);
  const authTag = data.subarray(13, 29);
  const ciphertext = data.subarray(29);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString("utf8");
}

function getDatabase(
  email: string,
  network: Network,
  options: { create?: boolean } = {},
): Database.Database | null {
  const storageDbFile = getStorageDatabaseFile(email, network);
  if (cachedDatabase?.open && cachedDatabasePath === storageDbFile) {
    return cachedDatabase;
  }

  if (options.create) {
    getOrCreateMasterKey();
  }

  if (!options.create && !fs.existsSync(storageDbFile)) {
    return null;
  }

  _closeDatabase();

  fs.mkdirSync(getAccountStorageDir(email, network), { recursive: true, mode: 0o700 });

  const db = new Database(storageDbFile, { timeout: 5000 });
  try {
    fs.chmodSync(storageDbFile, 0o600);
  } catch {
    // Best effort: some filesystems may not support chmod as expected.
  }

  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    initializeSchema(db);
  } catch (error) {
    db.close();
    throw error;
  }

  cachedDatabase = db;
  cachedDatabasePath = storageDbFile;
  return db;
}

function readMeta(db: Database.Database, key: string): string | null {
  const row = db.prepare("SELECT value FROM meta WHERE key = ?").get(key) as
    | Record<string, unknown>
    | undefined;
  return typeof row?.value === "string" ? row.value : null;
}

function writeMeta(db: Database.Database, key: string, value: string): void {
  db.prepare(
    `
    INSERT INTO meta (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `,
  ).run(key, value);
}

function encodeEncryptedMetaValue(encrypted: Uint8Array): string {
  return Buffer.from(encrypted).toString("base64");
}

function decodeEncryptedMetaValue(value: string): Uint8Array {
  return Buffer.from(value, "base64");
}

function createSchemaTables(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sandboxes (
      sandbox_id TEXT NOT NULL,
      PRIMARY KEY (sandbox_id)
    );

    CREATE TABLE IF NOT EXISTS wallets (
      wallet_id TEXT NOT NULL,
      encrypted BLOB NOT NULL,
      PRIMARY KEY (wallet_id)
    );

    CREATE TABLE IF NOT EXISTS keys (
      fingerprint TEXT NOT NULL,
      encrypted BLOB NOT NULL,
      PRIMARY KEY (fingerprint)
    );
  `);
}

function migrateWalletRowsToDescriptorOnly(db: Database.Database): void {
  const rows = db
    .prepare("SELECT wallet_id, encrypted FROM wallets ORDER BY rowid")
    .all() as Record<string, unknown>[];
  const update = db.prepare("UPDATE wallets SET encrypted = ? WHERE wallet_id = ?");

  for (const row of rows) {
    if (typeof row.wallet_id !== "string" || !(row.encrypted instanceof Uint8Array)) {
      throw new Error("Invalid wallet storage row");
    }

    const stored = deserializeEncrypted<StoredWalletData>(row.encrypted);
    const wallet = normalizeWalletData(stored);
    update.run(serializeEncrypted(serializeWalletData(wallet)), row.wallet_id);
  }
}

function parseSchemaVersion(version: string): number {
  const parsed = Number.parseInt(version, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || String(parsed) !== version) {
    throw new Error(`Unsupported storage schema version: ${version}`);
  }
  return parsed;
}

function initializeSchema(db: Database.Database): void {
  const version = readMeta(db, STORAGE_SCHEMA_VERSION_KEY);

  if (version === null) {
    runInTransaction(db, () => {
      createSchemaTables(db);
      writeMeta(db, STORAGE_SCHEMA_VERSION_KEY, String(STORAGE_SCHEMA_VERSION));
    });
    return;
  }

  const currentVersion = parseSchemaVersion(version);
  if (currentVersion > STORAGE_SCHEMA_VERSION) {
    throw new Error(`Unsupported storage schema version: ${version}`);
  }

  if (currentVersion === STORAGE_SCHEMA_VERSION) {
    return;
  }

  runInTransaction(db, () => {
    createSchemaTables(db);
    if (currentVersion < 2) {
      migrateWalletRowsToDescriptorOnly(db);
    }
    writeMeta(db, STORAGE_SCHEMA_VERSION_KEY, String(STORAGE_SCHEMA_VERSION));
  });
}

function runInTransaction<T>(db: Database.Database, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // Ignore rollback errors and rethrow the original failure.
    }
    throw error;
  }
}

// ── Encrypted read/write helpers ─────────────────────────────────────

function serializeEncrypted(data: unknown): Buffer {
  const key = getOrCreateMasterKey();
  const plaintext = JSON.stringify(data);
  return encrypt(plaintext, key);
}

function deserializeEncrypted<T>(encrypted: Uint8Array): T {
  const key = getOrCreateMasterKey();
  const plaintext = decrypt(Buffer.from(encrypted), key);
  return JSON.parse(plaintext) as T;
}

function encryptedRead<T>(
  email: string,
  network: Network,
  table: "profiles" | "wallets" | "keys",
  key?: string,
): T | null {
  try {
    const db = getDatabase(email, network, { create: false });
    if (!db) return null;

    let row: Record<string, unknown> | undefined;
    if (table === "profiles") {
      row = db.prepare("SELECT value FROM meta WHERE key = ?").get(PROFILE_META_KEY) as
        | Record<string, unknown>
        | undefined;
      if (typeof row?.value !== "string") return null;
      return deserializeEncrypted<T>(decodeEncryptedMetaValue(row.value));
    } else if (table === "wallets") {
      if (key === undefined) return null;
      row = db.prepare("SELECT encrypted FROM wallets WHERE wallet_id = ?").get(key) as
        | Record<string, unknown>
        | undefined;
    } else {
      if (key === undefined) return null;
      row = db.prepare("SELECT encrypted FROM keys WHERE fingerprint = ?").get(key) as
        | Record<string, unknown>
        | undefined;
    }

    if (!(row?.encrypted instanceof Uint8Array)) return null;
    return deserializeEncrypted<T>(row.encrypted);
  } catch {
    return null;
  }
}

function encryptedList<T>(table: "wallets" | "keys", email: string, network: Network): T[] {
  try {
    const db = getDatabase(email, network, { create: false });
    if (!db) return [];
    const query =
      table === "wallets"
        ? "SELECT encrypted FROM wallets ORDER BY rowid"
        : "SELECT encrypted FROM keys ORDER BY rowid";

    const rows = db.prepare(query).all() as Record<string, unknown>[];
    return rows.map((row) => {
      if (!(row.encrypted instanceof Uint8Array)) {
        throw new Error("Invalid encrypted payload");
      }
      return deserializeEncrypted<T>(row.encrypted);
    });
  } catch {
    return [];
  }
}

// ── Shared helpers ───────────────────────────────────────────────────

export function emailHash(email: string): string {
  return getEmailHash(email);
}

// ── Profile storage (per-user, per-network) ──────────────────────────

export interface Profile {
  apiKey: string;
  email: string;
  userId: string;
  name: string;
  ephemeralPub: string;
  ephemeralPriv: string;
}

export function saveProfile(email: string, network: Network, profile: Profile): void {
  const db = getDatabase(email, network, { create: true });
  db?.prepare(
    `
      INSERT INTO meta (key, value)
      VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `,
  ).run(PROFILE_META_KEY, encodeEncryptedMetaValue(serializeEncrypted(profile)));
}

export function loadProfile(email: string, network: Network): Profile | null {
  return encryptedRead<Profile>(email, network, "profiles");
}

// ── Sandbox storage ──────────────────────────────────────────────────

export function addSandboxId(email: string, network: Network, sandboxId: string): void {
  const db = getDatabase(email, network, { create: true });
  db?.prepare(
    `
      INSERT OR IGNORE INTO sandboxes (sandbox_id)
      VALUES (?)
    `,
  ).run(sandboxId);
}

export function removeSandboxId(email: string, network: Network, sandboxId: string): void {
  const db = getDatabase(email, network, { create: false });
  db?.prepare("DELETE FROM sandboxes WHERE sandbox_id = ?").run(sandboxId);
}

export function getSandboxIds(email: string, network: Network): string[] {
  try {
    const db = getDatabase(email, network, { create: false });
    if (!db) return [];

    const rows = db
      .prepare(
        `
        SELECT sandbox_id
        FROM sandboxes
        ORDER BY rowid
      `,
      )
      .all() as Record<string, unknown>[];

    return rows
      .map((row) => (typeof row.sandbox_id === "string" ? row.sandbox_id : null))
      .filter((sandboxId): sandboxId is string => sandboxId !== null);
  } catch {
    return [];
  }
}

// ── Wallet storage ───────────────────────────────────────────────────

export interface WalletData {
  walletId: string;
  groupId: string;
  gid: string;
  name: string;
  m: number;
  n: number;
  addressType: AddressType;
  descriptor: string;
  signers: string[];
  secretboxKey: string; // base64-encoded 32-byte key
  createdAt: string;
}

type StoredWalletData = Pick<
  WalletData,
  "createdAt" | "descriptor" | "gid" | "groupId" | "name" | "secretboxKey" | "walletId"
> & {
  // Legacy fields kept optional for old encrypted rows. New saves derive these from descriptor.
  addressType?: AddressType | number;
  m?: number;
  n?: number;
  signers?: string[];
};

function normalizeWalletData(wallet: StoredWalletData): WalletData {
  const parsed = parseDescriptor(wallet.descriptor);
  return {
    ...wallet,
    addressType: parsed.addressType,
    m: parsed.m,
    n: parsed.n,
    signers: parsed.signers,
  };
}

function serializeWalletData(wallet: WalletData): StoredWalletData {
  return {
    createdAt: wallet.createdAt,
    descriptor: wallet.descriptor,
    gid: wallet.gid,
    groupId: wallet.groupId,
    name: wallet.name,
    secretboxKey: wallet.secretboxKey,
    walletId: wallet.walletId,
  };
}

export function saveWallet(email: string, network: Network, wallet: WalletData): void {
  const db = getDatabase(email, network, { create: true });
  db?.prepare(
    `
      INSERT INTO wallets (wallet_id, encrypted)
      VALUES (?, ?)
      ON CONFLICT(wallet_id) DO UPDATE SET encrypted = excluded.encrypted
    `,
  ).run(wallet.walletId, serializeEncrypted(serializeWalletData(wallet)));
}

export function loadWallet(email: string, network: Network, walletId: string): WalletData | null {
  const wallet = encryptedRead<StoredWalletData>(email, network, "wallets", walletId);
  return wallet ? normalizeWalletData(wallet) : null;
}

export function listWallets(email: string, network: Network): WalletData[] {
  return encryptedList<StoredWalletData>("wallets", email, network).map(normalizeWalletData);
}

export function removeWallet(email: string, network: Network, walletId: string): void {
  const db = getDatabase(email, network, { create: false });
  db?.prepare("DELETE FROM wallets WHERE wallet_id = ?").run(walletId);
}

// ── Key storage ──────────────────────────────────────────────────────
// Stores mnemonic-based signing keys per user per network, matching the mobile app behavior.

export interface StoredKey {
  name: string; // user-given name to distinguish keys
  mnemonic: string; // BIP39 mnemonic — the root secret
  fingerprint: string; // master fingerprint (8-char hex) — identifies the signer
  createdAt: string; // ISO timestamp
}

export function saveKey(email: string, network: Network, key: StoredKey): void {
  const db = getDatabase(email, network, { create: true });
  db?.prepare(
    `
      INSERT INTO keys (fingerprint, encrypted)
      VALUES (?, ?)
      ON CONFLICT(fingerprint) DO UPDATE SET encrypted = excluded.encrypted
    `,
  ).run(key.fingerprint, serializeEncrypted(key));
}

export function loadKey(email: string, network: Network, fingerprint: string): StoredKey | null {
  return encryptedRead<StoredKey>(email, network, "keys", fingerprint);
}

export function listKeys(email: string, network: Network): StoredKey[] {
  return encryptedList<StoredKey>("keys", email, network);
}

export function removeKey(email: string, network: Network, fingerprint: string): void {
  const db = getDatabase(email, network, { create: false });
  db?.prepare("DELETE FROM keys WHERE fingerprint = ?").run(fingerprint);
}

export function _deleteAccountData(email: string): void {
  _closeDatabase();
  fs.rmSync(path.join(getCliHome(), "data", getEmailHash(email)), { recursive: true, force: true });
}
