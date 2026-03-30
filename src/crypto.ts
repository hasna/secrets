/**
 * AES-256-GCM encryption for vault secrets with AWS KMS envelope encryption.
 *
 * How it works:
 * 1. KMS generates a data key (plaintext + encrypted copy)
 * 2. We encrypt secrets locally with the plaintext data key (AES-256-GCM)
 * 3. The plaintext data key is cached in memory only (never on disk)
 * 4. The encrypted data key is stored at ~/.hasna/secrets/vault.key.enc
 * 5. On startup, KMS decrypts the data key back into memory
 *
 * Fallback: If KMS is not configured, uses a local key file (vault.key).
 *
 * Encrypted values: "enc:v1:<iv-hex>:<ciphertext+tag-hex>"
 * Plaintext values (legacy) lack the "enc:" prefix — transparently migrated.
 */

import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const ALGO = "aes-256-gcm";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const PREFIX = "enc:v1:";

let _cachedKey: Buffer | null = null;

function getKeyDir(): string {
  const dir = process.env.HASNA_SECRETS_KEY_DIR ?? join(homedir(), ".hasna", "secrets");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function getLocalKeyPath(): string {
  return join(getKeyDir(), "vault.key");
}

function getEncryptedKeyPath(): string {
  return join(getKeyDir(), "vault.key.enc");
}

// ---------------------------------------------------------------------------
// KMS config
// ---------------------------------------------------------------------------

interface KmsConfig {
  keyId: string;
  region: string;
  profile?: string;
}

function getKmsConfig(): KmsConfig | null {
  const keyId = process.env.HASNA_SECRETS_KMS_KEY_ID;
  if (keyId) {
    return {
      keyId,
      region: process.env.HASNA_SECRETS_KMS_REGION ?? process.env.AWS_REGION ?? "us-east-1",
      profile: process.env.HASNA_SECRETS_KMS_PROFILE ?? process.env.AWS_PROFILE,
    };
  }

  // Check config file
  const configPath = join(getKeyDir(), "kms.json");
  if (existsSync(configPath)) {
    try {
      const config = JSON.parse(readFileSync(configPath, "utf-8"));
      if (config.keyId) return config;
    } catch { /* ignore */ }
  }

  return null;
}

// ---------------------------------------------------------------------------
// KMS operations (using AWS CLI to avoid heavy SDK dep for this path)
// ---------------------------------------------------------------------------

function kmsGenerateDataKey(config: KmsConfig): { plaintext: Buffer; ciphertextBlob: Buffer } {
  const { execSync } = require("child_process");
  const profileFlag = config.profile ? `--profile ${config.profile}` : "";
  const result = execSync(
    `aws kms generate-data-key ${profileFlag} --region ${config.region} --key-id "${config.keyId}" --key-spec AES_256 --output json`,
    { encoding: "utf-8", timeout: 10000 }
  );
  const data = JSON.parse(result);
  return {
    plaintext: Buffer.from(data.Plaintext, "base64"),
    ciphertextBlob: Buffer.from(data.CiphertextBlob, "base64"),
  };
}

function kmsDecryptDataKey(config: KmsConfig, ciphertextBlob: Buffer): Buffer {
  const { execFileSync } = require("child_process");
  const { writeFileSync: wfs, unlinkSync } = require("fs");
  const { tmpdir } = require("os");

  // Write ciphertext to temp file (aws cli needs fileb://)
  const tmpPath = join(tmpdir(), `.vault-key-dec-${process.pid}`);
  wfs(tmpPath, ciphertextBlob, { mode: 0o600 });

  try {
    const profileFlag = config.profile ? `--profile` : null;
    const args = [
      "kms", "decrypt",
      ...(profileFlag ? [profileFlag, config.profile!] : []),
      "--region", config.region,
      "--ciphertext-blob", `fileb://${tmpPath}`,
      "--output", "json",
    ];
    const result = execFileSync("aws", args, { encoding: "utf-8", timeout: 10000 });
    const data = JSON.parse(result);
    return Buffer.from(data.Plaintext, "base64");
  } finally {
    try { unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/**
 * Get the master key. Priority:
 * 1. In-memory cache
 * 2. KMS envelope encryption (vault.key.enc)
 * 3. Local key file (vault.key) — fallback
 */
export function getMasterKey(): Buffer {
  if (_cachedKey) return _cachedKey;

  const kmsConfig = getKmsConfig();
  const encKeyPath = getEncryptedKeyPath();
  const localKeyPath = getLocalKeyPath();

  // Try KMS first
  if (kmsConfig) {
    if (existsSync(encKeyPath)) {
      // Decrypt existing data key via KMS
      const ciphertextBlob = readFileSync(encKeyPath);
      _cachedKey = kmsDecryptDataKey(kmsConfig, ciphertextBlob);
      return _cachedKey;
    }

    if (existsSync(localKeyPath)) {
      // Migrate: local key exists, wrap it with KMS
      const localKey = Buffer.from(readFileSync(localKeyPath, "utf-8").trim(), "hex");
      const { execFileSync } = require("child_process");
      const { writeFileSync: wfs, unlinkSync } = require("fs");
      const { tmpdir } = require("os");
      const tmpPath = join(tmpdir(), `.vault-key-enc-${process.pid}`);
      wfs(tmpPath, localKey, { mode: 0o600 });

      try {
        const profileFlag = kmsConfig.profile ? `--profile` : null;
        const args = [
          "kms", "encrypt",
          ...(profileFlag ? [profileFlag, kmsConfig.profile!] : []),
          "--region", kmsConfig.region,
          "--key-id", kmsConfig.keyId,
          "--plaintext", `fileb://${tmpPath}`,
          "--output", "json",
        ];
        const result = execFileSync("aws", args, { encoding: "utf-8", timeout: 10000 });
        const data = JSON.parse(result);
        const ciphertextBlob = Buffer.from(data.CiphertextBlob, "base64");
        writeFileSync(encKeyPath, ciphertextBlob, { mode: 0o600 });

        // Remove local plaintext key
        unlinkSync(localKeyPath);
        process.stderr.write("[secrets] Migrated vault.key to KMS-encrypted vault.key.enc\n");
      } finally {
        try { require("fs").unlinkSync(tmpPath); } catch { /* ignore */ }
      }

      _cachedKey = localKey;
      return _cachedKey;
    }

    // Generate new data key via KMS
    const { plaintext, ciphertextBlob } = kmsGenerateDataKey(kmsConfig);
    writeFileSync(encKeyPath, ciphertextBlob, { mode: 0o600 });
    _cachedKey = plaintext;
    return _cachedKey;
  }

  // Fallback: local key file
  if (existsSync(localKeyPath)) {
    _cachedKey = Buffer.from(readFileSync(localKeyPath, "utf-8").trim(), "hex");
    return _cachedKey;
  }

  // Generate local key
  const key = randomBytes(KEY_BYTES);
  writeFileSync(localKeyPath, key.toString("hex") + "\n", { mode: 0o600 });
  chmodSync(localKeyPath, 0o600);
  _cachedKey = key;
  return _cachedKey;
}

/**
 * Initialize KMS configuration.
 */
export function initKms(keyId: string, region: string = "us-east-1", profile?: string): void {
  const configPath = join(getKeyDir(), "kms.json");
  const config: KmsConfig = { keyId, region, ...(profile ? { profile } : {}) };
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
}

/**
 * Check KMS status.
 */
export function getKeyStatus(): {
  mode: "kms" | "local" | "none";
  kmsKeyId?: string;
  keyPath: string;
  exists: boolean;
} {
  const kmsConfig = getKmsConfig();
  const encKeyPath = getEncryptedKeyPath();
  const localKeyPath = getLocalKeyPath();

  if (kmsConfig && existsSync(encKeyPath)) {
    return { mode: "kms", kmsKeyId: kmsConfig.keyId, keyPath: encKeyPath, exists: true };
  }
  if (existsSync(localKeyPath)) {
    return { mode: "local", keyPath: localKeyPath, exists: true };
  }
  if (kmsConfig) {
    return { mode: "kms", kmsKeyId: kmsConfig.keyId, keyPath: encKeyPath, exists: false };
  }
  return { mode: "none", keyPath: localKeyPath, exists: false };
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt values
// ---------------------------------------------------------------------------

export function encrypt(plaintext: string): string {
  const key = getMasterKey();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString("hex")}:${Buffer.concat([encrypted, tag]).toString("hex")}`;
}

export function decrypt(stored: string): string {
  if (!stored.startsWith(PREFIX)) {
    return stored; // legacy plaintext
  }
  const key = getMasterKey();
  const rest = stored.slice(PREFIX.length);
  const colonIdx = rest.indexOf(":");
  if (colonIdx === -1) throw new Error("Malformed encrypted value");
  const iv = Buffer.from(rest.slice(0, colonIdx), "hex");
  const combined = Buffer.from(rest.slice(colonIdx + 1), "hex");
  const tag = combined.subarray(combined.length - 16);
  const ciphertext = combined.subarray(0, combined.length - 16);
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf-8");
}

export function isEncrypted(value: string): boolean {
  return value.startsWith(PREFIX);
}
