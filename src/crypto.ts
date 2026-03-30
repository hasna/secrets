/**
 * AES-256-GCM encryption for vault secrets.
 *
 * The master key is stored locally at ~/.hasna/secrets/vault.key (mode 600).
 * It is NEVER sent to RDS or any remote location.
 *
 * Encrypted values are stored as: "enc:v1:<iv-hex>:<ciphertext+tag-hex>"
 * Plaintext values (legacy) lack the "enc:" prefix and are transparently
 * migrated on first read.
 */

import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const ALGO = "aes-256-gcm";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const PREFIX = "enc:v1:";

function getKeyDir(): string {
  const dir = process.env.HASNA_SECRETS_KEY_DIR ?? join(homedir(), ".hasna", "secrets");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function getKeyPath(): string {
  return join(getKeyDir(), "vault.key");
}

/**
 * Load or generate the 256-bit master key.
 * The key file is mode 600 and never leaves the local machine.
 */
export function getMasterKey(): Buffer {
  const keyPath = getKeyPath();
  if (existsSync(keyPath)) {
    return Buffer.from(readFileSync(keyPath, "utf-8").trim(), "hex");
  }
  const key = randomBytes(KEY_BYTES);
  writeFileSync(keyPath, key.toString("hex") + "\n", { mode: 0o600 });
  chmodSync(keyPath, 0o600);
  return key;
}

/**
 * Encrypt a plaintext value.
 * Returns "enc:v1:<iv-hex>:<ciphertext+authTag-hex>"
 */
export function encrypt(plaintext: string): string {
  const key = getMasterKey();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString("hex")}:${Buffer.concat([encrypted, tag]).toString("hex")}`;
}

/**
 * Decrypt a vault value.
 * If the value doesn't have the "enc:" prefix, it's legacy plaintext — return as-is.
 */
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

/**
 * Check if a value is already encrypted.
 */
export function isEncrypted(value: string): boolean {
  return value.startsWith(PREFIX);
}
