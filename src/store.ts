import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import type { Vault, SecretEntry } from "./types.js";

const VAULT_VERSION = 1;

function getVaultFilePath(): string {
  if (process.env.OPEN_SECRETS_VAULT) return process.env.OPEN_SECRETS_VAULT;
  return join(homedir(), ".open-secrets", "vault.json");
}

function ensureVaultDir(): void {
  const dir = join(getVaultFilePath(), "..");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

function loadVault(): Vault {
  ensureVaultDir();
  const file = getVaultFilePath();
  if (!existsSync(file)) {
    return { version: VAULT_VERSION, secrets: {} };
  }
  try {
    const raw = readFileSync(file, "utf-8");
    return JSON.parse(raw) as Vault;
  } catch {
    return { version: VAULT_VERSION, secrets: {} };
  }
}

function saveVault(vault: Vault): void {
  ensureVaultDir();
  const file = getVaultFilePath();
  writeFileSync(file, JSON.stringify(vault, null, 2), { mode: 0o600 });
  chmodSync(file, 0o600);
}

export function setSecret(
  key: string,
  value: string,
  type: SecretEntry["type"] = "other",
  label?: string
): SecretEntry {
  const vault = loadVault();
  const now = new Date().toISOString();
  const existing = vault.secrets[key];
  const entry: SecretEntry = {
    key,
    value,
    type,
    label,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  vault.secrets[key] = entry;
  saveVault(vault);
  return entry;
}

export function getSecret(key: string): SecretEntry | undefined {
  const vault = loadVault();
  return vault.secrets[key];
}

export function deleteSecret(key: string): boolean {
  const vault = loadVault();
  if (!vault.secrets[key]) return false;
  delete vault.secrets[key];
  saveVault(vault);
  return true;
}

export function listSecrets(namespace?: string): SecretEntry[] {
  const vault = loadVault();
  const all = Object.values(vault.secrets);
  if (!namespace) return all;
  const prefix = namespace.endsWith("/") ? namespace : `${namespace}/`;
  return all.filter((s) => s.key.startsWith(prefix) || s.key === namespace);
}

export function searchSecrets(query: string): SecretEntry[] {
  const vault = loadVault();
  const q = query.toLowerCase();
  return Object.values(vault.secrets).filter(
    (s) =>
      s.key.toLowerCase().includes(q) ||
      (s.label?.toLowerCase().includes(q) ?? false) ||
      s.type.toLowerCase().includes(q)
  );
}

export function getVaultPath(): string {
  return getVaultFilePath();
}

export function importSecrets(
  entries: Array<{ key: string; value: string; type?: SecretEntry["type"]; label?: string }>
): number {
  const vault = loadVault();
  const now = new Date().toISOString();
  let count = 0;
  for (const e of entries) {
    const existing = vault.secrets[e.key];
    vault.secrets[e.key] = {
      key: e.key,
      value: e.value,
      type: e.type ?? "other",
      label: e.label,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    count++;
  }
  saveVault(vault);
  return count;
}

export function exportSecrets(redact = false): Vault {
  const vault = loadVault();
  if (!redact) return vault;
  const redacted: Vault = { version: vault.version, secrets: {} };
  for (const [k, v] of Object.entries(vault.secrets)) {
    redacted.secrets[k] = { ...v, value: "***REDACTED***" };
  }
  return redacted;
}
