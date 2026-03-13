import { hostname } from "os";
import { getDb } from "./db.js";
import type { SecretEntry, SecretType, AuditEntry } from "./types.js";

function currentAgent(): string {
  return process.env.AGENT_ID ?? process.env.USER ?? hostname();
}

function audit(action: AuditEntry["action"], key: string): void {
  const db = getDb();
  db.prepare(
    "INSERT INTO audit_log (action, key, agent, timestamp) VALUES (?, ?, ?, ?)"
  ).run(action, key, currentAgent(), new Date().toISOString());
}

export function setSecret(
  key: string,
  value: string,
  type: SecretType = "other",
  label?: string,
  expiresAt?: string
): SecretEntry {
  const db = getDb();
  const now = new Date().toISOString();
  const existing = db.prepare("SELECT created_at FROM secrets WHERE key = ?").get(key) as
    | { created_at: string }
    | undefined;

  db.prepare(`
    INSERT INTO secrets (key, value, type, label, expires_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      type = excluded.type,
      label = excluded.label,
      expires_at = excluded.expires_at,
      updated_at = excluded.updated_at
  `).run(key, value, type, label ?? null, expiresAt ?? null, existing?.created_at ?? now, now);

  audit("set", key);
  return getSecret(key)!;
}

export function getSecret(key: string): SecretEntry | undefined {
  const db = getDb();
  const row = db.prepare("SELECT * FROM secrets WHERE key = ?").get(key) as SecretEntry | undefined;
  if (!row) return undefined;
  audit("get", key);
  return row;
}

export function deleteSecret(key: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM secrets WHERE key = ?").run(key);
  if (result.changes === 0) return false;
  audit("delete", key);
  return true;
}

export function listSecrets(namespace?: string): SecretEntry[] {
  const db = getDb();
  if (!namespace) {
    return db.prepare("SELECT * FROM secrets ORDER BY key").all() as SecretEntry[];
  }
  const prefix = namespace.endsWith("/") ? namespace : `${namespace}/`;
  return db
    .prepare("SELECT * FROM secrets WHERE key LIKE ? OR key = ? ORDER BY key")
    .all(`${prefix}%`, namespace) as SecretEntry[];
}

export function searchSecrets(query: string): SecretEntry[] {
  const db = getDb();
  const q = `%${query}%`;
  return db
    .prepare(
      "SELECT * FROM secrets WHERE key LIKE ? OR label LIKE ? OR type LIKE ? ORDER BY key"
    )
    .all(q, q, q) as SecretEntry[];
}

export function importSecrets(
  entries: Array<{ key: string; value: string; type?: SecretType; label?: string; expires_at?: string }>
): number {
  let count = 0;
  for (const e of entries) {
    setSecret(e.key, e.value, e.type ?? "other", e.label, e.expires_at);
    count++;
  }
  return count;
}

export function exportSecrets(redact = false): { version: number; secrets: Record<string, SecretEntry> } {
  const db = getDb();
  const rows = db.prepare("SELECT * FROM secrets ORDER BY key").all() as SecretEntry[];
  const secrets: Record<string, SecretEntry> = {};
  for (const row of rows) {
    secrets[row.key] = redact ? { ...row, value: "***REDACTED***" } : row;
  }
  return { version: 2, secrets };
}

export function getAuditLog(key?: string, limit = 100): AuditEntry[] {
  const db = getDb();
  if (key) {
    return db
      .prepare("SELECT * FROM audit_log WHERE key = ? ORDER BY timestamp DESC LIMIT ?")
      .all(key, limit) as AuditEntry[];
  }
  return db
    .prepare("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?")
    .all(limit) as AuditEntry[];
}

export function pruneExpired(): number {
  const db = getDb();
  const result = db
    .prepare("DELETE FROM secrets WHERE expires_at IS NOT NULL AND expires_at < ?")
    .run(new Date().toISOString());
  return result.changes;
}

export function getVaultPath(): string {
  const db = getDb();
  return (db as any).filename as string;
}

// Users / agents registry
export interface User {
  id: string;
  name: string;
  type: "human" | "agent";
  registered_at: string;
  last_seen?: string;
}

export function registerUser(id: string, name: string, type: "human" | "agent" = "human"): User {
  const db = getDb();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO users (id, name, type, registered_at, last_seen)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET name = excluded.name, type = excluded.type, last_seen = excluded.last_seen
  `).run(id, name, type, now, now);
  return getUser(id)!;
}

export function getUser(id: string): User | undefined {
  const db = getDb();
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id) as User | undefined;
}

export function listUsers(type?: "human" | "agent"): User[] {
  const db = getDb();
  if (type) {
    return db.prepare("SELECT * FROM users WHERE type = ? ORDER BY name").all(type) as User[];
  }
  return db.prepare("SELECT * FROM users ORDER BY type, name").all() as User[];
}

export function deleteUser(id: string): boolean {
  const db = getDb();
  return db.prepare("DELETE FROM users WHERE id = ?").run(id).changes > 0;
}

export function touchUser(id: string): void {
  const db = getDb();
  db.prepare("UPDATE users SET last_seen = ? WHERE id = ?").run(new Date().toISOString(), id);
}
