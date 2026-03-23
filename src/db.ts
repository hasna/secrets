import { Database } from "bun:sqlite";
import { join } from "path";
import { homedir } from "os";
import { mkdirSync, existsSync, cpSync } from "fs";

function getDbPath(): string {
  // Support env var overrides
  const envPath = process.env.HASNA_SECRETS_DB_PATH ?? process.env.OPEN_SECRETS_DB;
  if (envPath) return envPath;

  const home = homedir();
  const newDir = join(home, ".hasna", "secrets");
  const oldDir = join(home, ".open-secrets");

  // Auto-migrate from old location if new dir doesn't exist yet
  if (!existsSync(newDir) && existsSync(oldDir)) {
    try {
      mkdirSync(join(home, ".hasna"), { recursive: true });
      cpSync(oldDir, newDir, { recursive: true });
    } catch {
      // Fall through
    }
  }

  return join(newDir, "vault.db");
}

function getDbDir(): string {
  return join(getDbPath(), "..");
}

let _db: Database | null = null;

export function getDb(): Database {
  const path = getDbPath();
  // Open fresh db if path changed (supports test isolation)
  if (_db && (_db as any).filename !== path) {
    _db.close();
    _db = null;
  }
  if (!_db) {
    const dir = getDbDir();
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
    _db = new Database(path, { create: true });
    _db.exec("PRAGMA journal_mode=WAL");
    migrate(_db);
  }
  return _db;
}

export function closeDb(): void {
  if (_db) { _db.close(); _db = null; }
}

export function resetDb(): void {
  closeDb();
}

function migrate(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS secrets (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      type       TEXT NOT NULL DEFAULT 'other',
      label      TEXT,
      expires_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      action    TEXT NOT NULL,
      key       TEXT NOT NULL,
      agent     TEXT NOT NULL,
      timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id         TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      type       TEXT NOT NULL DEFAULT 'human',
      registered_at TEXT NOT NULL,
      last_seen  TEXT
    );
  `);
}
