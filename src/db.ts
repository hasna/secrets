import { Database } from "bun:sqlite";
import { SqliteAdapter, ensureFeedbackTable, migrateDotfile } from "@hasna/cloud";
import { join } from "path";
import { homedir } from "os";
import { mkdirSync, existsSync } from "fs";

function getDbPath(): string {
  // Support env var overrides
  const envPath = process.env.HASNA_SECRETS_DB_PATH ?? process.env.OPEN_SECRETS_DB;
  if (envPath) return envPath;

  const home = homedir();
  migrateDotfile("secrets");
  const newDir = join(home, ".hasna", "secrets");
  if (!existsSync(newDir)) mkdirSync(newDir, { recursive: true, mode: 0o700 });
  return join(newDir, "vault.db");
}

function getDbDir(): string {
  return join(getDbPath(), "..");
}

let _db: Database | null = null;
let _adapter: SqliteAdapter | null = null;

export function getDb(): Database {
  const path = getDbPath();
  // Open fresh db if path changed (supports test isolation)
  if (_db && (_db as any).filename !== path) {
    _db.close();
    _db = null;
    _adapter = null;
  }
  if (!_db) {
    const dir = getDbDir();
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
    _adapter = new SqliteAdapter(path);
    _db = _adapter.raw;
    migrate(_db);
    ensureFeedbackTable(_adapter);
  }
  return _db;
}

export function closeDb(): void {
  if (_db) { _db.close(); _db = null; _adapter = null; }
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
