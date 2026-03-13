import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { resetDb } from "../src/db.js";
import {
  setSecret,
  getSecret,
  deleteSecret,
  listSecrets,
  searchSecrets,
  importSecrets,
  exportSecrets,
  getAuditLog,
  pruneExpired,
  registerUser,
  listUsers,
  deleteUser,
} from "../src/store.js";

let testDir: string;

beforeEach(() => {
  testDir = join(tmpdir(), `open-secrets-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(testDir, { recursive: true });
  process.env.OPEN_SECRETS_DB = join(testDir, "vault.db");
  resetDb();
});

afterEach(() => {
  resetDb();
  delete process.env.OPEN_SECRETS_DB;
  rmSync(testDir, { recursive: true, force: true });
});

describe("setSecret / getSecret", () => {
  it("stores and retrieves a secret", () => {
    setSecret("openai/api_key", "sk-test-123", "api_key");
    const entry = getSecret("openai/api_key");
    expect(entry).toBeDefined();
    expect(entry!.value).toBe("sk-test-123");
    expect(entry!.type).toBe("api_key");
  });

  it("stores with label", () => {
    setSecret("gmail/pass", "hunter2", "password", "My Gmail");
    expect(getSecret("gmail/pass")!.label).toBe("My Gmail");
  });

  it("stores with TTL", () => {
    const future = new Date(Date.now() + 86400000).toISOString();
    setSecret("token/short", "abc", "token", undefined, future);
    expect(getSecret("token/short")!.expires_at).toBe(future);
  });

  it("updates existing secret preserving created_at", async () => {
    setSecret("foo/bar", "v1", "other");
    const first = getSecret("foo/bar")!;
    await new Promise((r) => setTimeout(r, 10));
    setSecret("foo/bar", "v2", "other");
    const second = getSecret("foo/bar")!;
    expect(second.value).toBe("v2");
    expect(second.created_at).toBe(first.created_at);
    expect(second.updated_at).not.toBe(first.updated_at);
  });

  it("returns undefined for missing key", () => {
    expect(getSecret("does/not/exist")).toBeUndefined();
  });
});

describe("deleteSecret", () => {
  it("deletes an existing secret", () => {
    setSecret("to/delete", "bye", "other");
    expect(deleteSecret("to/delete")).toBe(true);
    expect(getSecret("to/delete")).toBeUndefined();
  });

  it("returns false for missing key", () => {
    expect(deleteSecret("not/there")).toBe(false);
  });
});

describe("listSecrets", () => {
  it("lists all secrets", () => {
    setSecret("openai/key", "sk-1", "api_key");
    setSecret("openai/org", "org-1", "other");
    setSecret("stripe/key", "sk-s", "api_key");
    setSecret("toplevel", "val", "other");
    expect(listSecrets().length).toBe(4);
  });

  it("filters by namespace", () => {
    setSecret("openai/key", "sk-1", "api_key");
    setSecret("openai/org", "org-1", "other");
    setSecret("stripe/key", "sk-s", "api_key");
    const openai = listSecrets("openai");
    expect(openai.length).toBe(2);
    expect(openai.every((s) => s.key.startsWith("openai/"))).toBe(true);
  });

  it("returns empty for unknown namespace", () => {
    setSecret("openai/key", "sk-1", "api_key");
    expect(listSecrets("unknown")).toHaveLength(0);
  });
});

describe("searchSecrets", () => {
  it("searches by key", () => {
    setSecret("openai/api_key", "sk-1", "api_key", "OpenAI production key");
    setSecret("gmail/password", "pass123", "password");
    expect(searchSecrets("openai")).toHaveLength(1);
  });

  it("searches by label", () => {
    setSecret("openai/api_key", "sk-1", "api_key", "OpenAI production key");
    expect(searchSecrets("production")).toHaveLength(1);
  });

  it("searches by type", () => {
    setSecret("openai/api_key", "sk-1", "api_key");
    setSecret("gmail/password", "pass123", "password");
    expect(searchSecrets("password")).toHaveLength(1);
  });

  it("returns empty for no match", () => {
    setSecret("openai/api_key", "sk-1", "api_key");
    expect(searchSecrets("zzznomatch")).toHaveLength(0);
  });
});

describe("importSecrets / exportSecrets", () => {
  it("imports multiple entries", () => {
    const count = importSecrets([
      { key: "a/b", value: "1", type: "api_key" },
      { key: "c/d", value: "2", type: "password" },
    ]);
    expect(count).toBe(2);
    expect(getSecret("a/b")!.value).toBe("1");
  });

  it("exports with values", () => {
    setSecret("key/one", "secret!", "token");
    expect(exportSecrets(false).secrets["key/one"].value).toBe("secret!");
  });

  it("exports redacted", () => {
    setSecret("key/one", "secret!", "token");
    expect(exportSecrets(true).secrets["key/one"].value).toBe("***REDACTED***");
  });
});

describe("audit log", () => {
  it("records set and get actions", () => {
    setSecret("audit/key", "val", "other");
    getSecret("audit/key");
    const log = getAuditLog("audit/key");
    expect(log.some((e) => e.action === "set")).toBe(true);
    expect(log.some((e) => e.action === "get")).toBe(true);
  });

  it("records delete action", () => {
    setSecret("audit/del", "val", "other");
    deleteSecret("audit/del");
    const log = getAuditLog("audit/del");
    expect(log.some((e) => e.action === "delete")).toBe(true);
  });
});

describe("pruneExpired", () => {
  it("removes expired secrets", () => {
    const past = new Date(Date.now() - 1000).toISOString();
    const future = new Date(Date.now() + 86400000).toISOString();
    setSecret("expired/key", "old", "other", undefined, past);
    setSecret("valid/key", "new", "other", undefined, future);
    const count = pruneExpired();
    expect(count).toBe(1);
    expect(getSecret("expired/key")).toBeUndefined();
    expect(getSecret("valid/key")).toBeDefined();
  });
});

describe("users", () => {
  it("registers and lists users", () => {
    registerUser("agent-1", "My Agent", "agent");
    registerUser("human-1", "Alice", "human");
    expect(listUsers().length).toBe(2);
    expect(listUsers("agent").length).toBe(1);
    expect(listUsers("human")[0].name).toBe("Alice");
  });

  it("updates on re-register", () => {
    registerUser("agent-1", "Old Name", "agent");
    registerUser("agent-1", "New Name", "agent");
    expect(listUsers().length).toBe(1);
    expect(listUsers()[0].name).toBe("New Name");
  });

  it("deletes a user", () => {
    registerUser("to-del", "Delete Me", "human");
    expect(deleteUser("to-del")).toBe(true);
    expect(listUsers()).toHaveLength(0);
  });

  it("returns false deleting nonexistent user", () => {
    expect(deleteUser("nope")).toBe(false);
  });
});
