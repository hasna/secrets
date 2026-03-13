import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, rmSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  setSecret,
  getSecret,
  deleteSecret,
  listSecrets,
  searchSecrets,
  importSecrets,
  exportSecrets,
  getVaultPath,
} from "../src/store.js";

// Point store at a temp file per test via OPEN_SECRETS_VAULT env var
let vaultFile: string;
let vaultDir: string;

beforeEach(() => {
  vaultDir = join(tmpdir(), `open-secrets-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(vaultDir, { recursive: true });
  vaultFile = join(vaultDir, "vault.json");
  process.env.OPEN_SECRETS_VAULT = vaultFile;
});

afterEach(() => {
  delete process.env.OPEN_SECRETS_VAULT;
  rmSync(vaultDir, { recursive: true, force: true });
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
    const entry = getSecret("gmail/pass");
    expect(entry!.label).toBe("My Gmail");
  });

  it("updates existing secret preserving createdAt", async () => {
    setSecret("foo/bar", "v1", "other");
    const first = getSecret("foo/bar")!;
    await new Promise((r) => setTimeout(r, 10));
    setSecret("foo/bar", "v2", "other");
    const second = getSecret("foo/bar")!;
    expect(second.value).toBe("v2");
    expect(second.createdAt).toBe(first.createdAt);
    expect(second.updatedAt).not.toBe(first.updatedAt);
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

  it("returns empty array for unknown namespace", () => {
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

describe("importSecrets", () => {
  it("imports multiple entries", () => {
    const count = importSecrets([
      { key: "a/b", value: "1", type: "api_key" },
      { key: "c/d", value: "2", type: "password" },
    ]);
    expect(count).toBe(2);
    expect(getSecret("a/b")!.value).toBe("1");
  });
});

describe("exportSecrets", () => {
  it("exports with values by default", () => {
    setSecret("key/one", "secret!", "token");
    expect(exportSecrets(false).secrets["key/one"].value).toBe("secret!");
  });

  it("redacts values when asked", () => {
    setSecret("key/one", "secret!", "token");
    expect(exportSecrets(true).secrets["key/one"].value).toBe("***REDACTED***");
  });
});

describe("getVaultPath", () => {
  it("reflects OPEN_SECRETS_VAULT env var", () => {
    expect(getVaultPath()).toBe(vaultFile);
  });
});
