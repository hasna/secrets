#!/usr/bin/env bun
import {
  getUser,
  setSecret,
  getSecret,
  deleteSecret,
  listSecrets,
  searchSecrets,
  importSecrets,
  exportSecrets,
  getAuditLog,
  pruneExpired,
  getVaultPath,
  registerUser,
  listUsers,
  deleteUser,
} from "./store.js";
import { getDb } from "./db.js";
import { encrypt, decrypt, isEncrypted, getMasterKey } from "./crypto.js";
import type { SecretEntry } from "./types.js";

const SECRET_TYPES: SecretEntry["type"][] = ["api_key", "password", "token", "credential", "other"];

function usage(): void {
  console.log(`
secrets — local secrets vault for AI agents

Commands:
  set <key> <value> [--type <type>] [--label <label>] [--ttl <ttl>]
  get <key>
  delete <key>               (aliases: remove, rm, uninstall)
  import-env                 import ~/.secrets/ .env files into vault [--dir <path>] [--push] [--dry-run] [--overwrite]
  export-env                 export vault secrets to ~/.secrets/ .env files [--dir <path>] [--force] [--dry-run]
  list [namespace]
  search <query>
  export [--redact]
  import <json-file>
  gc                          prune expired secrets
  audit [key]                 show audit log
  path                        show vault db path

  users list [--type human|agent]
  users register <id> <name> [--type human|agent]
  users delete <id>

  encrypt-vault               encrypt all plaintext secrets in the vault
  key                         show master key status
  key init                    generate master key if missing
  key path                    show master key file path

  aws configure               interactive AWS setup
  aws push [key]              push secret(s) to AWS Secrets Manager
  aws pull <key>              pull secret from AWS Secrets Manager
  aws sync                    bidirectional sync

  feedback <message>          send feedback [--email <email>] [--category <cat>]
  mcp                         start MCP server (stdio)
  mcp install [--target claude|codex|gemini]  install MCP into AI agents

Types: ${SECRET_TYPES.join(", ")}
TTL examples: 30d, 24h, 60m

Examples:
  secrets set openai/api_key sk-abc123 --type api_key
  secrets set gmail/password "hunter2" --type password --label "Gmail"
  secrets get openai/api_key
  secrets list openai
  secrets search gmail
  secrets users register my-agent "My Agent" --type agent
  secrets aws configure
  secrets aws sync
`);
}

const BOOLEAN_FLAGS = new Set(["redact", "push", "dry-run", "force", "overwrite"]);

function parseArgs(args: string[]): { flags: Record<string, string>; positional: string[] } {
  const flags: Record<string, string> = {};
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      if (BOOLEAN_FLAGS.has(key) || !args[i + 1] || args[i + 1].startsWith("--")) {
        flags[key] = "true";
      } else {
        flags[key] = args[i + 1];
        i++;
      }
    } else {
      positional.push(args[i]);
    }
  }
  return { flags, positional };
}

function parseTtl(ttl: string): string {
  const match = ttl.match(/^(\d+)([smhd])$/);
  if (!match) { console.error(`Invalid TTL: ${ttl}. Use e.g. 30d, 24h, 60m`); process.exit(1); }
  const [, num, unit] = match;
  const ms = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[unit as string]!;
  return new Date(Date.now() + parseInt(num) * ms).toISOString();
}

function formatEntry(entry: SecretEntry, showValue = false): string {
  const val = showValue ? entry.value : "***";
  const label = entry.label ? ` (${entry.label})` : "";
  const expiry = entry.expires_at
    ? ` [expires: ${new Date(entry.expires_at).toLocaleDateString()}]`
    : "";
  const expired =
    entry.expires_at && new Date(entry.expires_at) < new Date() ? " [EXPIRED]" : "";
  return `${entry.key}${label} [${entry.type}]${expiry}${expired} = ${val}`;
}

const args = process.argv.slice(2);
const [command, ...rest] = args;

if (!command || command === "--help" || command === "-h") {
  usage();
  process.exit(0);
}

const { flags, positional } = parseArgs(rest);

switch (command) {
  case "set": {
    const [key, value] = positional;
    if (!key || !value) { console.error("Usage: secrets set <key> <value>"); process.exit(1); }
    const type = (flags.type as SecretEntry["type"]) ?? "other";
    if (!SECRET_TYPES.includes(type)) {
      console.error(`Invalid type "${type}". Valid: ${SECRET_TYPES.join(", ")}`);
      process.exit(1);
    }
    // Warn if AGENT_ID is set but agent is not registered — mirrors open-todos pattern
    const agentId = process.env["AGENT_ID"];
    if (agentId && !getUser(agentId)) {
      console.warn(`⚠ Warning: AGENT_ID="${agentId}" is set but not registered. Run: secrets users register ${agentId} <name> --type agent`);
    }
    const expiresAt = flags.ttl ? parseTtl(flags.ttl) : undefined;
    const entry = setSecret(key, value, type, flags.label, expiresAt);
    console.log(`✓ Stored: ${entry.key} [${entry.type}]${expiresAt ? ` (expires ${new Date(expiresAt).toLocaleDateString()})` : ""}`);
    break;
  }

  case "get": {
    const [key] = positional;
    if (!key) { console.error("Usage: secrets get <key>"); process.exit(1); }
    const entry = getSecret(key);
    if (!entry) { console.error(`Not found: ${key}`); process.exit(1); }
    if (process.stdout.isTTY) {
      console.log(formatEntry(entry, true));
    } else {
      process.stdout.write(entry.value);
    }
    break;
  }

  case "delete":
  case "remove":
  case "rm":
  case "uninstall": {
    const [key] = positional;
    if (!key) { console.error(`Usage: secrets ${command} <key>`); process.exit(1); }
    if (!deleteSecret(key)) { console.error(`Not found: ${key}`); process.exit(1); }
    console.log(`✓ Deleted: ${key}`);
    break;
  }

  case "list": {
    const [namespace] = positional;
    const entries = listSecrets(namespace);
    if (entries.length === 0) {
      console.log(namespace ? `No secrets in namespace: ${namespace}` : "Vault is empty.");
    } else {
      for (const e of entries) console.log(formatEntry(e));
      console.log(`\n${entries.length} secret(s)`);
    }
    break;
  }

  case "search": {
    const [query] = positional;
    if (!query) { console.error("Usage: secrets search <query>"); process.exit(1); }
    const results = searchSecrets(query);
    if (results.length === 0) { console.log(`No results for: ${query}`); }
    else {
      for (const e of results) console.log(formatEntry(e));
      console.log(`\n${results.length} result(s)`);
    }
    break;
  }

  case "export": {
    const redact = "redact" in flags;
    console.log(JSON.stringify(exportSecrets(redact), null, 2));
    break;
  }

  case "import": {
    const [file] = positional;
    if (!file) { console.error("Usage: secrets import <json-file>"); process.exit(1); }
    try {
      const { readFileSync } = await import("fs");
      const data = JSON.parse(readFileSync(file, "utf-8"));
      const entries = Array.isArray(data) ? data : data.secrets ? Object.values(data.secrets) : [];
      const count = importSecrets(entries as any);
      console.log(`✓ Imported ${count} secret(s)`);
    } catch (e: any) {
      console.error(`Import failed: ${e.message}`);
      process.exit(1);
    }
    break;
  }

  case "gc": {
    const count = pruneExpired();
    console.log(`✓ Pruned ${count} expired secret(s)`);
    break;
  }

  case "audit": {
    const [key] = positional;
    const limit = flags.limit ? parseInt(flags.limit) : 50;
    const entries = getAuditLog(key, limit);
    if (entries.length === 0) { console.log("No audit entries."); }
    else {
      for (const e of entries) {
        console.log(`[${e.timestamp}] ${e.action.toUpperCase().padEnd(6)} ${e.key} — ${e.agent}`);
      }
    }
    break;
  }

  case "path": {
    console.log(getVaultPath());
    break;
  }

  case "users": {
    const [sub, ...userRest] = positional;
    const { flags: uFlags, positional: uPos } = parseArgs(userRest);
    switch (sub) {
      case "list": {
        const users = listUsers(uFlags.type as any);
        if (users.length === 0) { console.log("No users registered."); }
        else {
          for (const u of users) {
            const seen = u.last_seen ? ` (last seen: ${new Date(u.last_seen).toLocaleDateString()})` : "";
            console.log(`${u.id} [${u.type}] — ${u.name}${seen}`);
          }
          console.log(`\n${users.length} user(s)`);
        }
        break;
      }
      case "register": {
        const [id, name] = uPos;
        if (!id || !name) { console.error("Usage: secrets users register <id> <name> [--type human|agent]"); process.exit(1); }
        const user = registerUser(id, name, (uFlags.type as any) ?? "human");
        console.log(`✓ Registered: ${user.id} [${user.type}] — ${user.name}`);
        break;
      }
      case "delete": {
        const [id] = uPos;
        if (!id) { console.error("Usage: secrets users delete <id>"); process.exit(1); }
        if (!deleteUser(id)) { console.error(`Not found: ${id}`); process.exit(1); }
        console.log(`✓ Deleted user: ${id}`);
        break;
      }
      default:
        console.error(`Unknown users subcommand: ${sub}`);
        process.exit(1);
    }
    break;
  }

  case "aws": {
    const [sub, ...awsRest] = positional;
    const { loadAwsConfig, saveAwsConfig, pushSecret, pullSecret, syncAll } = await import("./aws.js");

    switch (sub) {
      case "configure": {
        const readline = await import("readline");
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        const ask = (q: string): Promise<string> =>
          new Promise((r) => rl.question(q, r));

        console.log("Configure AWS Secrets Manager access\n");
        const access_key_id = await ask("AWS Access Key ID: ");
        const secret_access_key = await ask("AWS Secret Access Key: ");
        const region = await ask("AWS Region [us-east-1]: ") || "us-east-1";
        const prefix = await ask("Key prefix (optional, e.g. open-secrets/prod): ");
        rl.close();

        saveAwsConfig({ access_key_id, secret_access_key, region, prefix: prefix || undefined });
        console.log("✓ AWS configuration saved");
        break;
      }

      case "push": {
        const [key] = awsRest;
        if (key) {
          await pushSecret(key);
          console.log(`✓ Pushed: ${key}`);
        } else {
          const entries = listSecrets();
          for (const e of entries) {
            await pushSecret(e.key);
            console.log(`✓ Pushed: ${e.key}`);
          }
        }
        break;
      }

      case "pull": {
        const [key] = awsRest;
        if (!key) { console.error("Usage: secrets aws pull <key>"); process.exit(1); }
        await pullSecret(key);
        console.log(`✓ Pulled: ${key}`);
        break;
      }

      case "sync": {
        console.log("Syncing with AWS Secrets Manager...");
        const { pushed, pulled, errors } = await syncAll();
        if (pushed.length) console.log(`Pushed (${pushed.length}): ${pushed.join(", ")}`);
        if (pulled.length) console.log(`Pulled (${pulled.length}): ${pulled.join(", ")}`);
        if (errors.length) { console.error(`Errors:\n${errors.map(e => `  ${e}`).join("\n")}`); }
        console.log("✓ Sync complete");
        break;
      }

      default:
        console.error(`Unknown aws subcommand: ${sub}`);
        process.exit(1);
    }
    break;
  }

  case "mcp": {
    const [sub] = positional;
    if (sub === "install") {
      const targets = flags.target ? [flags.target] : ["claude", "codex", "gemini"];
      const { installMcp } = await import("./install.js");
      installMcp(targets);
    } else {
      const { startMcpServer } = await import("./mcp.js");
      await startMcpServer();
    }
    break;
  }

  case "import-dot-secrets": {
    // Bridge: import all *.env files from ~/.secrets/ into the vault
    const { readdirSync, readFileSync, existsSync } = await import("fs");
    const { join } = await import("path");
    const { homedir } = await import("os");
    const secretsDir = flags.dir ?? join(homedir(), ".secrets");
    if (!existsSync(secretsDir)) {
      console.error(`Directory not found: ${secretsDir}`);
      process.exit(1);
    }

    // Recursively find *.env files
    function findEnvFiles(dir: string): string[] {
      const results: string[] = [];
      try {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          const full = join(dir, entry.name);
          if (entry.isDirectory()) results.push(...findEnvFiles(full));
          else if (entry.isFile() && entry.name.endsWith(".env")) results.push(full);
        }
      } catch { /* skip unreadable dirs */ }
      return results;
    }

    // Infer type from key name
    function inferType(key: string): SecretEntry["type"] {
      const k = key.toUpperCase();
      if (k.includes("PASSWORD") || k.includes("PASS") || k.includes("PWD")) return "password";
      if (k.includes("API_KEY") || k.includes("APIKEY") || k.includes("SECRET_KEY")) return "api_key";
      if (k.includes("TOKEN") || k.includes("_KEY")) return "token";
      if (k.includes("CERT") || k.includes("CERTIFICATE")) return "certificate";
      return "other";
    }

    const envFiles = findEnvFiles(secretsDir);
    let imported = 0, skipped = 0;
    for (const file of envFiles) {
      const content = readFileSync(file, "utf-8");
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eqIdx = trimmed.indexOf("=");
        if (eqIdx === -1) continue;
        const rawKey = trimmed.slice(0, eqIdx).trim();
        let rawValue = trimmed.slice(eqIdx + 1).trim();
        if ((rawValue.startsWith('"') && rawValue.endsWith('"')) ||
            (rawValue.startsWith("'") && rawValue.endsWith("'"))) {
          rawValue = rawValue.slice(1, -1);
        }
        if (!rawKey || !rawValue) continue;
        const key = rawKey.toLowerCase().replace(/_/g, "-");
        const type = inferType(rawKey);
        // Skip if already exists and not overriding
        if (!flags.overwrite && getSecret(key)) { skipped++; continue; }
        setSecret(key, rawValue, type);
        imported++;
      }
    }
    console.log(`✓ Imported ${imported} secret(s) from ${envFiles.length} file(s) in ${secretsDir}`);
    if (skipped > 0) console.log(`  Skipped ${skipped} already-existing key(s) (use --overwrite to replace)`);
    break;
  }

  case "import-env": {
    const { importEnv } = await import("./env.js");
    try {
      const result = await importEnv({
        dir: flags.dir,
        push: "push" in flags,
        dryRun: "dry-run" in flags,
        overwrite: "overwrite" in flags,
      });
      if ("dry-run" in flags) {
        console.log(`\n[dry-run] Would import ${result.imported} secret(s) from ${result.files} file(s)`);
      } else {
        console.log(`✓ Imported ${result.imported} secret(s) from ${result.files} file(s)`);
        if (result.skipped > 0) console.log(`  Skipped ${result.skipped} already-existing key(s) (use --overwrite to replace)`);
      }
    } catch (e: any) {
      console.error(`Import failed: ${e.message}`);
      process.exit(1);
    }
    break;
  }

  case "export-env": {
    const { exportEnv } = await import("./env.js");
    try {
      const result = exportEnv({
        dir: flags.dir,
        force: "force" in flags,
        dryRun: "dry-run" in flags,
      });
      if ("dry-run" in flags) {
        console.log(`\n[dry-run] Would export ${result.exported} secret(s) to ${result.files} file(s)`);
      } else {
        console.log(`✓ Exported ${result.exported} secret(s) to ${result.files} file(s)`);
        if (result.skippedFiles > 0) console.log(`  Skipped ${result.skippedFiles} existing file(s) (use --force to overwrite)`);
      }
    } catch (e: any) {
      console.error(`Export failed: ${e.message}`);
      process.exit(1);
    }
    break;
  }

  case "encrypt-vault": {
    // Migrate all plaintext secrets to encrypted
    const db = getDb();
    const rows = db.prepare("SELECT key, value FROM secrets").all() as { key: string; value: string }[];
    let migrated = 0;
    let alreadyEncrypted = 0;
    for (const row of rows) {
      if (isEncrypted(row.value)) {
        alreadyEncrypted++;
        continue;
      }
      const enc = encrypt(row.value);
      db.prepare("UPDATE secrets SET value = ?, updated_at = ? WHERE key = ?")
        .run(enc, new Date().toISOString(), row.key);
      migrated++;
    }
    console.log(`✓ Encrypted ${migrated} secret(s). ${alreadyEncrypted} already encrypted.`);
    break;
  }

  case "key": {
    const [sub] = positional;
    const { join } = await import("path");
    const { homedir } = await import("os");
    const { existsSync } = await import("fs");
    const keyDir = process.env.HASNA_SECRETS_KEY_DIR ?? join(homedir(), ".hasna", "secrets");
    const keyPath = join(keyDir, "vault.key");
    if (sub === "path") {
      console.log(keyPath);
    } else if (sub === "exists") {
      console.log(existsSync(keyPath) ? "yes" : "no");
    } else if (sub === "init") {
      getMasterKey(); // creates if not exists
      console.log(`✓ Master key ready at ${keyPath}`);
    } else {
      const exists = existsSync(keyPath);
      console.log(`Master key: ${exists ? "✓ present" : "✗ missing"}`);
      console.log(`Location:   ${keyPath}`);
      if (exists) {
        const { statSync } = await import("fs");
        const stat = statSync(keyPath);
        const mode = (stat.mode & 0o777).toString(8);
        console.log(`Permissions: ${mode}${mode === "600" ? " (correct)" : " ⚠ should be 600"}`);
      }
      console.log(`\nCommands:`);
      console.log(`  secrets key init     Generate key if missing`);
      console.log(`  secrets key path     Show key file path`);
      console.log(`  secrets key exists   Check if key exists`);
    }
    break;
  }

  case "feedback": {
    const [msg, ...restMsg] = positional;
    const message = [msg, ...restMsg.filter(r => !r.startsWith("--"))].join(" ");
    if (!message) { console.error("Usage: secrets feedback <message> [--email <email>] [--category <cat>]"); process.exit(1); }
    const db = getDb();
    db.run(
      "INSERT INTO feedback (message, email, category, version) VALUES (?, ?, ?, ?)",
      [message, flags.email || null, flags.category || "general", "0.1.0"]
    );
    console.log("✓ Feedback saved. Thank you!");
    break;
  }

  default: {
    console.error(`Unknown command: ${command}`);
    usage();
    process.exit(1);
  }
}
