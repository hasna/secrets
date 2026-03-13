#!/usr/bin/env bun
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
  getVaultPath,
  registerUser,
  listUsers,
  deleteUser,
} from "./store.js";
import type { SecretEntry } from "./types.js";

const SECRET_TYPES: SecretEntry["type"][] = ["api_key", "password", "token", "credential", "other"];

function usage(): void {
  console.log(`
secrets — local secrets vault for AI agents

Commands:
  set <key> <value> [--type <type>] [--label <label>] [--ttl <ttl>]
  get <key>
  delete <key>
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

  aws configure               interactive AWS setup
  aws push [key]              push secret(s) to AWS Secrets Manager
  aws pull <key>              pull secret from AWS Secrets Manager
  aws sync                    bidirectional sync

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

function parseArgs(args: string[]): { flags: Record<string, string>; positional: string[] } {
  const flags: Record<string, string> = {};
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      flags[key] = args[i + 1] ?? "true";
      i++;
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

  case "delete": {
    const [key] = positional;
    if (!key) { console.error("Usage: secrets delete <key>"); process.exit(1); }
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

  default: {
    console.error(`Unknown command: ${command}`);
    usage();
    process.exit(1);
  }
}
