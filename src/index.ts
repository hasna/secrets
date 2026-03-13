#!/usr/bin/env node
import {
  setSecret,
  getSecret,
  deleteSecret,
  listSecrets,
  searchSecrets,
  getVaultPath,
  importSecrets,
  exportSecrets,
} from "./store.js";
import type { SecretEntry } from "./types.js";

const TYPES: SecretEntry["type"][] = ["api_key", "password", "token", "credential", "other"];

function usage(): void {
  console.log(`
secrets — local secrets vault for AI agents

Usage:
  secrets set <key> <value> [--type <type>] [--label <label>]
  secrets get <key>
  secrets delete <key>
  secrets list [namespace]
  secrets search <query>
  secrets export [--redact]
  secrets import <json-file>
  secrets path

Types: ${TYPES.join(", ")}

Examples:
  secrets set openai/api_key sk-abc123 --type api_key
  secrets set gmail/password "hunter2" --type password --label "Gmail account"
  secrets set stripe/webhook_secret whsec_xxx --type token
  secrets get openai/api_key
  secrets list openai
  secrets search gmail
  secrets export --redact
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

function formatEntry(entry: SecretEntry, showValue = false): string {
  const val = showValue ? entry.value : "***";
  const label = entry.label ? ` (${entry.label})` : "";
  return `${entry.key}${label} [${entry.type}] = ${val}`;
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
    if (!key || !value) {
      console.error("Usage: secrets set <key> <value> [--type <type>] [--label <label>]");
      process.exit(1);
    }
    const type = (flags.type as SecretEntry["type"]) ?? "other";
    if (!TYPES.includes(type)) {
      console.error(`Invalid type "${type}". Valid: ${TYPES.join(", ")}`);
      process.exit(1);
    }
    const entry = setSecret(key, value, type, flags.label);
    console.log(`✓ Stored: ${entry.key} [${entry.type}]`);
    break;
  }

  case "get": {
    const [key] = positional;
    if (!key) {
      console.error("Usage: secrets get <key>");
      process.exit(1);
    }
    const entry = getSecret(key);
    if (!entry) {
      console.error(`Not found: ${key}`);
      process.exit(1);
    }
    // When stdout is a TTY, show formatted; when piped, just print the value
    if (process.stdout.isTTY) {
      console.log(formatEntry(entry, true));
    } else {
      process.stdout.write(entry.value);
    }
    break;
  }

  case "delete": {
    const [key] = positional;
    if (!key) {
      console.error("Usage: secrets delete <key>");
      process.exit(1);
    }
    const deleted = deleteSecret(key);
    if (!deleted) {
      console.error(`Not found: ${key}`);
      process.exit(1);
    }
    console.log(`✓ Deleted: ${key}`);
    break;
  }

  case "list": {
    const [namespace] = positional;
    const entries = listSecrets(namespace);
    if (entries.length === 0) {
      console.log(namespace ? `No secrets in namespace: ${namespace}` : "Vault is empty.");
    } else {
      for (const e of entries.sort((a, b) => a.key.localeCompare(b.key))) {
        console.log(formatEntry(e, false));
      }
      console.log(`\n${entries.length} secret(s)`);
    }
    break;
  }

  case "search": {
    const [query] = positional;
    if (!query) {
      console.error("Usage: secrets search <query>");
      process.exit(1);
    }
    const results = searchSecrets(query);
    if (results.length === 0) {
      console.log(`No results for: ${query}`);
    } else {
      for (const e of results.sort((a, b) => a.key.localeCompare(b.key))) {
        console.log(formatEntry(e, false));
      }
      console.log(`\n${results.length} result(s)`);
    }
    break;
  }

  case "export": {
    const redact = "redact" in flags;
    const vault = exportSecrets(redact);
    console.log(JSON.stringify(vault, null, 2));
    break;
  }

  case "import": {
    const [file] = positional;
    if (!file) {
      console.error("Usage: secrets import <json-file>");
      process.exit(1);
    }
    try {
      const { readFileSync } = await import("fs");
      const raw = readFileSync(file, "utf-8");
      const data = JSON.parse(raw);
      // Support both vault format and array format
      const entries = Array.isArray(data)
        ? data
        : data.secrets
        ? Object.values(data.secrets)
        : [];
      const count = importSecrets(entries as any);
      console.log(`✓ Imported ${count} secret(s)`);
    } catch (e: any) {
      console.error(`Import failed: ${e.message}`);
      process.exit(1);
    }
    break;
  }

  case "path": {
    console.log(getVaultPath());
    break;
  }

  default: {
    console.error(`Unknown command: ${command}`);
    usage();
    process.exit(1);
  }
}
