import { readdirSync, readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from "fs";
import { join, relative, dirname, basename } from "path";
import { homedir } from "os";
import { setSecret, listSecrets, getSecret } from "./store.js";
import type { SecretType } from "./types.js";

/**
 * Infer secret type from variable name.
 */
function inferType(varName: string): SecretType {
  const k = varName.toUpperCase();
  if (k.includes("API_KEY") || k.includes("APIKEY") || k.includes("SECRET_KEY")) return "api_key";
  if (k.includes("TOKEN")) return "token";
  if (k.includes("PASSWORD") || k.includes("PASS") || k.includes("PWD")) return "password";
  return "other";
}

/**
 * Parse a .env file into key=value pairs.
 * Handles KEY=VALUE, KEY="VALUE", KEY='VALUE', comments, blank lines.
 */
function parseEnvFile(content: string): Array<{ varName: string; value: string }> {
  const results: Array<{ varName: string; value: string }> = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("export ")) {
      // Also handle `export KEY=VALUE`
      if (trimmed.startsWith("export ")) {
        const rest = trimmed.slice(7).trim();
        const eqIdx = rest.indexOf("=");
        if (eqIdx === -1) continue;
        const varName = rest.slice(0, eqIdx).trim();
        let value = rest.slice(eqIdx + 1).trim();
        value = stripQuotes(value);
        if (varName && value) results.push({ varName, value });
      }
      continue;
    }
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const varName = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();
    value = stripQuotes(value);
    if (!varName || !value) continue;
    results.push({ varName, value });
  }
  return results;
}

function stripQuotes(s: string): string {
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

/**
 * Recursively find all .env files in a directory.
 * Skips .secrets nested inside .secrets (known bug on some machines).
 */
function findEnvFiles(dir: string, rootDir: string): string[] {
  const results: string[] = [];
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        // Skip .secrets nested dirs
        if (entry.name === ".secrets") continue;
        results.push(...findEnvFiles(full, rootDir));
      } else if (entry.isFile() && entry.name.endsWith(".env")) {
        results.push(full);
      }
    }
  } catch { /* skip unreadable dirs */ }
  return results;
}

/**
 * Convert a file path + variable name into a vault key.
 *
 * File path: ~/.secrets/hasnaxyz/anthropic/live.env
 * Variable: HASNAXYZ_ANTHROPIC_LIVE_API_KEY
 * Vault key: hasnaxyz/anthropic/live/api_key
 *
 * Strategy:
 * - Get the relative dir path from secrets root (e.g. "hasnaxyz/anthropic")
 * - Get the env file basename without .env (e.g. "live")
 * - Combine: "hasnaxyz/anthropic/live"
 * - Strip the prefix from the variable name to get the suffix
 * - The prefix is the dir path + env name, uppercased with _ separators
 * - Vault key = dir_path/env_name/suffix_lowercase
 */
function toVaultKey(filePath: string, varName: string, secretsRoot: string): string {
  const relDir = relative(secretsRoot, dirname(filePath));
  const envName = basename(filePath, ".env"); // "live", "sandbox"
  const dirPath = relDir ? `${relDir}/${envName}` : envName;

  // Build the expected prefix from the directory path + env name
  // e.g. "hasnaxyz/anthropic/live" -> "HASNAXYZ_ANTHROPIC_LIVE"
  // Hyphens in dir names map to underscores in variable names
  const prefixParts = dirPath.split("/").map((s) => s.replace(/-/g, "_").toUpperCase());
  const expectedPrefix = prefixParts.join("_");

  let suffix: string;
  const upperVar = varName.toUpperCase();
  if (upperVar.startsWith(expectedPrefix + "_")) {
    suffix = varName.slice(expectedPrefix.length + 1).toLowerCase();
  } else {
    // Fallback: use full variable name lowercase
    suffix = varName.toLowerCase();
  }

  // Replace _ with / in suffix? No — keep suffix as single segment with underscores replaced
  // Actually per spec: suffix stays as-is but with _ for readability
  // The vault key should be: dir_path/suffix_with_underscores
  return `${dirPath}/${suffix}`;
}

/**
 * Convert a vault key back to a file path and variable name.
 *
 * Vault key: hasnaxyz/anthropic/live/api_key
 * -> dir segments: hasnaxyz/anthropic
 * -> env level: live
 * -> key suffix: api_key
 * -> File: ~/.secrets/hasnaxyz/anthropic/live.env
 * -> Variable: HASNAXYZ_ANTHROPIC_LIVE_API_KEY
 *
 * We need to figure out which segment is the "env level" (live, sandbox, test, staging).
 * The env level is the segment that matches known env names, scanning from the end.
 */
const KNOWN_ENVS = new Set(["live", "sandbox", "test", "staging"]);

function fromVaultKey(vaultKey: string, secretsRoot: string): { filePath: string; varName: string } {
  const parts = vaultKey.split("/");

  // Find the env-level segment (scan from end, looking for known env names)
  let envIdx = -1;
  for (let i = parts.length - 2; i >= 1; i--) {
    if (KNOWN_ENVS.has(parts[i])) {
      envIdx = i;
      break;
    }
  }

  let dirParts: string[];
  let envName: string;
  let keySuffix: string;

  if (envIdx >= 0) {
    dirParts = parts.slice(0, envIdx);
    envName = parts[envIdx];
    keySuffix = parts.slice(envIdx + 1).join("_");
  } else {
    // No known env found — use second-to-last as a generic level
    // e.g. "hasnaxyz/github/token" -> dir=hasnaxyz/github, env=?
    // Fallback: all parts except last form the dir, last is key, env defaults to "live"
    dirParts = parts.slice(0, -1);
    envName = "live";
    keySuffix = parts[parts.length - 1];
  }

  const dirPath = dirParts.join("/");
  const filePath = join(secretsRoot, dirPath, `${envName}.env`);
  const varName = [...dirParts, envName, keySuffix].join("_").toUpperCase();

  return { filePath, varName };
}

export interface ImportEnvOptions {
  dir?: string;
  push?: boolean;
  dryRun?: boolean;
  overwrite?: boolean;
}

export async function importEnv(opts: ImportEnvOptions): Promise<{ imported: number; skipped: number; files: number }> {
  const secretsRoot = opts.dir ?? join(homedir(), ".secrets");
  if (!existsSync(secretsRoot)) {
    throw new Error(`Directory not found: ${secretsRoot}`);
  }

  const envFiles = findEnvFiles(secretsRoot, secretsRoot);
  let imported = 0;
  let skipped = 0;
  const toPush: string[] = [];

  for (const file of envFiles) {
    const content = readFileSync(file, "utf-8");
    const entries = parseEnvFile(content);
    for (const { varName, value } of entries) {
      const vaultKey = toVaultKey(file, varName, secretsRoot);
      const type = inferType(varName);

      if (opts.dryRun) {
        console.log(`[dry-run] ${varName} -> ${vaultKey} [${type}]`);
        imported++;
        continue;
      }

      // Skip if already exists and not overwriting
      if (!opts.overwrite && getSecret(vaultKey)) {
        skipped++;
        continue;
      }

      setSecret(vaultKey, value, type, varName);
      imported++;
      if (opts.push) toPush.push(vaultKey);
    }
  }

  // Push to AWS if requested
  if (opts.push && toPush.length > 0 && !opts.dryRun) {
    const { pushSecret } = await import("./aws.js");
    for (const key of toPush) {
      try {
        await pushSecret(key);
        console.log(`  Pushed: ${key}`);
      } catch (e: any) {
        console.error(`  Push failed for ${key}: ${e.message}`);
      }
    }
  }

  return { imported, skipped, files: envFiles.length };
}

export interface ExportEnvOptions {
  dir?: string;
  force?: boolean;
  dryRun?: boolean;
}

export function exportEnv(opts: ExportEnvOptions): { exported: number; files: number; skippedFiles: number } {
  const secretsRoot = opts.dir ?? join(homedir(), ".secrets");

  const allSecrets = listSecrets();
  if (allSecrets.length === 0) {
    throw new Error("Vault is empty — nothing to export.");
  }

  // Group secrets by target file
  const fileMap = new Map<string, Array<{ varName: string; value: string }>>();

  for (const entry of allSecrets) {
    const { filePath, varName } = fromVaultKey(entry.key, secretsRoot);
    if (!fileMap.has(filePath)) fileMap.set(filePath, []);
    fileMap.get(filePath)!.push({ varName, value: entry.value });
  }

  let exported = 0;
  let files = 0;
  let skippedFiles = 0;

  for (const [filePath, vars] of fileMap) {
    if (opts.dryRun) {
      console.log(`[dry-run] Would write ${filePath} (${vars.length} var(s))`);
      for (const v of vars) console.log(`  ${v.varName}=***`);
      files++;
      exported += vars.length;
      continue;
    }

    if (!opts.force && existsSync(filePath)) {
      console.log(`  Skipped (exists): ${filePath}`);
      skippedFiles++;
      continue;
    }

    const dir = dirname(filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });

    const content = vars.map((v) => `${v.varName}="${v.value}"`).join("\n") + "\n";
    writeFileSync(filePath, content, { mode: 0o600 });
    files++;
    exported += vars.length;
  }

  return { exported, files, skippedFiles };
}
