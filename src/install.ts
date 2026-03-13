import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { execSync } from "child_process";

const MCP_NAME = "secrets";

function getSecretsCmd(): string {
  try {
    return execSync("which secrets", { encoding: "utf-8" }).trim();
  } catch {
    return "secrets";
  }
}

function mcpEntry(cmd: string) {
  return {
    type: "stdio",
    command: cmd,
    args: ["mcp"],
    env: {},
  };
}

// ── Claude Code ────────────────────────────────────────────────────────────────

function installClaudeCode(cmd: string): string {
  const path = join(homedir(), ".claude.json");
  if (!existsSync(path)) return "~/.claude.json not found — skipped";
  const d = JSON.parse(readFileSync(path, "utf-8"));
  d.mcpServers ??= {};
  d.mcpServers[MCP_NAME] = mcpEntry(cmd);
  writeFileSync(path, JSON.stringify(d, null, 2));
  return `✓ Claude Code — registered as "${MCP_NAME}" in ~/.claude.json`;
}

// ── Codex CLI ─────────────────────────────────────────────────────────────────

function installCodex(cmd: string): string {
  const path = join(homedir(), ".codex", "config.json");
  const dir = join(path, "..");
  let d: any = {};
  if (existsSync(path)) {
    try { d = JSON.parse(readFileSync(path, "utf-8")); } catch {}
  } else {
    mkdirSync(dir, { recursive: true });
  }
  d.mcpServers ??= {};
  d.mcpServers[MCP_NAME] = mcpEntry(cmd);
  writeFileSync(path, JSON.stringify(d, null, 2));
  return `✓ Codex CLI — registered as "${MCP_NAME}" in ~/.codex/config.json`;
}

// ── Gemini CLI ────────────────────────────────────────────────────────────────

function installGemini(cmd: string): string {
  const dir = join(homedir(), ".gemini", "extensions", MCP_NAME);
  mkdirSync(dir, { recursive: true });

  // gemini-extension.json manifest
  writeFileSync(
    join(dir, "gemini-extension.json"),
    JSON.stringify({ name: MCP_NAME, version: "1.0.0" }, null, 2)
  );

  // SKILL.md with MCP server info
  writeFileSync(
    join(dir, "SKILL.md"),
    `---
name: ${MCP_NAME}
description: Local secrets vault — get/set/list/delete/search secrets, audit log, user registry
user_invocable: false
mcp:
  command: ${cmd}
  args: [mcp]
---

MCP server for open-secrets vault. Use tools: get_secret, set_secret, list_secrets, delete_secret, search_secrets, audit_log, register_user, list_users.
`
  );

  return `✓ Gemini CLI — extension installed at ~/.gemini/extensions/${MCP_NAME}/`;
}

export function installMcp(targets: string[] = ["claude", "codex", "gemini"]): void {
  const cmd = getSecretsCmd();
  const results: string[] = [];

  for (const target of targets) {
    try {
      switch (target) {
        case "claude": results.push(installClaudeCode(cmd)); break;
        case "codex":  results.push(installCodex(cmd)); break;
        case "gemini": results.push(installGemini(cmd)); break;
        default: results.push(`⚠ Unknown target: ${target}`);
      }
    } catch (e: any) {
      results.push(`✗ ${target}: ${e.message}`);
    }
  }

  for (const r of results) console.log(r);
  console.log("\nRestart your AI agent to pick up the new MCP server.");
}
