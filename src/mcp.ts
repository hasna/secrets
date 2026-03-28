import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerCloudTools } from "@hasna/cloud";
import { PG_MIGRATIONS } from "./pg-migrations.js";
import { z } from "zod";
import {
  setSecret,
  getSecret,
  deleteSecret,
  listSecrets,
  searchSecrets,
  getAuditLog,
  registerUser,
  listUsers,
} from "./store.js";

const SECRET_TYPES = ["api_key", "password", "token", "credential", "other"] as const;

export async function startMcpServer(): Promise<void> {
  const server = new McpServer({
    name: "open-secrets",
    version: "0.1.0",
  });

  server.tool(
    "get_secret",
    "Retrieve a secret value by key",
    { key: z.string().describe("The secret key (e.g. openai/api_key)") },
    async ({ key }) => {
      const entry = getSecret(key);
      if (!entry) return { content: [{ type: "text", text: `Not found: ${key}` }], isError: true };
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ key: entry.key, value: entry.value, type: entry.type, label: entry.label }),
          },
        ],
      };
    }
  );

  server.tool(
    "set_secret",
    "Store a secret in the vault",
    {
      key: z.string().describe("The secret key (e.g. openai/api_key)"),
      value: z.string().describe("The secret value"),
      type: z.enum(SECRET_TYPES).optional().describe("Secret type"),
      label: z.string().optional().describe("Human-readable label"),
      ttl: z.string().optional().describe("TTL e.g. 30d, 24h"),
    },
    async ({ key, value, type, label, ttl }) => {
      const expiresAt = ttl ? parseTtl(ttl) : undefined;
      const entry = setSecret(key, value, type ?? "other", label, expiresAt);
      return { content: [{ type: "text", text: `Stored: ${entry.key} [${entry.type}]` }] };
    }
  );

  server.tool(
    "delete_secret",
    "Delete a secret from the vault",
    { key: z.string() },
    async ({ key }) => {
      const ok = deleteSecret(key);
      if (!ok) return { content: [{ type: "text", text: `Not found: ${key}` }], isError: true };
      return { content: [{ type: "text", text: `Deleted: ${key}` }] };
    }
  );

  server.tool(
    "list_secrets",
    "List secrets, optionally filtered by namespace",
    { namespace: z.string().optional().describe("Namespace prefix e.g. openai") },
    async ({ namespace }) => {
      const entries = listSecrets(namespace);
      const lines = entries.map((e) => `${e.key} [${e.type}]${e.label ? ` — ${e.label}` : ""}`);
      return { content: [{ type: "text", text: lines.join("\n") || "No secrets found." }] };
    }
  );

  server.tool(
    "search_secrets",
    "Search secrets by key, label, or type",
    { query: z.string() },
    async ({ query }) => {
      const entries = searchSecrets(query);
      const lines = entries.map((e) => `${e.key} [${e.type}]${e.label ? ` — ${e.label}` : ""}`);
      return { content: [{ type: "text", text: lines.join("\n") || "No results." }] };
    }
  );

  server.tool(
    "audit_log",
    "View audit log for a key or recent activity",
    {
      key: z.string().optional().describe("Filter by key"),
      limit: z.number().optional().describe("Max entries (default 50)"),
    },
    async ({ key, limit }) => {
      const entries = getAuditLog(key, limit ?? 50);
      const lines = entries.map(
        (e) => `[${e.timestamp}] ${e.action.toUpperCase()} ${e.key} by ${e.agent}`
      );
      return { content: [{ type: "text", text: lines.join("\n") || "No audit entries." }] };
    }
  );

  server.tool(
    "register_user",
    "Register a human or agent user",
    {
      id: z.string().describe("Unique ID (e.g. agent name or email)"),
      name: z.string().describe("Display name"),
      type: z.enum(["human", "agent"]).optional(),
    },
    async ({ id, name, type }) => {
      const user = registerUser(id, name, type ?? "human");
      return { content: [{ type: "text", text: `Registered: ${user.id} (${user.type})` }] };
    }
  );

  server.tool(
    "list_users",
    "List registered users and agents",
    { type: z.enum(["human", "agent"]).optional() },
    async ({ type }) => {
      const users = listUsers(type);
      const lines = users.map((u) => `${u.id} [${u.type}] — ${u.name}`);
      return { content: [{ type: "text", text: lines.join("\n") || "No users registered." }] };
    }
  );

  server.tool(
    "send_feedback",
    "Send feedback about this service",
    {
      message: z.string().describe("Feedback message"),
      email: z.string().optional().describe("Contact email (optional)"),
      category: z.enum(["bug", "feature", "general"]).optional().describe("Feedback category"),
    },
    async ({ message, email, category }) => {
      const { getDb } = await import("./db.js");
      const db = getDb();
      db.run(
        "INSERT INTO feedback (message, email, category, version) VALUES (?, ?, ?, ?)",
        [message, email || null, category || "general", "0.1.0"]
      );
      return { content: [{ type: "text", text: "Feedback saved. Thank you!" }] };
    }
  );

  const transport = new StdioServerTransport();
  registerCloudTools(server, "secrets", { migrations: PG_MIGRATIONS });
  await server.connect(transport);
}

function parseTtl(ttl: string): string {
  const match = ttl.match(/^(\d+)([smhd])$/);
  if (!match) throw new Error(`Invalid TTL: ${ttl}. Use e.g. 30d, 24h, 60m`);
  const [, num, unit] = match;
  const ms = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[unit as string]!;
  return new Date(Date.now() + parseInt(num) * ms).toISOString();
}
