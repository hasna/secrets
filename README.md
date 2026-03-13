# open-secrets

A local secrets vault for AI agents. Store API keys, passwords, tokens, and any credentials — in a single, permission-locked file at `~/.open-secrets/vault.json`.

Not to be confused with `.secrets/` (division-level API key storage). This is for **agent day-to-day work** — ephemeral lookups, multi-type credentials, namespaced keys.

## Install

```bash
bun install -g @hasna/secrets
```

## Usage

```bash
# Store a secret
secrets set openai/api_key sk-abc123 --type api_key
secrets set gmail/password "hunter2" --type password --label "Gmail account"
secrets set stripe/webhook_secret whsec_xxx --type token

# Retrieve
secrets get openai/api_key

# List all, or by namespace
secrets list
secrets list openai

# Search by key, label, or type
secrets search gmail
secrets search api_key

# Delete
secrets delete gmail/password

# Export (redacted by default for safety)
secrets export --redact
secrets export > backup.json

# Import from JSON
secrets import backup.json

# Show vault file path
secrets path
```

## Key format

Use `/` as a namespace separator:

```
service/field
service/environment/field
```

Examples:
- `openai/api_key`
- `openai/prod/api_key`
- `gmail/andrei/password`
- `stripe/live/secret_key`

## Types

| Type | Use for |
|------|---------|
| `api_key` | API keys |
| `password` | Passwords |
| `token` | OAuth tokens, webhook secrets |
| `credential` | Combined credentials (e.g. user+pass pairs) |
| `other` | Anything else |

## Storage

Secrets are stored at `~/.open-secrets/vault.json` with `600` permissions (owner read/write only). The directory has `700` permissions.

> **Note:** Secrets are stored in plaintext. Do not store secrets you'd be uncomfortable having on disk. For high-security use cases, use a proper secrets manager.

## Piping

When stdout is not a TTY, `secrets get` outputs just the raw value — useful for scripting:

```bash
OPENAI_API_KEY=$(secrets get openai/api_key)
```

## License

MIT
