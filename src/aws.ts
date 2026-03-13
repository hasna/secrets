import {
  SecretsManagerClient,
  GetSecretValueCommand,
  CreateSecretCommand,
  UpdateSecretCommand,
  ListSecretsCommand,
  DeleteSecretCommand,
  ResourceNotFoundException,
} from "@aws-sdk/client-secrets-manager";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { setSecret, listSecrets, getSecret } from "./store.js";
import type { AwsConfig } from "./types.js";

function getAwsConfigPath(): string {
  return join(homedir(), ".open-secrets", "aws.json");
}

export function loadAwsConfig(): AwsConfig | null {
  const path = getAwsConfigPath();
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as AwsConfig;
  } catch {
    return null;
  }
}

export function saveAwsConfig(config: AwsConfig): void {
  const path = getAwsConfigPath();
  const dir = join(path, "..");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify(config, null, 2), { mode: 0o600 });
}

function makeClient(config: AwsConfig): SecretsManagerClient {
  return new SecretsManagerClient({
    region: config.region,
    credentials: {
      accessKeyId: config.access_key_id,
      secretAccessKey: config.secret_access_key,
    },
  });
}

function awsName(key: string, prefix?: string): string {
  const base = key.replace(/\//g, "/");
  return prefix ? `${prefix}/${base}` : base;
}

function localKey(awsName: string, prefix?: string): string {
  if (prefix && awsName.startsWith(`${prefix}/`)) {
    return awsName.slice(prefix.length + 1);
  }
  return awsName;
}

export async function pushSecret(key: string): Promise<void> {
  const config = loadAwsConfig();
  if (!config) throw new Error("AWS not configured. Run: secrets aws configure");

  const entry = getSecret(key);
  if (!entry) throw new Error(`Secret not found: ${key}`);

  const client = makeClient(config);
  const name = awsName(key, config.prefix);

  try {
    await client.send(new GetSecretValueCommand({ SecretId: name }));
    await client.send(new UpdateSecretCommand({ SecretId: name, SecretString: entry.value }));
  } catch (e: any) {
    if (e instanceof ResourceNotFoundException || e.name === "ResourceNotFoundException") {
      await client.send(
        new CreateSecretCommand({
          Name: name,
          SecretString: entry.value,
          Description: entry.label ?? `Managed by open-secrets (type: ${entry.type})`,
          Tags: [
            { Key: "open-secrets-key", Value: key },
            { Key: "open-secrets-type", Value: entry.type },
          ],
        })
      );
    } else {
      throw e;
    }
  }
}

export async function pullSecret(key: string): Promise<void> {
  const config = loadAwsConfig();
  if (!config) throw new Error("AWS not configured. Run: secrets aws configure");

  const client = makeClient(config);
  const name = awsName(key, config.prefix);

  const res = await client.send(new GetSecretValueCommand({ SecretId: name }));
  if (!res.SecretString) throw new Error(`No string value for secret: ${name}`);

  setSecret(key, res.SecretString);
}

export async function syncAll(): Promise<{ pushed: string[]; pulled: string[]; errors: string[] }> {
  const config = loadAwsConfig();
  if (!config) throw new Error("AWS not configured. Run: secrets aws configure");

  const client = makeClient(config);
  const pushed: string[] = [];
  const pulled: string[] = [];
  const errors: string[] = [];

  // Push all local secrets to AWS
  const local = listSecrets();
  for (const entry of local) {
    try {
      await pushSecret(entry.key);
      pushed.push(entry.key);
    } catch (e: any) {
      errors.push(`push ${entry.key}: ${e.message}`);
    }
  }

  // Pull any AWS secrets not in local vault
  try {
    const prefix = config.prefix;
    let nextToken: string | undefined;
    do {
      const res = await client.send(
        new ListSecretsCommand({ NextToken: nextToken, MaxResults: 100 })
      );
      for (const s of res.SecretList ?? []) {
        if (!s.Name) continue;
        if (prefix && !s.Name.startsWith(`${prefix}/`)) continue;
        const key = localKey(s.Name, prefix);
        if (!getSecret(key)) {
          try {
            await pullSecret(key);
            pulled.push(key);
          } catch (e: any) {
            errors.push(`pull ${key}: ${e.message}`);
          }
        }
      }
      nextToken = res.NextToken;
    } while (nextToken);
  } catch (e: any) {
    errors.push(`list: ${e.message}`);
  }

  return { pushed, pulled, errors };
}
