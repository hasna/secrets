export type SecretType = "api_key" | "password" | "token" | "credential" | "other";

export interface SecretEntry {
  key: string;
  value: string;
  type: SecretType;
  label?: string;
  expires_at?: string;
  created_at: string;
  updated_at: string;
}

export interface AuditEntry {
  id: number;
  action: "get" | "set" | "delete";
  key: string;
  agent: string;
  timestamp: string;
}

export interface AwsConfig {
  access_key_id: string;
  secret_access_key: string;
  region: string;
  prefix?: string;
}
