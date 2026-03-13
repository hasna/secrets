export interface SecretEntry {
  key: string;
  value: string;
  type: "api_key" | "password" | "token" | "credential" | "other";
  label?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Vault {
  version: number;
  secrets: Record<string, SecretEntry>;
}
