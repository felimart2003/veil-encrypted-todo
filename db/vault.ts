import { env } from "cloudflare:workers";
export function vaultDb(): D1Database {
  if (!env.DB) throw new Error("Vault database unavailable");
  return env.DB;
}
export function setupHash(): string | undefined { return env.VEIL_SETUP_HASH; }
