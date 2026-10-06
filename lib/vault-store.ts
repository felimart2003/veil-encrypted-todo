import type { Envelope } from "./veil-crypto.ts";

export type VaultRecord = { envelope: Envelope; writeHash: string; revision: number };
export type VaultSnapshot = VaultRecord & { etag: string };
export interface VaultStore {
  read(): Promise<VaultSnapshot | null>;
  create(value: VaultRecord): Promise<boolean>;
  replace(value: VaultRecord, etag: string): Promise<boolean>;
}
