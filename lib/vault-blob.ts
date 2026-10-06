import { get, put, BlobPreconditionFailedError } from "@vercel/blob";
import type { VaultRecord, VaultStore } from "./vault-store.ts";

const pathname = "veil/vault.json";
// This module is imported only by the server route. The Blob credential is never
// returned to the browser; public reads select only envelope and revision.
export function createBlobStore(client = { get, put }): VaultStore {
  const read: VaultStore["read"] = async () => {
    const result = await client.get(pathname, { access: "private", useCache: false });
    if (!result) return null;
    if (result.statusCode !== 200) throw new Error("Unexpected vault storage response");
    const value = await new Response(result.stream).json() as VaultRecord;
    if (!value.envelope || !Number.isSafeInteger(value.revision) || value.revision < 1 || !/^[a-f0-9]{64}$/.test(value.writeHash)) {
      throw new Error("Invalid stored vault");
    }
    return { ...value, etag: result.blob.etag };
  };
  const options = { access: "private" as const, addRandomSuffix: false, contentType: "application/json" };
  return {
    read,
    async create(value) {
      try {
        await client.put(pathname, JSON.stringify(value), { ...options, allowOverwrite: false });
        return true;
      } catch (error) {
        // A concurrent setup may have created the singleton. Never retry with
        // overwrite permission, even when the original upload result is unclear.
        if (await read()) return false;
        throw error;
      }
    },
    async replace(value, etag) {
      try {
        await client.put(pathname, JSON.stringify(value), { ...options, allowOverwrite: true, ifMatch: etag });
        return true;
      } catch (error) {
        if (error instanceof BlobPreconditionFailedError) return false;
        throw error;
      }
    },
  };
}
