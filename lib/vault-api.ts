import type { Envelope } from "./veil-crypto.ts";
import type { VaultStore } from "./vault-store.ts";

const response = (value: unknown, status = 200) => Response.json(value, { status, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
async function digest(token: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))), b => b.toString(16).padStart(2, "0")).join("");
}
function equal(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function valid(e: Envelope): boolean {
  const base64 = /^[A-Za-z0-9+/]+={0,2}$/;
  return !!e && e.version === 1 && typeof e.salt === "string" && e.salt.length === 24 && base64.test(e.salt) && typeof e.iv === "string" && e.iv.length === 16 && base64.test(e.iv) && typeof e.ciphertext === "string" && e.ciphertext.length >= 24 && e.ciphertext.length <= 200_000 && base64.test(e.ciphertext);
}
export function createVaultApi(store: VaultStore, setupHash: () => string | undefined, preview: Envelope) {
  return {
    async GET() {
      try {
        const row = await store.read();
        return response(row ? { initialized: true, envelope: row.envelope, revision: row.revision } : { initialized: false, envelope: preview, revision: 0 });
      } catch {
        console.error("Vault read unavailable");
        return response({ error: "The vault is temporarily unavailable. Please try again." }, 503);
      }
    },
    async POST(request: Request) {
      try {
        const origin = request.headers.get("origin");
        if (origin && origin !== new URL(request.url).origin) return response({ error: "Cross-origin writes are not allowed." }, 403);
        if (!request.headers.get("content-type")?.includes("application/json")) return response({ error: "JSON required." }, 415);
        if (Number(request.headers.get("content-length") || 0) > 210_000) return response({ error: "Vault too large." }, 413);
        const raw = await request.text();
        if (raw.length > 210_000) return response({ error: "Vault too large." }, 413);
        let body;
        try { body = JSON.parse(raw); } catch { return response({ error: "Invalid JSON." }, 400); }
        if (!body || !valid(body.envelope) || !Number.isSafeInteger(body.revision) || body.revision < 0) return response({ error: "Invalid encrypted envelope." }, 400);
        const token = request.headers.get("authorization")?.replace(/^Bearer /, "") || "";
        if (!/^[A-Za-z0-9+/]{43}=$/.test(token)) return response({ error: "A valid write credential is required." }, 401);
        const writeHash = await digest(token);
        const row = await store.read();
        if (!row) {
          const invite = request.headers.get("x-veil-setup") || "";
          const expected = setupHash();
          if (!expected || !invite || !equal(await digest(invite), expected)) return response({ error: "The private setup invitation is required." }, 403);
          if (body.revision !== 0) return response({ error: "Reload the vault before setup." }, 409);
          const inserted = await store.create({ envelope: body.envelope, writeHash, revision: 1 });
          if (!inserted) return response({ error: "This vault has already been claimed. Reload to unlock it." }, 409);
          return response({ revision: 1 });
        }
        if (!equal(writeHash, row.writeHash)) return response({ error: "Write access denied." }, 401);
        if (body.envelope.salt !== row.envelope.salt) return response({ error: "Vault salt cannot change." }, 400);
        if (body.revision !== row.revision) return response({ error: "Another tab changed this list. Lock and unlock to load the latest version." }, 409);
        const updated = await store.replace({ envelope: body.envelope, writeHash: row.writeHash, revision: row.revision + 1 }, row.etag);
        if (!updated) return response({ error: "Another tab changed this list. Lock and unlock to load the latest version." }, 409);
        return response({ revision: row.revision + 1 });
      } catch {
        // Do not log credentials, request contents, storage URLs, or SDK errors.
        console.error("Vault write unavailable");
        return response({ error: "Could not save. Your changes remain on this screen; try again." }, 503);
      }
    },
  };
}
