import { createVaultApi } from "@/lib/vault-api";
import { createBlobStore } from "@/lib/vault-blob";
import preview from "@/lib/preview-envelope.json";
import type { Envelope } from "@/lib/veil-crypto";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
const api = createVaultApi(createBlobStore(), () => process.env.VEIL_SETUP_HASH, preview as Envelope);
export const GET = api.GET;
export const POST = api.POST;
