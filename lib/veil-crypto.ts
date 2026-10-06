/** Protocol v1. Never store passphrases. */
export type Envelope = { version: 1; salt: string; iv: string; ciphertext: string };
export type Task = { id: string; title: string; done: boolean };
export type Unlocked = { key: CryptoKey; writeToken: string };
export const ITERATIONS = 600_000;
const encoder = new TextEncoder();
const aad = encoder.encode("VEIL:encrypted-tasks:v1");
export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
export function fromBase64(input: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(input), (char) => char.charCodeAt(0));
}
export async function derive(passphrase: string, salt: string): Promise<Unlocked> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: fromBase64(salt), iterations: ITERATIONS, hash: "SHA-256" }, material, 512));
  const key = await crypto.subtle.importKey("raw", bits.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
  const writeToken = toBase64(bits.slice(32));
  bits.fill(0);
  return { key, writeToken };
}
export async function seal(tasks: Task[], key: CryptoKey, salt: string): Promise<Envelope> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = encoder.encode(JSON.stringify({ format: "VEIL:v1", tasks }));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, payload);
  payload.fill(0);
  return { version: 1, salt, iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(encrypted)) };
}
export async function unseal(envelope: Envelope, key: CryptoKey): Promise<Task[]> {
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(envelope.iv), additionalData: aad, tagLength: 128 }, key, fromBase64(envelope.ciphertext)));
  try {
    const value = JSON.parse(new TextDecoder().decode(plaintext));
    if (value.format !== "VEIL:v1" || !Array.isArray(value.tasks) || value.tasks.length > 500 || value.tasks.some((t: Task) => typeof t.id !== "string" || typeof t.title !== "string" || typeof t.done !== "boolean")) throw new Error("Invalid vault");
    return value.tasks;
  } finally { plaintext.fill(0); }
}
