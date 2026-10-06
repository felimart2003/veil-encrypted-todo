# VEIL

A publicly visible personal to-do list whose meaning stays behind a secret. Anyone can inspect the encrypted list and source code; only someone with the passphrase can decrypt or edit the list.

Hosting target: **Vercel**. The Vercel migration is prepared; a verified production URL will be added after deployment.

## Use it

The owner opens their private, one-time setup invitation and chooses a unique passphrase of at least 16 characters. The key is created in the browser, never by the build process. Add tasks, mark them complete, or delete them after unlocking. Changes are encrypted before they are saved to shared storage. Other visitors see ciphertext. Click **Lock the vault** when finished; it also locks after five minutes without keyboard or pointer activity.

Optional automatic unlock: append `#key=YOUR_URL_ENCODED_KEY` to the site URL. Encode the key with `encodeURIComponent` or `URLSearchParams`. The fragment is consumed and removed on load. It is not sent in the HTTP request, but the full link is a secret: anyone who has it can read and edit the vault. Use the password field on shared devices. Query-string keys such as `?key=` are intentionally unsupported.

**There is no forgotten-key recovery.** Save your passphrase privately. The setup invitation cannot replace or reset an initialized vault.

## Security design

- Browser-native Web Crypto API, with no external cryptography library.
- PBKDF2-SHA-256, 600,000 iterations, and a random 128-bit salt derive 512 bits. The first 256 bits become a non-exportable AES key; the remaining 256 bits become an independent write credential.
- AES-256-GCM encrypts the entire list, including task IDs and completion state. Each save uses a fresh random 96-bit nonce, a 128-bit authentication tag, and a fixed protocol label as authenticated additional data.
- The public endpoint exposes only the versioned encrypted envelope and revision. No secret, encryption key, write credential, or write hash appears in the public response.
- The write endpoint hashes and validates the separate write credential on every mutation. Knowing the public source code does not grant write access.
- A private runtime environment variable stores the SHA-256 hash of a random setup invitation. Initialization creates a singleton private blob with overwrites disabled; a concurrent or replayed invitation cannot replace it.
- Saves require the stored revision and an atomic Blob ETag precondition. Conflicting changes from another tab are rejected. Reads bypass the storage CDN cache to retrieve the current version immediately.
- Input limits, JSON validation, origin checks, non-cacheable API responses, and browser security headers limit accidental exposure and unsafe mutations.
- Keys and cleartext live only in page memory. There is no localStorage or sessionStorage copy, analytics, remote font, or third-party script. Locking drops credentials, cleartext tasks, and form drafts. JavaScript garbage collection means this is not a guarantee of physical memory erasure.
- The initial visual preview is genuine AES-GCM ciphertext created with a random, discarded key. It is not the owner's list and has no public unlock passphrase.

Read [SECURITY.md](SECURITY.md) for the trust model and limitations. The algorithms, parameters, salt, and IV are deliberately public. Security relies on a strong secret, not hidden source code.

## Stack

React, TypeScript, and Next.js on Vercel. A Vercel Function serves the public encrypted envelope and authenticates writes. Vercel private Blob storage holds a single encrypted vault document and the write-credential hash. No separate database provider is required for this personal list.

The active `dev`, `build`, and `start` commands use Next.js. Historical starter utilities and D1 migrations are retained in the repository but are not used by the Vercel application. No ChatGPT Sites deployment configuration is active.

## Development and verification

Requires Node 22.13 or later.

```sh
npm ci
npm test
npm run build
node node_modules/typescript/bin/tsc --noEmit
```

For local development, link the intended Vercel project, connect its private Blob store, and pull the development environment with `vercel env pull .env.local` before `npm run dev`. Use a separate development Blob store; do not edit the production vault during testing.

The cryptography test checks Unicode text and completion state, fresh nonces, wrong keys, altered ciphertext, deterministic derivation, and an encrypted empty list. API tests cover public encrypted reads, denied anonymous writes and setup claims, authorized persistence, stale revisions, foreign origins, malformed envelopes, invitation replay, and concurrent initialization and updates across independent server instances. The storage contract tests require private access, uncached reads, and conditional overwrites.

## Deploy to Vercel

1. Import this GitHub repository into your Vercel workspace. Use the Next.js preset and the repository root.
2. Create a **private** Vercel Blob store in `iad1` and connect it to this project. Keep preview/development storage separate from production. Vercel supplies `BLOB_STORE_ID` and OIDC credentials; a private `BLOB_READ_WRITE_TOKEN` can also be used when needed. Never prefix storage credentials with `NEXT_PUBLIC_`.
3. Run `node scripts/create-setup-invitation.mjs https://YOUR-SITE.vercel.app`. It writes the invitation and its digest to an ignored `.veil-private/setup-invitation.json` file, without displaying secret values.
4. Set `VEIL_SETUP_HASH` as a private production environment variable using the file's `setupHash`, then deploy. The real encryption passphrase is never an environment variable.
5. Make the production deployment publicly accessible. Privately open the file's `setupUrl` and choose your actual passphrase in the browser. The setup invitation stops working after initialization.

The private storage URL must never be substituted for `/api/vault`. The public API deliberately omits the write hash and storage metadata.

`.env*`, `.dev.vars*`, `.veil-private/`, local database files, build output, and Vercel link files are ignored. A checkout contains no usable owner key or setup invitation.

## Commit attribution

GitHub associates commits with accounts by their author email, independently of who authenticated the push. Use the account's verified email or its GitHub-provided noreply address from **Settings → Emails**. Configure Git locally in your checkout before committing; do not commit personal credentials or email settings as application secrets. Existing commits retain their original author email.

## License

MIT; see [LICENSE](LICENSE). Vendored starter utilities retain their upstream license notices.