# VEIL

A publicly visible personal to-do list whose meaning stays behind a secret. Anyone can inspect the encrypted list and source code; only someone with the passphrase can decrypt or edit the list.

Live site: https://veil-encrypted-tasks-felim.fmart3.chatgpt.site

## Use it

The owner opens their private, one-time setup invitation and chooses a unique passphrase of at least 16 characters. The key is created in the browser, never by the build process. Add tasks, mark them complete, or delete them after unlocking. Changes are encrypted before they are saved to the shared database. Other visitors see ciphertext. Click **Lock the vault** when finished; it also locks after five minutes without keyboard or pointer activity.

Optional automatic unlock: append `#key=YOUR_URL_ENCODED_KEY` to the site URL. Encode the key with `encodeURIComponent` or `URLSearchParams`. The fragment is consumed and removed on load. It is not sent in the HTTP request, but the full link is a secret: anyone who has it can read and edit the vault. Use the password field on shared devices. Query-string keys such as `?key=` are intentionally unsupported.

**There is no forgotten-key recovery.** Save your passphrase privately. The setup invitation cannot replace or reset an initialized vault.

## Security design

- Browser-native Web Crypto API, with no external cryptography library.
- PBKDF2-SHA-256, 600,000 iterations, and a random 128-bit salt derive 512 bits. The first 256 bits become a non-exportable AES key; the remaining 256 bits become an independent write credential.
- AES-256-GCM encrypts the entire list, including task IDs and completion state. Each save uses a fresh random 96-bit nonce, a 128-bit authentication tag, and a fixed protocol label as authenticated additional data.
- The public endpoint exposes only the versioned encrypted envelope and revision. No secret, encryption key, write credential, or write hash appears in the public response.
- The write endpoint hashes and validates the separate write credential on every mutation. Knowing the public source code does not grant write access.
- A runtime secret stores the SHA-256 hash of a random setup invitation. Initialization atomically inserts the singleton vault; a concurrent or replayed invitation cannot replace it.
- Optimistic concurrency rejects stale saves from another tab. Input limits, JSON validation, prepared SQL statements, origin checks, and non-cacheable API responses limit accidental exposure and unsafe mutations.
- Keys and cleartext live only in page memory. There is no localStorage or sessionStorage copy, analytics, remote font, or third-party script. Locking drops credentials, cleartext tasks, and form drafts. JavaScript garbage collection means this is not a guarantee of physical memory erasure.
- The initial visual preview is genuine AES-GCM ciphertext created with a random, discarded key. It is not the owner's list and has no public unlock passphrase.

Read [SECURITY.md](SECURITY.md) for the trust model and limitations. The algorithms, parameters, salt, and IV are deliberately public. Security relies on a strong secret, not hidden source code.

## Stack

React and TypeScript on Vinext / Vite, a Cloudflare-compatible Worker, and a Cloudflare D1 database. Sites provides the public deployment and persistent database. Production schema is managed through the committed Drizzle migrations.

## Development

Requires Node 22.13 or later.

```sh
npm ci
npm run db:generate # only after a schema change
npm run dev
npm run build
node node_modules/typescript/bin/tsc --noEmit
node --test tests/crypto.test.mjs tests/api.test.mjs
```

For a locally built Worker, initialize its local database separately:

```sh
node node_modules/wrangler/bin/wrangler.js d1 execute site-creator-d1 --local --config dist/server/wrangler.json --file drizzle/0000_gray_madame_masque.sql --persist-to .wrangler/state
```

A fresh deployment must set `VEIL_SETUP_HASH` as a private runtime secret. Generate a random 32-byte invitation, store only its SHA-256 hex digest as this environment value, and privately open `/#setup=INVITATION` to create the list. Never put the invitation or a real passphrase in source, build arguments, fixtures, or committed environment files. The invitation is no longer accepted after initialization.

Local development state and production state are separate. `.dev.vars`, `.env*`, local database files, build output, and private owner setup files are ignored. A checkout of this public repository contains no usable owner key or setup invitation.

## Verification

The cryptography test checks round-trip encryption of Unicode task text and status, fresh nonces, rejection of wrong keys and altered ciphertext, deterministic derivation, and an encrypted empty list. Integration verification covers public encrypted reads, denied anonymous writes and setup claims, authorized persistence, stale revisions, cross-origin writes, malformed envelopes, and reuse of a setup invitation.

## License

MIT; see [LICENSE](LICENSE). Vendored starter utilities retain their upstream license notices.

