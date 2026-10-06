# Security model

VEIL is a cybersecurity portfolio experiment, not an audited vault or password manager.

## What it protects

Task text and completion state are encrypted before the browser sends them to storage. An anonymous visitor, or someone who downloads the public repository, cannot read the plaintext or edit the shared list without obtaining the owner's key or separate write credential. A wrong key or modified ciphertext fails AES-GCM authentication. The server sees a separate write credential over HTTPS; it does not receive the AES key or original passphrase.

## Trust boundaries and limits

The browser and the served JavaScript must be trusted. A compromised device, extension, deployment, hosting account, or modified site can capture a key or plaintext during use. This project does not protect against an actively malicious host, replay of database snapshots by a database administrator, or physical memory inspection. Clearing React state and dropping key references is not secure memory erasure.

The encrypted envelope is public, so attackers can attempt offline guessing. A minimum length is a usability rule, not proof of entropy. Choose a unique passphrase with substantial randomness, such as 5–6 independently selected random words. Anyone given the correct key can both read and edit; there is no read-only secret, second factor, or recovery service.

Ciphertext size, salt, IV, protocol, and revision are public. List length changes and save frequency can be inferred. There is no padding or traffic analysis protection. The platform may retain backups, request metadata, and previous deployment versions. The server validates envelope shape and authorization but cannot verify task content without decrypting it.

The URL fragment is not included in HTTP requests. A full unlock link can nevertheless be exposed through browser history synchronization, copying, bookmarks, extensions, or screenshots. Removing it from the address bar promptly reduces exposure, but does not guarantee removal from every browser history system. Prefer entering the key in the password field.

The setup invitation is a one-time claim capability. Its SHA-256 digest lives in runtime secret configuration; the invitation stays outside the public repository. It cannot overwrite an initialized vault. Keep it private until setup is complete. Losing the real encryption key means losing the readable list; a hosting administrator can erase the database but cannot recover its plaintext.

## Reporting

Open a GitHub issue for a reproducible security concern without including real secrets, decrypted tasks, write credentials, or private setup invitations.

## References

- [Web Cryptography specification](https://www.w3.org/TR/WebCryptoAPI/)
- [MDN Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [MDN URI fragments](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Fragment)
