# Security & Cryptography

This document explains every cryptographic decision made in HouseKey Vault — what we use, why we chose it, and what the threat model looks like. Written for developers and security reviewers, not just cryptographers.

---

## Core principle

**The server never holds what it needs to decrypt your vault.**

Even if the database is fully compromised, an attacker finds only ciphertext they cannot open. There is no master password on the server side, no key escrow, and no recovery backdoor. The tradeoff is explicit: if you lose both your key file and your seed phrase, your vault is permanently inaccessible — by design.

---

## Authentication — ECDSA P-256 Challenge-Response

At registration, the browser generates an ECDSA P-256 key pair using the Web Crypto API. The private key is written to a `.hkv` file the user controls (USB drive, cloud folder, phone storage). The public key is sent to the server and stored in plaintext — it is not secret.

Login works as follows:

1. Client requests a one-time nonce tied to the public key hash
2. Browser reads the `.hkv` file, imports the private key, and signs the nonce with ECDSA-SHA256
3. Server verifies the signature against the stored public key
4. On success: session cookie issued, encrypted vault blob returned
5. Nonce is marked `used = true` and expires after 2 minutes regardless

The private key never leaves the browser at any point. The server never sees it, not even in transit.

**Why P-256:** It is the curve used in TLS, banking systems, and government PKI. It has a 30-year security margin, broad hardware support (including secure enclaves), and is natively supported by the Web Crypto API without any third-party library.

**Replay protection:** Every nonce is single-use and short-lived. A stolen nonce from a captured request cannot be replayed — the server will reject it immediately.

**Brute force protection:** Three consecutive failed verification attempts trigger a 5-minute lockout stored in the `lockouts` table. The lockout is enforced server-side, not client-side.

---

## Vault Encryption — AES-256-GCM

All vault data (credentials, metadata, folder structure) is serialized as JSON, encrypted with AES-256-GCM in the browser, and only then sent to the server. The server stores the ciphertext and the IV. It has no mechanism to decrypt either.

AES-256-GCM provides both confidentiality and authenticity — the GCM authentication tag means any tampering with the ciphertext will cause decryption to fail with an explicit error rather than silently returning corrupted data.

**IV rotation:** A fresh random 12-byte IV is generated on every save operation using `crypto.getRandomValues`. Reusing an IV with the same key under AES-GCM is catastrophic (it leaks the XOR of plaintexts), so this is enforced unconditionally.

---

## Vault Key Derivation — HKDF-SHA256

The AES-256-GCM vault key is derived from the private key using HKDF (RFC 5869) rather than a raw hash.

```
IKM  = raw private key bytes (PKCS-8 DER)
salt = SHA-256(publicKeyB64)          — unique per key pair
info = "housekeyvault-vault-v2"       — domain separation label
PRF  = HMAC-SHA256
→ 256-bit AES-GCM key
```

**Why not SHA-256(privateKey)?** The naive approach works but has two weaknesses. First, there is no domain separation — the same private key bytes could theoretically produce the same output in a different context. Second, there is no salt, which means two users with the same private key material (impossible in practice but worth ruling out) would derive the same AES key. HKDF addresses both: the salt is `SHA-256(publicKey)`, which binds the AES key to this specific key pair, and the `info` field ensures the derived key material is scoped exclusively to vault encryption.

**Migration path:** Vaults created before the HKDF upgrade used `SHA-256(privateKey)` directly. On first login, `decryptVault` attempts HKDF first and falls back to the legacy SHA-256 path if it fails. When legacy decryption succeeds, the vault is immediately re-encrypted with the HKDF key and saved — the user sees "Upgrading vault encryption…" for under a second. After that, the legacy path is never used again for that vault.

---

## Recovery — PBKDF2 with 200,000 Iterations

At registration, a 12-word seed phrase is generated using `crypto.getRandomValues` mapped to a BIP39-style word list. It is shown once and never stored anywhere in plaintext.

A second encrypted copy of the vault is derived from this phrase and stored server-side:

```
key = PBKDF2(
  password   = seed phrase (UTF-8, lowercased, trimmed),
  salt       = "housekeyvault-recovery-v1" (static, known),
  iterations = 200,000,
  hash       = SHA-256,
  keylen     = 256 bits
)
→ AES-256-GCM key for the recovery vault copy
```

The server also stores `SHA-256(seed phrase)` to verify the phrase before returning the recovery blob, without ever seeing the phrase itself.

**Why 200,000 iterations:** PBKDF2 is intentionally slow. At 200k iterations on modern hardware, a single guess takes roughly 200ms. An attacker attempting offline brute force against a leaked `seed_hash` would need to find both the hash AND run PBKDF2 for every guess — making exhaustive search of even a weak phrase impractical within any reasonable timeframe.

**Recovery flow:**
1. User enters seed phrase → client computes its SHA-256 hash
2. Server verifies hash match → returns seed-encrypted vault blob
3. Client decrypts locally with PBKDF2-derived key
4. Client generates a brand-new ECDSA key pair
5. Vault re-encrypted with new HKDF key, new public key registered
6. Old public key invalidated — session opens with the new key pair

The old key file is cryptographically dead after recovery.

---

## Secure Sharing — Ephemeral ECDH + AES-256-GCM

Individual credentials can be shared via a one-time link. The protocol ensures the server never sees the decryption key, even though it stores the ciphertext.

```
1. Sender generates two ephemeral P-256 key pairs:
      (senderEph_priv, senderEph_pub)
      (recipientEph_priv, recipientEph_pub)

2. ECDH shared secret:
      sharedSecret = ECDH(senderEph_priv, recipientEph_pub)

3. AES key derived:
      aesKey = HKDF(sharedSecret, salt=random, info="housekeyvault-share-v1")

4. Credential encrypted with aesKey → ciphertext + IV

5. Server receives:  { ciphertext, iv, senderEph_pub }
   URL fragment:     #recipientEph_priv (base64)

6. Recipient's browser:
      sharedSecret = ECDH(recipientEph_priv, senderEph_pub)  — same result
      aesKey       = HKDF(sharedSecret, ...)
      credential   = AES-GCM-Decrypt(ciphertext, aesKey)
```

The URL fragment (the `#...` part) is never included in HTTP requests by the browser. The server physically cannot see `recipientEph_priv`. The ciphertext stored on the server is permanently undecryptable without the fragment.

**One-time enforcement:** On the first GET to `/api/share/[id]`, the server sets `used = true` and returns the ciphertext. Any subsequent request receives HTTP 410 Gone. There is no way to retrieve the ciphertext a second time via the API.

**TTL:** Shares expire after 1, 24, or 168 hours (configurable at creation). Expired rows are rejected server-side regardless of `used` status.

---

## Second Device Lock — PBKDF2 with Shared Salt

High-sensitivity entries can require a second physical device to decrypt. When enabled, two independent unlock paths are created that derive **the same AES key** from **the same salt**:

```
salt          = 32 random bytes (stored in vault entry, not secret)
deviceSecret  = 32 random bytes (stored in .hkv2 file, never leaves second device)
passphrase    = user-memorised string (never stored anywhere)

Path A (file):       PBKDF2(deviceSecret,  salt, 200k, SHA-256) → AES key
Path B (passphrase): PBKDF2(passphrase,    salt, 200k, SHA-256) → AES key
```

Because both paths use the same salt and the same PBKDF2 parameters, they produce identical AES keys when the correct secret is provided. The password is then encrypted with this key and stored in the vault entry alongside the salt and IV.

To view or copy a protected password, the user must either select the `.hkv2` file from the second device or type the emergency passphrase. Neither path contacts the server.

**Threat model:** An attacker with full database access sees: ciphertext, IV, salt. They cannot decrypt without either `deviceSecret` (on the physical second device) or the passphrase (memorised). Loss of both means the password is unrecoverable — this is intentional and disclosed to the user at setup.

The `.hkv2` file is saved using the same 3-tier browser storage system as the main `.hkv` file: `showSaveFilePicker` on Chrome/Edge (user chooses location), blob download on Firefox/Safari/mobile.

---

## Breach Detection — HIBP k-Anonymity

Password breach checking uses the [Have I Been Pwned](https://haveibeenpwned.com) API with k-Anonymity:

```
1. Browser computes SHA-1(password) → 40-char hex hash
2. Only the first 5 chars (the "prefix") are sent to /api/hibp
3. Server proxies the request to api.pwnedpasswords.com/range/{prefix}
4. HIBP returns all hashes starting with that prefix (~500 entries)
5. Browser searches the list for the remaining 35 chars (the "suffix")
6. Match found → password has been breached N times
```

The full hash never leaves the browser. The password itself never leaves the browser. The server proxy adds `Add-Padding: true` to the HIBP request, which pads all responses to a uniform size to prevent traffic analysis based on response length.

**Rate limiting on the proxy:** The `/api/hibp` route enforces a sliding window rate limit to prevent abuse and protect the HIBP quota:
- 30 requests per IP per 60 seconds
- 200 requests globally per 60 seconds
- Responses cached for 1 hour (`Cache-Control: private, max-age=3600`) — repeated checks of the same password prefix are served from the browser cache without hitting HIBP

Responses include `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining` headers.

---

## Session Management

| Property | Value |
|---|---|
| Token generation | `crypto.randomBytes(32)` — Node.js server-side |
| Storage | HttpOnly cookie, not accessible to JavaScript |
| SameSite | Strict — immune to CSRF |
| TTL | 15 minutes from issuance |
| Invalidation | Explicit logout deletes the session row; token cannot be reused |

Sessions are stored in the `sessions` table with an `expires_at` timestamp. The server rejects any token past its expiry regardless of database state.

---

## What the Server Stores

| Field | Secret? | Can decrypt vault? |
|---|---|---|
| `public_key` | No | No |
| `public_key_hash` | No | No |
| `encrypted_vault` | — | Only with private key (in `.hkv`) |
| `vault_iv` | No | No |
| `seed_hash` | No | No |
| `seed_encrypted_vault` | — | Only with seed phrase |
| `seed_vault_iv` | No | No |
| Share `ciphertext` | — | Only with URL fragment (never sent to server) |
| Share `iv` | No | No |
| Share `sender_pub_key` | No | No |

A full database dump is cryptographically useless without the user's `.hkv` file or seed phrase.

---

## Browser Compatibility

All cryptographic operations use the **Web Crypto API** (`window.crypto.subtle`) — no third-party library is involved. Web Crypto runs in a dedicated thread, keys marked `extractable: false` cannot be read back by JavaScript even if the page is compromised, and the API is available in all modern browsers.

The one exception is the TOTP engine (RFC 6238), which uses `crypto.subtle.sign` with HMAC-SHA1 — also native, no library.

---

## Known Limitations & Future Work

**Vault key not memory-safe:** `CryptoKey` objects derived from the private key live in JavaScript memory for the duration of the session. Web Crypto does not expose a zeroing API. Mitigation: the private key string (`privateKeyB64`) should be imported into a non-extractable `CryptoKey` at login and never stored in React state as a raw string. This is a planned improvement.

**No Certificate Pinning:** Browsers do not support cert pinning for arbitrary origins in web apps. This is a fundamental limitation of the platform, not the implementation.

**PBKDF2 vs Argon2:** PBKDF2 is the only memory-hard-adjacent KDF available in Web Crypto. Argon2id would be preferable for the seed phrase and second-device paths (it is resistant to GPU attacks in a way PBKDF2 is not), but it requires a WASM polyfill. This is on the roadmap for a future version.

**Static PBKDF2 salt for recovery:** The salt for the recovery key derivation is the static string `"housekeyvault-recovery-v1"`. A random per-user salt stored server-side would be stronger. The current approach is safe given the strength of a 12-word random phrase but is acknowledged as a hardening opportunity.

---

## Algorithms at a Glance

| Purpose | Algorithm | Standard |
|---|---|---|
| Authentication | ECDSA P-256 | FIPS 186-4 |
| Vault encryption | AES-256-GCM | FIPS 197, SP 800-38D |
| Vault key derivation | HKDF-SHA256 | RFC 5869 |
| Recovery key derivation | PBKDF2-SHA256, 200k iter | RFC 2898 |
| Seed phrase entropy | `crypto.getRandomValues` | W3C Web Crypto |
| Share key agreement | ECDH P-256 + HKDF | RFC 6090, RFC 5869 |
| Second device keys | PBKDF2-SHA256, 200k iter | RFC 2898 |
| TOTP | HMAC-SHA1, RFC 6238 | RFC 6238 |
| Breach check | SHA-1 prefix, k-Anonymity | HIBP API |
| Session tokens | `crypto.randomBytes(32)` | Node.js crypto module |
