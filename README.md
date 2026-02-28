# HouseKey Vault

**HackUDC 2026**

A zero-knowledge password manager where authentication is performed entirely through a cryptographic key pair stored on a physical file — no master password, no shared secret, no trust in the server.

---

## The Problem

Every major password manager today requires you to trust a third party with either your master password or a derived secret. If their servers are compromised, your vault is at risk. If you forget your master password, you are locked out.

HouseKey Vault eliminates both problems: the server never sees your private key or your plaintext vault, and recovery is handled through a seed phrase you control.

---

## How It Works

### Authentication

HouseKey Vault uses ECDSA P-256 challenge-response authentication. At registration, the browser generates a key pair via the Web Crypto API. The private key is written to a `.hkv` file on a location the user controls — a USB drive, phone storage, or cloud-synced folder. The public key is sent to the server.

At login, the browser reads the `.hkv` file, requests a one-time nonce from the server, signs it with the private key, and sends the signature back. The server verifies the signature against the stored public key. If valid, it returns the encrypted vault blob and sets a 15-minute session cookie. The private key never leaves the client at any point.

### Vault Encryption

The vault is encrypted with AES-256-GCM. The encryption key is derived from the private key using SHA-256 as a key derivation step, meaning the server cannot decrypt the vault even if its database is fully compromised.

### Recovery

During account creation, a 12-word BIP39-style seed phrase is generated and shown once. A second copy of the vault is simultaneously encrypted using a key derived from this seed phrase via PBKDF2 (200,000 iterations, SHA-256) and stored server-side alongside the SHA-256 hash of the seed.

If the key file is lost, the user enters the seed phrase in the recovery screen. The client verifies the seed against its hash, decrypts the seed-encrypted vault, generates a brand-new key pair, re-encrypts the vault with the new key, and updates the server record — all in one authenticated round trip that also establishes a new session. The old key is invalidated.

### Breach Detection

Passwords are checked against the Have I Been Pwned database using k-Anonymity: only the first 5 characters of the SHA-1 hash of the password are sent to the HIBP API. The full hash never leaves the client.

### TOTP / 2FA

TOTP codes are generated client-side using a pure Web Crypto implementation of RFC 6238 (HMAC-SHA-1). The TOTP secret is stored encrypted inside the vault blob, never transmitted in plaintext. Codes are displayed inline on each entry with a live countdown ring.

### Secure Credential Sharing

Individual credentials can be shared via a one-time link using ephemeral ECDH key exchange. When a share is created, two ephemeral P-256 key pairs are generated in the browser. A shared AES-256-GCM key is derived from the ECDH exchange and used to encrypt the credential. The server stores only the ciphertext and the sender's ephemeral public key. The recipient's ephemeral private key is embedded in the URL fragment (`#key=…`), which the browser never includes in HTTP requests — making the decryption key invisible to the server at all times.

On first access, the server marks the share as used and returns the ciphertext. The recipient's browser derives the same AES key from the ECDH exchange and decrypts locally. A second access returns HTTP 410. The server cannot decrypt the share even if the database is fully compromised.

### Second Device Lock

High-sensitivity entries (bank accounts, crypto wallets) can be protected with a second factor that requires a physically separate device. When enabled, a random 32-byte salt and a random 32-byte `deviceSecret` are generated in the browser. Both the `.hkv2` key file and an emergency passphrase derive the **same** AES-256-GCM key via PBKDF2(secret, salt, 200,000, SHA-256) — so the user has two independent paths to decrypt without any server involvement.

The `.hkv2` file is saved to a location the user controls (using the same 3-tier browser storage system as the main `.hkv` file). The salt is stored in the vault entry. The emergency passphrase is never stored anywhere. To view or copy a second-device-protected password, the user must either select the `.hkv2` file from the second device or type the emergency passphrase — neither path touches the server.

### Import / Export

The vault supports importing credentials from Bitwarden CSV, Bitwarden JSON, 1Password CSV, and LastPass CSV. The format is detected automatically from the file headers. Exports are available as Bitwarden JSON (recommended, compatible with most managers), Bitwarden CSV (universal), or HouseKey native JSON (full fidelity backup including folders, breach status, TOTP secrets, and timestamps). All import and export processing happens entirely in the browser.

---

## Security Model

| Property | Implementation |
|---|---|
| Authentication | ECDSA P-256 challenge-response |
| Vault encryption | AES-256-GCM |
| Vault key derivation | SHA-256 from private key |
| Recovery key derivation | PBKDF2, 200,000 iterations, SHA-256 |
| Second device key derivation | PBKDF2, 200,000 iterations, SHA-256 (shared salt for file + passphrase paths) |
| Credential sharing | Ephemeral ECDH P-256 + AES-256-GCM, key in URL fragment only |
| Server storage | Public key + encrypted blob only |
| Private key location | User-controlled file, never transmitted |
| Session | HttpOnly cookie, SameSite Strict, 15-min TTL |
| Challenge replay protection | Nonces marked used on first verification, 2-min TTL |
| Brute force protection | 3 failed attempts triggers 5-minute lockout |
| Breach check | HIBP k-Anonymity, SHA-1 prefix only |
| TOTP | RFC 6238, computed entirely in the browser |
| Share links | One-time use, server marks consumed on first GET, HTTP 410 on reuse |

The server stores three things per user: the public key, the primary encrypted vault (decryptable only with the private key file), and the recovery vault (decryptable only with the seed phrase). Neither alone is sufficient to access the vault contents. Share ciphertext stored server-side is permanently undecryptable without the URL fragment the server never receives.

---

## Browser Compatibility

Key file storage adapts automatically to the browser in use. The same logic applies to `.hkv2` second device files.

| Tier | Browsers | Mechanism |
|---|---|---|
| 1 | Chrome 86+, Edge 86+ | `showDirectoryPicker()` — writes directly to a selected folder |
| 2 | Chrome/Edge (no directory) | `showSaveFilePicker()` — saves to a user-chosen location |
| 3 | Firefox, Safari, iOS, Android | Automatic download of `.hkv` / `.hkv2` file, loaded via `<input type="file">` at login |

All tiers produce the same key file format and use identical cryptographic primitives. There is no functionality difference — only the file management experience differs.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Next.js 15 (App Router, Turbopack) |
| Language | TypeScript |
| Cryptography (client) | Web Crypto API — no external crypto library |
| Cryptography (server) | Node.js `crypto` module |
| Database | Supabase (PostgreSQL) |
| Validation | Zod |
| Deployment | Vercel |

---

## Project Structure

```
housekeyvault/
├── app/
│   ├── page.tsx                    # Single-page client application
│   ├── share/
│   │   └── [id]/page.tsx           # Public share recipient page (zero auth)
│   └── api/
│       ├── auth/
│       │   ├── register/route.ts   # Store public key, encrypted vault, seed hash
│       │   ├── challenge/route.ts  # Issue one-time nonce
│       │   ├── verify/route.ts     # Verify ECDSA signature, open session
│       │   ├── recover/route.ts    # Seed-phrase recovery, re-key vault
│       │   └── logout/route.ts     # Invalidate session
│       ├── vault/
│       │   └── save/route.ts       # Persist updated encrypted vault blob
│       ├── share/
│       │   └── route.ts            # POST create share, GET retrieve (one-time)
│       └── hibp/route.ts           # k-Anonymity proxy for HIBP API
└── lib/
    ├── crypto-client.ts            # Web Crypto: keygen, sign, AES-GCM, PBKDF2
    ├── crypto-server.ts            # Node crypto: ECDSA verify, session tokens
    ├── usb-storage.ts              # Cross-browser key file storage (3-tier fallback)
    ├── share-crypto.ts             # Ephemeral ECDH share creation (client-side)
    ├── import-export.ts            # Bitwarden / 1Password / LastPass import & export
    ├── api-client.ts               # Typed fetch wrappers
    └── supabase-server.ts          # Supabase admin client
```

---

## Database Schema

```sql
create table users (
  id                   text primary key default gen_random_uuid()::text,
  public_key           text not null,
  public_key_hash      text unique not null,
  encrypted_vault      text not null,
  vault_iv             text not null,
  seed_hash            text unique not null,
  seed_encrypted_vault text not null,
  seed_vault_iv        text not null,
  created_at           timestamptz default now()
);

create table challenges (
  id             uuid primary key default gen_random_uuid(),
  nonce          text unique not null,
  pub_key_hash   text not null,
  used           boolean default false,
  expires_at     timestamptz not null,
  created_at     timestamptz default now()
);

create table sessions (
  id         uuid primary key default gen_random_uuid(),
  user_id    text references users(id) on delete cascade,
  token      text unique not null,
  expires_at timestamptz not null,
  created_at timestamptz default now()
);

create table lockouts (
  user_id      text primary key references users(id) on delete cascade,
  fail_count   int default 0,
  locked_until timestamptz,
  last_attempt timestamptz
);

create table shares (
  id             text primary key default gen_random_uuid()::text,
  ciphertext     text not null,
  iv             text not null,
  sender_pub_key text not null,
  expires_at     timestamptz not null,
  used           boolean default false,
  created_by     text,
  created_at     timestamptz default now()
);

create index shares_expires_idx on shares (expires_at);
```

---

## Local Development

**Prerequisites:** Node.js 18+, a Supabase project.

```bash
git clone https://github.com/BreaGG/HackUDC2026---HouseKey-Vault
cd housekeyvault
npm install
```

Create `.env.local`:

```env
NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
```

Run the SQL schema above in the Supabase SQL Editor, then:

```bash
npm run dev
```

Open `http://localhost:3000`.

---

## Team

Built at HackUDC 2026, Universidade da Coruña.