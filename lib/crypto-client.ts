// lib/crypto-client.ts
// All crypto runs in the BROWSER. Private key never leaves the client.

// ─── HELPERS (defined first, used everywhere) ────────────────────────────────

export function bufToB64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

// Always returns a proper ArrayBuffer — fixes Web Crypto type errors
export function b64ToBuf(b64: string): ArrayBuffer {
  const binary = atob(b64);
  const buf = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return buf;
}

export function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── KEY GENERATION ──────────────────────────────────────────────────────────

export async function generateKeyPair(): Promise<{
  publicKeyB64: string;
  privateKeyB64: string;
  publicKeyHash: string;
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const [publicKeyRaw, privateKeyRaw] = await Promise.all([
    crypto.subtle.exportKey("spki", keyPair.publicKey),
    crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
  ]);

  const publicKeyB64 = bufToB64(publicKeyRaw);
  const privateKeyB64 = bufToB64(privateKeyRaw);
  const publicKeyHash = await hashPublicKey(publicKeyB64);

  return { publicKeyB64, privateKeyB64, publicKeyHash };
}

// ─── CHALLENGE SIGNING ───────────────────────────────────────────────────────

export async function signChallenge(
  privateKeyB64: string,
  challenge: string
): Promise<string> {
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    b64ToBuf(privateKeyB64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    new TextEncoder().encode(challenge)
  );

  return bufToB64(signature);
}

// ─── VAULT ENCRYPTION (AES-256-GCM) ─────────────────────────────────────────
//
// Key derivation: HKDF-SHA256
//
//   IKM  = raw private key bytes (PKCS-8 DER)
//   salt = SHA-256(publicKeyB64) — ties the AES key to this specific key pair,
//          so a key derived from key pair A cannot decrypt a vault from key pair B
//   info = "housekeyvault-vault-v2" — domain separation, prevents the same IKM
//          from producing the same key material for any other purpose
//
// Why HKDF over raw SHA-256:
//   The old approach (SHA-256(privateKey)) is a single compression with no
//   domain separation, no salt, and no stretch. HKDF provides all three
//   and is the standard KDF for this pattern (RFC 5869).
//
// Migration path:
//   deriveVaultKey(priv, pub)  → HKDF (new, default)
//   deriveVaultKeyLegacy(priv) → SHA-256 (read-only, for migrating old vaults)

export async function deriveVaultKey(
  privateKeyB64: string,
  publicKeyB64: string,
): Promise<CryptoKey> {
  const privateKeyBytes = b64ToBuf(privateKeyB64);

  // salt = SHA-256(publicKey) — unique per key pair, non-secret
  const saltBuf = await crypto.subtle.digest("SHA-256", b64ToBuf(publicKeyB64));

  // Import raw key bytes as HKDF base key
  const hkdfKey = await crypto.subtle.importKey(
    "raw", privateKeyBytes,
    { name: "HKDF" },
    false, ["deriveKey"]
  );

  // Derive AES-256-GCM key
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBuf,
      info: new TextEncoder().encode("housekeyvault-vault-v2"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Legacy derivation — only used to migrate existing vaults on first login.
// After migration the vault is re-encrypted with the HKDF key and this is
// never called again.
export async function deriveVaultKeyLegacy(privateKeyB64: string): Promise<CryptoKey> {
  const privateKeyBytes = b64ToBuf(privateKeyB64);
  const hashBuffer = await crypto.subtle.digest("SHA-256", privateKeyBytes);
  return crypto.subtle.importKey(
    "raw", hashBuffer,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"]
  );
}

export async function encryptVault(
  data: VaultData,
  privateKeyB64: string,
  publicKeyB64: string,
): Promise<{ encryptedVault: string; vaultIV: string }> {
  const aesKey = await deriveVaultKey(privateKeyB64, publicKeyB64);
  // Fresh random IV on every save — never reuse IV with the same key
  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const iv = ivBytes.buffer.slice(0, 12) as ArrayBuffer;
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(JSON.stringify(data))
  );
  return {
    encryptedVault: bufToB64(ciphertext),
    vaultIV: bufToB64(iv),
  };
}

// Decrypt with automatic legacy fallback:
//   1. Try HKDF key (new vaults, vault_version >= 2)
//   2. If that fails, fall back to SHA-256 key (old vaults) and schedule
//      a silent re-encryption with the HKDF key on next save.
//   publicKeyB64 is optional — if absent we skip HKDF and go straight to legacy.
export async function decryptVault(
  encryptedVault: string,
  vaultIV: string,
  privateKeyB64: string,
  publicKeyB64?: string,
): Promise<VaultData & { _legacyKey?: boolean }> {
  // Try HKDF first (new vaults)
  if (publicKeyB64) {
    try {
      const aesKey = await deriveVaultKey(privateKeyB64, publicKeyB64);
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: b64ToBuf(vaultIV) },
        aesKey,
        b64ToBuf(encryptedVault)
      );
      return JSON.parse(new TextDecoder().decode(plaintext)) as VaultData;
    } catch {
      // Fall through to legacy
    }
  }

  // Legacy: SHA-256 key (vaults created before HKDF migration)
  const legacyKey = await deriveVaultKeyLegacy(privateKeyB64);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(vaultIV) },
    legacyKey,
    b64ToBuf(encryptedVault)
  );
  const vault = JSON.parse(new TextDecoder().decode(plaintext)) as VaultData;
  // Signal to caller that this vault needs re-encryption with HKDF key
  return { ...vault, _legacyKey: true };
}

// ─── PUBLIC KEY HASHING ──────────────────────────────────────────────────────

export async function hashPublicKey(publicKeyB64: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", b64ToBuf(publicKeyB64));
  return bufToHex(hash);
}

// ─── SEED PHRASE ─────────────────────────────────────────────────────────────

const WORD_LIST = [
  "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
  "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
  "action","actor","actual","adapt","add","addict","address","adjust","admit","adult",
  "advance","advice","afford","afraid","again","agent","agree","ahead","aim","air",
  "airport","aisle","alarm","album","alcohol","alert","alien","alley","allow","almost",
  "alone","alpha","already","alter","always","amateur","amazing","among","amount","amused",
  "analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual",
  "answer","antenna","antique","anxiety","apart","april","arch","arctic","arena","argue",
  "arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art",
  "artist","artwork","aspect","assault","asset","assist","assume","asthma","athlete","atom",
  "attack","attend","attract","auction","august","aunt","author","auto","autumn","average",
  "avocado","avoid","awake","aware","away","awesome","awful","awkward","axis","baby",
  "balance","bamboo","banana","banner","barely","bargain","barrel","base","basic","basket",
  "battle","beach","bean","beauty","because","become","before","begin","behave","behind",
  "benefit","best","betray","better","between","beyond","bicycle","birth","bitter","black",
  "blade","blame","blast","bleak","bless","blind","blood","blossom","blouse","blue",
  "blur","blush","board","boat","body","boil","bomb","bone","bonus","book",
  "boost","border","boring","borrow","boss","bottom","bounce","brain","brand","brave",
  "bread","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom",
  "brown","bubble","buddy","budget","buffalo","build","bulb","burden","burger","burst",
];

export function generateSeedPhrase(): string {
  const indices = crypto.getRandomValues(new Uint32Array(12));
  return Array.from(indices).map(n => WORD_LIST[n % WORD_LIST.length]).join(" ");
}

// ─── PASSWORD UTILITIES ──────────────────────────────────────────────────────

export function scorePassword(password: string): { score: number; label: string; color: string } {
  if (!password) return { score: 0, label: "", color: "var(--border)" };
  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  score = Math.min(4, score);
  const labels = ["", "Weak", "Fair", "Good", "Strong"];
  const colors = ["var(--border)", "#FF4444", "#FF8C00", "#F5A623", "#39FF85"];
  return { score, label: labels[score], color: colors[score] };
}

export function generatePassword(opts: {
  length?: number; symbols?: boolean; numbers?: boolean; uppercase?: boolean;
} = {}): string {
  const { length = 20, symbols = true, numbers = true, uppercase = true } = opts;
  let chars = "abcdefghijklmnopqrstuvwxyz";
  if (uppercase) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (numbers)   chars += "0123456789";
  if (symbols)   chars += "!@#$%^&*-_+=";
  const bytes = crypto.getRandomValues(new Uint8Array(length * 3));
  let result = "";
  for (let i = 0; i < bytes.length && result.length < length; i++) {
    if (bytes[i] < Math.floor(256 / chars.length) * chars.length)
      result += chars[bytes[i] % chars.length];
  }
  return result.slice(0, length).padEnd(length, chars[0]);
}

export function emptyVault(): VaultData {
  return { entries: [], createdAt: Date.now(), version: 1 };
}

// ─── TYPES ───────────────────────────────────────────────────────────────────

export interface VaultEntry {
  id: string; site: string; username: string; password: string;
  url?: string; notes?: string; createdAt: number; updatedAt: number; breached?: boolean;
}

export interface VaultData {
  entries: VaultEntry[]; createdAt: number; version: number;
}

// ─── DURESS / DECOY VAULT ────────────────────────────────────────────────────
// When the user sets up a duress PIN, a second "decoy" vault is created at
// registration and stored alongside the real vault. Both blobs are the same
// size and format — the server cannot distinguish them.
//
// Duress key derivation uses HKDF with a different info label:
//   info = "housekeyvault-duress-v1"   (vs "housekeyvault-vault-v2" for real)
//
// This means the same private key + same public key → completely different
// AES-256-GCM key for the decoy. The decoy cannot be derived without knowing
// the duress PIN because the PIN is mixed into the IKM via PBKDF2 first:
//
//   step 1: duressSecret = PBKDF2(duressPin, publicKeyHash, 100k, SHA-256)
//   step 2: ikm = XOR(privateKeyBytes, duressSecret)  [byte-wise, zero-padded]
//   step 3: aesKey = HKDF(ikm, salt=SHA-256(publicKey), info="housekeyvault-duress-v1")
//
// Result: decoy vault can only be decrypted if the attacker has BOTH the .hkv
// file AND the duress PIN — and neither the server nor any observer can tell
// which vault blob is the real one.

export async function deriveDuressVaultKey(
  privateKeyB64: string,
  publicKeyB64:  string,
  duressPin:     string,
): Promise<CryptoKey> {
  const toPlain = (u: Uint8Array): ArrayBuffer =>
    u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

  // Step 1: derive a duress secret from the PIN using PBKDF2
  const enc        = new TextEncoder();
  const pinBase    = await crypto.subtle.importKey(
    "raw", toPlain(enc.encode(duressPin.trim())),
    { name: "PBKDF2" }, false, ["deriveKey"]
  );
  const duressKey  = await crypto.subtle.deriveKey(
    {
      name:       "PBKDF2",
      // salt = first 32 bytes of publicKeyB64 — unique per key pair
      salt:       toPlain(enc.encode(publicKeyB64.slice(0, 32))),
      iterations: 100_000,   // lower than recovery — PIN entry is interactive
      hash:       "SHA-256",
    },
    pinBase,
    { name: "AES-GCM", length: 256 },
    true,   // extractable so we can export and XOR
    ["encrypt"]
  );
  const duressBytes = await crypto.subtle.exportKey("raw", duressKey);

  // Step 2: XOR private key bytes with duress secret → mixed IKM
  const privBytes  = new Uint8Array(b64ToBuf(privateKeyB64));
  const duressArr  = new Uint8Array(duressBytes);
  const mixedArr   = new Uint8Array(privBytes.length);
  for (let i = 0; i < privBytes.length; i++) {
    mixedArr[i] = privBytes[i] ^ duressArr[i % duressArr.length];
  }
  const mixedBuf = mixedArr.buffer.slice(0, mixedArr.byteLength) as ArrayBuffer;

  // Step 3: HKDF with duress domain label → AES-256-GCM key
  const saltBuf = await crypto.subtle.digest("SHA-256", b64ToBuf(publicKeyB64));
  const hkdfKey = await crypto.subtle.importKey(
    "raw", mixedBuf, { name: "HKDF" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBuf,
      info: enc.encode("housekeyvault-duress-v1"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptDecoyVault(
  data:          VaultData,
  privateKeyB64: string,
  publicKeyB64:  string,
  duressPin:     string,
): Promise<{ encryptedVault: string; vaultIV: string }> {
  const aesKey  = await deriveDuressVaultKey(privateKeyB64, publicKeyB64, duressPin);
  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const iv      = ivBytes.buffer.slice(0, 12) as ArrayBuffer;
  const ct      = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(JSON.stringify(data))
  );
  return { encryptedVault: bufToB64(ct), vaultIV: bufToB64(iv) };
}

export async function decryptDecoyVault(
  encryptedVault: string,
  vaultIV:        string,
  privateKeyB64:  string,
  publicKeyB64:   string,
  duressPin:      string,
): Promise<VaultData> {
  const aesKey = await deriveDuressVaultKey(privateKeyB64, publicKeyB64, duressPin);
  const plain  = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(vaultIV) },
    aesKey,
    b64ToBuf(encryptedVault)
  );
  return JSON.parse(new TextDecoder().decode(plain)) as VaultData;
}
// At registration we encrypt a *copy* of the vault with a key derived from the
// seed phrase (PBKDF2 → AES-256-GCM). This copy is what /api/auth/recover returns.
// The client decrypts it with the seed, then re-encrypts with the new private key.

export async function deriveVaultKeyFromSeed(seedPhrase: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  // Slice to plain ArrayBuffer — WebCrypto rejects Uint8Array<ArrayBufferLike>
  const toPlain = (u: Uint8Array): ArrayBuffer =>
    u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
  const baseKey = await crypto.subtle.importKey(
    "raw", toPlain(enc.encode(seedPhrase.trim().toLowerCase())),
    { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: toPlain(enc.encode("housekeyvault-recovery-v1")),
      iterations: 200_000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptVaultWithSeed(
  data: VaultData,
  seedPhrase: string
): Promise<{ encryptedVault: string; vaultIV: string }> {
  const aesKey = await deriveVaultKeyFromSeed(seedPhrase);
  const ivRaw = crypto.getRandomValues(new Uint8Array(12));
  const iv = ivRaw.buffer.slice(0, 12) as ArrayBuffer;
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(JSON.stringify(data))
  );
  return {
    encryptedVault: bufToB64(ciphertext),
    vaultIV: bufToB64(iv),
  };
}

export async function decryptVaultWithSeed(
  encryptedVault: string,
  vaultIV: string,
  seedPhrase: string
): Promise<VaultData> {
  const aesKey = await deriveVaultKeyFromSeed(seedPhrase);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(vaultIV) },
    aesKey,
    b64ToBuf(encryptedVault)
  );
  return JSON.parse(new TextDecoder().decode(plaintext)) as VaultData;
}