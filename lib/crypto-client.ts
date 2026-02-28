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

export async function deriveVaultKey(privateKeyB64: string): Promise<CryptoKey> {
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
  privateKeyB64: string
): Promise<{ encryptedVault: string; vaultIV: string }> {
  const aesKey = await deriveVaultKey(privateKeyB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(JSON.stringify(data))
  );
  return {
    encryptedVault: bufToB64(ciphertext),
    vaultIV: bufToB64(iv.buffer as ArrayBuffer),
  };
}

export async function decryptVault(
  encryptedVault: string,
  vaultIV: string,
  privateKeyB64: string
): Promise<VaultData> {
  const aesKey = await deriveVaultKey(privateKeyB64);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(vaultIV) },
    aesKey,
    b64ToBuf(encryptedVault)
  );
  return JSON.parse(new TextDecoder().decode(plaintext)) as VaultData;
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

// ─── SEED-BASED VAULT KEY (for recovery) ─────────────────────────────────────
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