// lib/usb-storage.ts
// Cross-browser key storage with progressive fallback:
//
//   Tier 1 — File System Access API  (Chrome/Edge 86+ desktop)
//             Writes to a directory the user picks (USB recommended)
//
//   Tier 2 — File download + <input type="file"> picker
//             Works on Firefox, Safari, iOS, Android — user manages the file
//
//   Tier 3 — Encrypted localStorage  (optional "stay logged in" convenience)
//             Private key encrypted with a PIN before storage; never stored raw

const KEY_FILENAME = "housekeyvault.hkv";
const LS_KEY       = "hkv_key_enc";   // localStorage key for Tier 3

export interface KeyFile {
  privateKeyB64:  string;
  publicKeyB64:   string;
  publicKeyHash:  string;
  createdAt:      number;
  version:        number;
}

// ─── CAPABILITY DETECTION ─────────────────────────────────────────────────────

export function isFileSystemAccessSupported(): boolean {
  return typeof window !== "undefined" && "showDirectoryPicker" in window;
}

export function isFileSaveSupported(): boolean {
  // showSaveFilePicker is Tier 1 too, but we use it as a nicer Tier-2 fallback
  return typeof window !== "undefined" && "showSaveFilePicker" in window;
}

// Always true in a browser — Tier 2 just uses download + file input
export function isFallbackSupported(): boolean {
  return typeof window !== "undefined";
}

export type StorageTier = "directory" | "file" | "download";

export function detectTier(): StorageTier {
  if (isFileSystemAccessSupported()) return "directory";
  if (isFileSaveSupported())         return "file";
  return "download";
}

// ─── TIER 1 — FILE SYSTEM ACCESS API (Chrome/Edge) ───────────────────────────

async function pickDirectory(): Promise<FileSystemDirectoryHandle> {
  // @ts-ignore — showDirectoryPicker not in all TS libs
  return window.showDirectoryPicker({ id: "housekeyvault-usb", mode: "readwrite", startIn: "desktop" });
}

async function writeToDirectory(dirHandle: FileSystemDirectoryHandle, keyFile: KeyFile): Promise<void> {
  const fh = await dirHandle.getFileHandle(KEY_FILENAME, { create: true });
  const w  = await fh.createWritable();
  await w.write(JSON.stringify(keyFile, null, 2));
  await w.close();
}

async function readFromDirectory(dirHandle: FileSystemDirectoryHandle): Promise<KeyFile> {
  let fh: FileSystemFileHandle;
  try { fh = await dirHandle.getFileHandle(KEY_FILENAME); }
  catch { throw new Error(`No key file found. Expected: ${KEY_FILENAME}`); }
  const text = await (await fh.getFile()).text();
  return parseKeyFile(text);
}

// ─── TIER 2a — showSaveFilePicker (Chrome/Edge without directory picker) ──────

async function saveWithFilePicker(keyFile: KeyFile): Promise<void> {
  // @ts-ignore
  const fh = await window.showSaveFilePicker({
    suggestedName: KEY_FILENAME,
    types: [{ description: "HouseKey Vault Key", accept: { "application/json": [".hkv"] } }],
  });
  const w = await fh.createWritable();
  await w.write(JSON.stringify(keyFile, null, 2));
  await w.close();
}

// ─── TIER 2b — Download link (Firefox, Safari, iOS, Android) ─────────────────

export function downloadKeyFile(keyFile: KeyFile): void {
  const blob = new Blob([JSON.stringify(keyFile, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = KEY_FILENAME;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// Prompt user to pick their saved .hkv file from any location
export function loadKeyFileFromPicker(): Promise<KeyFile> {
  return new Promise((resolve, reject) => {
    const input    = document.createElement("input");
    input.type     = "file";
    input.accept   = ".hkv,application/json";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return reject(new Error("No file selected."));
      try {
        const text = await file.text();
        resolve(parseKeyFile(text));
      } catch (e) {
        reject(e);
      }
    };
    input.oncancel = () => reject(new Error("File selection cancelled."));
    input.click();
  });
}

// ─── TIER 3 — Encrypted localStorage  ────────────────────────────────────────
// Key is encrypted with AES-256-GCM derived from a PIN via PBKDF2.
// The PIN is never stored — only the ciphertext and salt are.

async function deriveKeyFromPIN(pin: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const pinEnc = new TextEncoder().encode(pin);
  const pinBuf = pinEnc.buffer.slice(pinEnc.byteOffset, pinEnc.byteOffset + pinEnc.byteLength) as ArrayBuffer;
  const base = await crypto.subtle.importKey(
    "raw", pinBuf, { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200_000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function saveKeyToLocalStorage(keyFile: KeyFile, pin: string): Promise<void> {
  const salt = new Uint8Array(crypto.getRandomValues(new Uint8Array(16)).buffer.slice(0,16) as ArrayBuffer);
  const iv   = new Uint8Array(crypto.getRandomValues(new Uint8Array(12)).buffer.slice(0,12) as ArrayBuffer);
  const key  = await deriveKeyFromPIN(pin, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as Uint8Array<ArrayBuffer> },
    key,
    new TextEncoder().encode(JSON.stringify(keyFile))
  );
  const payload = {
    salt: bufToB64(salt.buffer as ArrayBuffer),
    iv:   bufToB64(iv.buffer as ArrayBuffer),
    data: bufToB64(ciphertext),
  };
  localStorage.setItem(LS_KEY, JSON.stringify(payload));
}

export async function loadKeyFromLocalStorage(pin: string): Promise<KeyFile> {
  const raw = localStorage.getItem(LS_KEY);
  if (!raw) throw new Error("No saved key found on this device.");
  const { salt, iv, data } = JSON.parse(raw);
  const key = await deriveKeyFromPIN(pin, new Uint8Array(b64ToBuf(salt) as ArrayBuffer) as Uint8Array<ArrayBuffer>);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b64ToBuf(iv) as ArrayBuffer) as Uint8Array<ArrayBuffer> },
      key,
      b64ToBuf(data)
    );
    return parseKeyFile(new TextDecoder().decode(plaintext));
  } catch {
    throw new Error("Wrong PIN or corrupted key.");
  }
}

export function hasLocalStorageKey(): boolean {
  return typeof window !== "undefined" && !!localStorage.getItem(LS_KEY);
}

export function clearLocalStorageKey(): void {
  localStorage.removeItem(LS_KEY);
}

// ─── SHARED HELPERS ───────────────────────────────────────────────────────────

function parseKeyFile(text: string): KeyFile {
  let kf: KeyFile;
  try { kf = JSON.parse(text); } catch { throw new Error("Key file is corrupted or invalid."); }
  if (!kf.privateKeyB64 || !kf.publicKeyB64) throw new Error("Invalid key file format.");
  return kf;
}

function bufToB64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b64ToBuf(b64: string): ArrayBuffer {
  const binary = atob(b64);
  const buf    = new ArrayBuffer(binary.length);
  const view   = new Uint8Array(buf);
  for (let i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i);
  return buf;
}

// ─── HIGH-LEVEL API (used by page.tsx) ───────────────────────────────────────
// These replace the old setupUSBKey / loadUSBKey functions.
// They detect the browser tier and do the right thing automatically.

/**
 * Save the key file after account creation.
 * Returns the tier that was used so the UI can show appropriate instructions.
 */
export async function setupUSBKey(keyFile: KeyFile): Promise<StorageTier> {
  const tier = detectTier();

  if (tier === "directory") {
    // @ts-ignore
    const dirHandle = await window.showDirectoryPicker({
      id: "housekeyvault-usb", mode: "readwrite", startIn: "desktop",
    });
    // Check for existing key
    try {
      await dirHandle.getFileHandle(KEY_FILENAME);
      throw new Error(
        "A key file already exists in that location. " +
        "Use a different folder or delete the existing housekeyvault.hkv file."
      );
    } catch (e: any) {
      if (e.name !== "NotFoundError") throw e;
    }
    await writeToDirectory(dirHandle, keyFile);
    return "directory";
  }

  if (tier === "file") {
    await saveWithFilePicker(keyFile);
    return "file";
  }

  // Tier 2b — download
  downloadKeyFile(keyFile);
  return "download";
}

/**
 * Load the key file during login.
 * Returns the KeyFile — throws if not found or wrong PIN.
 */
export async function loadUSBKey(): Promise<KeyFile> {
  const tier = detectTier();

  if (tier === "directory") {
    // @ts-ignore
    const dirHandle = await window.showDirectoryPicker({
      id: "housekeyvault-usb", mode: "readwrite", startIn: "desktop",
    });
    return readFromDirectory(dirHandle);
  }

  // Tier 2 (file picker) and Tier 2b (download) both load via <input type="file">
  return loadKeyFileFromPicker();
}