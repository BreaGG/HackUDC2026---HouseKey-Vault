// lib/import-export.ts
// Import from: Bitwarden CSV, Bitwarden JSON, 1Password CSV, LastPass CSV
// Export to:   Bitwarden CSV, Bitwarden JSON, HouseKey JSON (native)
//
// All processing happens entirely in the browser — no file ever touches the server.

import type { VaultEntry } from "@/lib/crypto-client";

// ─── TYPES ───────────────────────────────────────────────────────────────────

export type ImportSource = "bitwarden-csv" | "bitwarden-json" | "1password-csv" | "lastpass-csv";
export type ExportFormat = "bitwarden-csv" | "bitwarden-json" | "housekeyvault-json";

export interface ImportResult {
  entries:   Omit<VaultEntry, "id" | "createdAt" | "updatedAt">[];
  skipped:   number;
  source:    ImportSource;
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function parseCSV(text: string): Record<string, string>[] {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];

  // Parse header — handle quoted fields
  const parseRow = (line: string): string[] => {
    const result: string[] = [];
    let current = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
        else inQuotes = !inQuotes;
      } else if (ch === "," && !inQuotes) {
        result.push(current); current = "";
      } else {
        current += ch;
      }
    }
    result.push(current);
    return result;
  };

  const headers = parseRow(lines[0]).map(h => h.trim().toLowerCase());
  const rows: Record<string, string>[] = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const vals = parseRow(lines[i]);
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => { row[h] = (vals[idx] ?? "").trim(); });
    rows.push(row);
  }
  return rows;
}

function extractTOTPSecret(totp: string): string {
  if (!totp) return "";
  // otpauth://totp/...?secret=XXX&... → extract secret
  try {
    const url = new URL(totp);
    return url.searchParams.get("secret") ?? totp;
  } catch {
    // Already a raw secret
    return totp;
  }
}

function csvEscape(val: string): string {
  if (val.includes(",") || val.includes('"') || val.includes("\n")) {
    return `"${val.replace(/"/g, '""')}"`;
  }
  return val;
}

function downloadText(content: string, filename: string, mime = "text/plain"): void {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// ─── IMPORT: BITWARDEN CSV ────────────────────────────────────────────────────
// Header: folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp

export function importBitwardenCSV(text: string): ImportResult {
  const rows   = parseCSV(text);
  const entries: ImportResult["entries"] = [];
  let skipped  = 0;

  for (const row of rows) {
    if (row["type"] !== "login") { skipped++; continue; }
    const site     = row["name"] || row["login_uri"] || "";
    const username = row["login_username"] || "";
    const password = row["login_password"] || "";
    if (!site || !password) { skipped++; continue; }

    entries.push({
      site,
      username,
      password,
      url:         row["login_uri"]   || "",
      notes:       row["notes"]       || "",
      totpSecret:  extractTOTPSecret(row["login_totp"] || ""),
      folderId:    "",
      breached:    undefined,
    } as any);
  }

  return { entries, skipped, source: "bitwarden-csv" };
}

// ─── IMPORT: BITWARDEN JSON ───────────────────────────────────────────────────

export function importBitwardenJSON(text: string): ImportResult {
  const entries: ImportResult["entries"] = [];
  let skipped = 0;

  let data: any;
  try { data = JSON.parse(text); } catch { throw new Error("Invalid JSON file."); }

  const items: any[] = data.items ?? data;
  if (!Array.isArray(items)) throw new Error("Unrecognised Bitwarden JSON format.");

  for (const item of items) {
    if (item.type !== 1 || !item.login) { skipped++; continue; } // type 1 = login
    const login    = item.login;
    const site     = item.name || (login.uris?.[0]?.uri ?? "");
    const username = login.username || "";
    const password = login.password || "";
    if (!site || !password) { skipped++; continue; }

    const totp = login.totp ? extractTOTPSecret(login.totp) : "";

    entries.push({
      site,
      username,
      password,
      url:        login.uris?.[0]?.uri ?? "",
      notes:      item.notes || "",
      totpSecret: totp,
      folderId:   "",
      breached:   undefined,
    } as any);
  }

  return { entries, skipped, source: "bitwarden-json" };
}

// ─── IMPORT: 1PASSWORD CSV ────────────────────────────────────────────────────
// Header varies by version; common: Title,Username,Password,URL,Notes,OTPAuth

export function import1PasswordCSV(text: string): ImportResult {
  const rows   = parseCSV(text);
  const entries: ImportResult["entries"] = [];
  let skipped  = 0;

  for (const row of rows) {
    // 1Password uses different header names depending on export version
    const site     = row["title"] || row["name"] || row["website"] || "";
    const username = row["username"] || row["email"] || "";
    const password = row["password"] || "";
    const url      = row["url"] || row["website"] || "";
    const notes    = row["notes"] || row["memo"] || "";
    const totp     = row["otpauth"] || row["one-time password"] || row["totp"] || "";

    if (!site || !password) { skipped++; continue; }

    entries.push({
      site,
      username,
      password,
      url,
      notes,
      totpSecret: extractTOTPSecret(totp),
      folderId:   "",
      breached:   undefined,
    } as any);
  }

  return { entries, skipped, source: "1password-csv" };
}

// ─── IMPORT: LASTPASS CSV ─────────────────────────────────────────────────────
// Header: url,username,password,totp,extra,name,grouping,fav

export function importLastPassCSV(text: string): ImportResult {
  const rows   = parseCSV(text);
  const entries: ImportResult["entries"] = [];
  let skipped  = 0;

  for (const row of rows) {
    const site     = row["name"] || row["url"] || "";
    const username = row["username"] || "";
    const password = row["password"] || "";
    const url      = row["url"] || "";
    const notes    = row["extra"] || row["note"] || "";
    const totp     = row["totp"] || "";

    if (!site || !password) { skipped++; continue; }

    entries.push({
      site,
      username,
      password,
      url,
      notes,
      totpSecret: extractTOTPSecret(totp),
      folderId:   "",
      breached:   undefined,
    } as any);
  }

  return { entries, skipped, source: "lastpass-csv" };
}

// ─── AUTO-DETECT FORMAT ───────────────────────────────────────────────────────

export function detectImportFormat(text: string, filename: string): ImportSource {
  const lower = filename.toLowerCase();
  const first = text.slice(0, 500).toLowerCase();

  if (lower.endsWith(".json")) {
    // Bitwarden JSON has "items" array with "type" numbers
    if (first.includes('"items"') || first.includes('"type":')) return "bitwarden-json";
  }

  // CSV detection by header
  const firstLine = text.split(/\r?\n/)[0].toLowerCase();
  if (firstLine.includes("login_username") || firstLine.includes("login_password")) return "bitwarden-csv";
  if (firstLine.includes("grouping") || firstLine.includes("extra")) return "lastpass-csv";
  if (firstLine.includes("otpauth") || firstLine.includes("one-time password")) return "1password-csv";

  // Fallback: try Bitwarden CSV (most common)
  return "bitwarden-csv";
}

export function importAuto(text: string, filename: string): ImportResult {
  const fmt = detectImportFormat(text, filename);
  switch (fmt) {
    case "bitwarden-json": return importBitwardenJSON(text);
    case "bitwarden-csv":  return importBitwardenCSV(text);
    case "1password-csv":  return import1PasswordCSV(text);
    case "lastpass-csv":   return importLastPassCSV(text);
  }
}

// ─── EXPORT: BITWARDEN CSV ────────────────────────────────────────────────────

export function exportBitwardenCSV(entries: VaultEntry[], publicKeyHash = ""): void {
  const exportedAt = new Date().toISOString();
  const watermark  = publicKeyHash ? buildWatermark(publicKeyHash, exportedAt) : "";

  const header = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp";
  const rows = entries.map(e => {
    const totp = (e as any).totpSecret
      ? `otpauth://totp/${encodeURIComponent(e.site)}:${encodeURIComponent(e.username)}?secret=${(e as any).totpSecret}&issuer=${encodeURIComponent(e.site)}&algorithm=SHA1&digits=6&period=30`
      : "";
    return [
      "",                        // folder
      "0",                       // favorite
      "login",                   // type
      csvEscape(e.site),         // name
      // Watermark injected here — invisible zero-width chars survive CSV round-trips
      csvEscape(((e as any).notes ?? "") + (e === entries[0] ? watermark : "")),
      "",                        // fields
      "0",                       // reprompt
      csvEscape((e as any).url ?? ""),
      csvEscape(e.username),
      csvEscape(e.password),
      csvEscape(totp),
    ].join(",");
  });

  downloadText([header, ...rows].join("\n"), "housekeyvault-export-bitwarden.csv", "text/csv");
}

// ─── EXPORT: BITWARDEN JSON ───────────────────────────────────────────────────

export function exportBitwardenJSON(entries: VaultEntry[], publicKeyHash = ""): void {
  const exportedAt = new Date().toISOString();
  const watermark  = publicKeyHash ? buildWatermark(publicKeyHash, exportedAt) : "";

  const items = entries.map(e => ({
    type:         1,
    name:         e.site,
    // Watermark appended to notes of first entry — invisible, survives JSON round-trips
    notes:        ((e as any).notes ?? "") + (e === entries[0] ? watermark : "") || null,
    favorite:     false,
    reprompt:     0,
    login: {
      username: e.username,
      password: e.password,
      totp:     (e as any).totpSecret
        ? `otpauth://totp/${encodeURIComponent(e.site)}?secret=${(e as any).totpSecret}`
        : null,
      uris: (e as any).url
        ? [{ match: null, uri: (e as any).url }]
        : [],
    },
  }));

  const payload = {
    encrypted:  false,
    folders:    [],
    // Watermark also lives here — ignored by all importers
    _hkv:       watermark || undefined,
    exportedAt,
    items,
  };

  downloadText(JSON.stringify(payload, null, 2), "housekeyvault-export-bitwarden.json", "application/json");
}

// ─── EXPORT: HOUSEKEYVAULT NATIVE JSON ───────────────────────────────────────
// Full fidelity — includes folderId, breached status, timestamps.
// Not readable by other managers, but perfect for backup.

export function exportNativeJSON(entries: VaultEntry[], publicKeyHash = ""): void {
  const exportedAt = new Date().toISOString();
  const watermark  = publicKeyHash ? buildWatermark(publicKeyHash, exportedAt) : "";

  const payload = {
    format:     "housekeyvault",
    version:    1,
    exportedAt,
    // Watermark stored explicitly — native format so we can be verbose about it
    _forensic:  watermark || undefined,
    entries,
  };
  downloadText(JSON.stringify(payload, null, 2), "housekeyvault-export-native.json", "application/json");
}

// ─── STEGANOGRAPHIC WATERMARK ────────────────────────────────────────────────
// Each export file carries an invisible forensic fingerprint encoded using
// Unicode zero-width characters (U+200B, U+200C, U+FEFF).
//
// Encoding scheme (binary → zero-width chars):
//   bit 0 → U+200B ZERO WIDTH SPACE
//   bit 1 → U+200C ZERO WIDTH NON-JOINER
//   byte boundary → U+FEFF ZERO WIDTH NO-BREAK SPACE (separator)
//
// The watermark encodes: exportedAt (ISO timestamp) + publicKeyHash (first 16 hex chars)
// It is injected as a run of invisible chars in a comment / whitespace field
// that surviving import tools silently ignore. Visually the file looks identical.
//
// Forensic use: if an exported file is leaked, the watermark survives copy-paste
// and reveals exactly when it was exported and which account produced it.

const ZW0  = "\u200B"; // zero-width space  → bit 0
const ZW1  = "\u200C"; // zero-width non-joiner → bit 1
const ZWSEP= "\uFEFF"; // BOM / zero-width no-break space → byte separator

/** Encode a UTF-8 string as a run of zero-width unicode characters. */
function zwEncode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  return Array.from(bytes)
    .map(byte =>
      Array.from({ length: 8 }, (_, i) => (byte >> (7 - i)) & 1 ? ZW1 : ZW0).join("") + ZWSEP
    )
    .join("");
}

/** Decode zero-width characters back to the original string. Throws if malformed. */
export function zwDecode(text: string): string {
  // Extract only our zero-width chars
  const zw = Array.from(text).filter(c => c === ZW0 || c === ZW1 || c === ZWSEP);
  const byteStrs = zw.join("").split(ZWSEP).filter(s => s.length === 8);
  const bytes = byteStrs.map(s =>
    parseInt(Array.from(s).map(c => c === ZW1 ? "1" : "0").join(""), 2)
  );
  return new TextDecoder().decode(new Uint8Array(bytes));
}

/**
 * Build a watermark string for injection into exports.
 * @param publicKeyHash  hex string — identifies the account
 * @param exportedAt     ISO timestamp — when the export happened
 */
export function buildWatermark(publicKeyHash: string, exportedAt: string): string {
  const payload = JSON.stringify({
    hkv: true,
    account: publicKeyHash.slice(0, 16),   // 16 hex chars = 64-bit fingerprint
    at: exportedAt,
  });
  return zwEncode(payload);
}

/**
 * Attempt to extract and decode a HouseKey watermark from any text.
 * Returns null if no valid watermark is found.
 */
export function extractWatermark(text: string): { account: string; at: string } | null {
  try {
    const decoded = zwDecode(text);
    const obj = JSON.parse(decoded);
    if (obj.hkv && obj.account && obj.at) return { account: obj.account, at: obj.at };
    return null;
  } catch {
    return null;
  }
}

// ─── FILE PICKER HELPER ───────────────────────────────────────────────────────

export function pickImportFile(): Promise<{ text: string; filename: string }> {
  return new Promise((resolve, reject) => {
    const input   = document.createElement("input");
    input.type    = "file";
    input.accept  = ".csv,.json";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return reject(new Error("No file selected."));
      try {
        const text = await file.text();
        resolve({ text, filename: file.name });
      } catch (e) {
        reject(e);
      }
    };
    input.oncancel = () => reject(new Error("Cancelled."));
    input.click();
  });
}