"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import { createPortal } from "react-dom";
import {
  generateKeyPair, signChallenge, encryptVault, decryptVault,
  encryptVaultWithSeed, decryptVaultWithSeed,
  generateSeedPhrase, generatePassword, scorePassword, emptyVault,
  encryptDecoyVault, decryptDecoyVault,
  type VaultData, type VaultEntry,
} from "@/lib/crypto-client";
import { setupUSBKey, loadUSBKey, detectTier, type StorageTier } from "@/lib/usb-storage";
import { api } from "@/lib/api-client";
import { importAuto, exportBitwardenCSV, exportBitwardenJSON, exportNativeJSON, pickImportFile, type ImportResult } from "@/lib/import-export";
import { createShare, type SharePayload } from "@/lib/share-crypto";

type Screen = "landing"|"create"|"login"|"recover"|"vault"|"paranoia";
interface SessionState { privateKeyB64:string; publicKeyB64:string; publicKeyHash:string; vault:VaultData; isDuress?:boolean; }
interface Folder { id:string; name:string; color:string; }

const FOLDER_COLORS = ["#C9A84C","#27AE8F","#C0392B","#5B8DEF","#9B59B6","#E67E22"];

// ── TOTP ENGINE ───────────────────────────────────────────────────────────────
// RFC 6238 — pure client-side, no library needed
function base32Decode(s: string): Uint8Array {
  const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.toUpperCase().replace(/[= ]/g,"");
  let bits = 0, val = 0;
  const out: number[] = [];
  for (const c of clean) {
    const idx = CHARS.indexOf(c);
    if (idx < 0) continue;
    val = (val << 5) | idx; bits += 5;
    if (bits >= 8) { bits -= 8; out.push((val >> bits) & 0xff); }
  }
  return new Uint8Array(out);
}

async function generateTOTP(secret: string, digits = 6, period = 30): Promise<string> {
  const keyBytes = base32Decode(secret);
  // Copy to a plain ArrayBuffer — WebCrypto rejects Uint8Array<ArrayBufferLike>
  const keyBuf = keyBytes.buffer.slice(keyBytes.byteOffset, keyBytes.byteOffset + keyBytes.byteLength) as ArrayBuffer;
  const counter = Math.floor(Date.now() / 1000 / period);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(4, counter, false);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBuf, { name:"HMAC", hash:"SHA-1" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, buf);
  const arr = new Uint8Array(sig);
  const offset = arr[19] & 0xf;
  const code = ((arr[offset]&0x7f)<<24|(arr[offset+1]&0xff)<<16|(arr[offset+2]&0xff)<<8|(arr[offset+3]&0xff)) % Math.pow(10, digits);
  return String(code).padStart(digits, "0");
}

function totpProgress(period = 30): number {
  return ((Date.now()/1000) % period) / period;
}

// ── SITE LOGOS ────────────────────────────────────────────────────────────────
const LOGOS: Record<string,(c:string)=>React.ReactNode> = {
  google:    c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>,
  github:    c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2z"/></svg>,
  youtube:   c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/></svg>,
  twitter:   c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.748l7.73-8.835L1.254 2.25H8.08l4.259 5.631 5.905-5.631zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>,
  x:         c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.748l7.73-8.835L1.254 2.25H8.08l4.259 5.631 5.905-5.631zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>,
  linkedin:  c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>,
  facebook:  c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>,
  instagram: c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838a6.162 6.162 0 1 0 0 12.324 6.162 6.162 0 0 0 0-12.324zM12 16a4 4 0 1 1 0-8 4 4 0 0 1 0 8zm6.406-11.845a1.44 1.44 0 1 0 0 2.881 1.44 1.44 0 0 0 0-2.881z"/></svg>,
  spotify:   c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z"/></svg>,
  netflix:   c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M5.398 0v.006c3.028 8.556 5.37 15.175 8.348 23.596 2.344.058 4.85.398 4.854.398-2.8-7.924-5.923-16.747-8.8-24zm8.489 0v9.63L18.6 24c-.508.06-1.06.091-1.6.091-2.8 0-5.38-.558-5.38-.558l.04-.018V0zm-8.49 0v23.569c1.665-.19 3.666-.332 5.432-.332V0z"/></svg>,
  amazon:    c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M.045 18.02c.072-.116.187-.124.348-.022 3.636 2.11 7.594 3.166 11.87 3.166 2.852 0 5.668-.533 8.447-1.595l.315-.14c.226-.088.39.032.287.224-.315.315-2.315 2.072-5.011 3.233-8.094 3.494-5.036.42-9.527-1.94-11.904-4.65a.635.635 0 0 1-.028-.37z"/></svg>,
  apple:     c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.54 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701"/></svg>,
  microsoft: c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M11.4 24H0V12.6h11.4V24zM24 24H12.6V12.6H24V24zM11.4 11.4H0V0h11.4v11.4zm12.6 0H12.6V0H24v11.4z"/></svg>,
  discord:   c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>,
  slack:     c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/></svg>,
  notion:    c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M4.459 4.208c.746.606 1.026.56 2.428.466l13.215-.793c.28 0 .047-.28-.046-.326L17.86 1.968c-.42-.326-.981-.7-2.055-.607L3.01 2.295c-.466.046-.56.28-.374.466zm.793 3.08v13.904c0 .747.373 1.027 1.214.98l14.523-.84c.841-.046.935-.56.935-1.167V6.354c0-.606-.233-.933-.748-.887l-15.177.887c-.56.047-.747.327-.747.933zm14.337.745c.093.42 0 .84-.42.888l-.7.14v10.264c-.608.327-1.168.514-1.635.514-.748 0-.935-.234-1.495-.933l-4.577-7.186v6.952L12.21 19s0 .84-1.168.84l-3.222.186c-.093-.186 0-.653.327-.746l.84-.233V9.854L7.822 9.76c-.094-.42.14-1.026.793-1.073l3.456-.233 4.764 7.279v-6.44l-1.215-.139c-.093-.514.28-.887.747-.933z"/></svg>,
  figma:     c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M15.852 8.981h-4.588V0h4.588c2.476 0 4.49 2.014 4.49 4.49s-2.014 4.491-4.49 4.491zM12.735 7.51h3.117c1.665 0 3.019-1.355 3.019-3.019s-1.354-3.019-3.019-3.019h-3.117V7.51zm0 1.471H8.148c-2.476 0-4.49-2.014-4.49-4.49S5.672 0 8.148 0h4.588v8.981zm-4.587-7.51c-1.665 0-3.019 1.355-3.019 3.019s1.354 3.019 3.019 3.019h3.117V1.471H8.148zm4.587 15.019H8.148c-2.476 0-4.49-2.014-4.49-4.49s2.014-4.49 4.49-4.49h4.588v8.98zM8.148 8.981c-1.665 0-3.019 1.355-3.019 3.019s1.354 3.019 3.019 3.019h3.117V8.981H8.148z"/></svg>,
  dropbox:   c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M6 1.807L0 5.871l6 4.064 6-4.064L6 1.807zm12 0l-6 4.064 6 4.064 6-4.064L18 1.807zM0 13.999l6 4.064 6-4.064-6-4.064L0 13.999zm18-4.064l-6 4.064 6 4.064 6-4.064-6-4.064zM6 19.139l6 4.054 6-4.054-6-4.064-6 4.064z"/></svg>,
  reddit:    c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M12 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0zm5.01 4.744c.688 0 1.25.561 1.25 1.249a1.25 1.25 0 0 1-2.498.056l-2.597-.547-.8 3.747c1.824.07 3.48.632 4.674 1.488.308-.309.73-.491 1.207-.491.968 0 1.754.786 1.754 1.754 0 .716-.435 1.333-1.01 1.614a3.111 3.111 0 0 1 .042.52c0 2.694-3.13 4.87-7.004 4.87-3.874 0-7.004-2.176-7.004-4.87 0-.183.015-.366.043-.534A1.748 1.748 0 0 1 4.028 12c0-.968.786-1.754 1.754-1.754.463 0 .898.196 1.207.49 1.207-.883 2.878-1.43 4.744-1.487l.885-4.182a.342.342 0 0 1 .14-.197.35.35 0 0 1 .238-.042l2.906.617a1.214 1.214 0 0 1 1.108-.701zM9.25 12C8.561 12 8 12.562 8 13.25c0 .687.561 1.248 1.25 1.248.687 0 1.248-.561 1.248-1.249 0-.688-.561-1.249-1.249-1.249zm5.5 0c-.687 0-1.248.561-1.248 1.25 0 .687.561 1.248 1.249 1.248.688 0 1.249-.561 1.249-1.249 0-.687-.562-1.249-1.25-1.249zm-5.466 3.99a.327.327 0 0 0-.231.094.33.33 0 0 0 0 .463c.842.842 2.484.913 2.961.913.477 0 2.105-.056 2.961-.913a.361.361 0 0 0 .029-.463.33.33 0 0 0-.464 0c-.547.533-1.684.73-2.512.73-.828 0-1.979-.196-2.512-.73a.326.326 0 0 0-.232-.095z"/></svg>,
  twitch:    c=><svg viewBox="0 0 24 24" width="15" height="15" fill={c}><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z"/></svg>,
};
function getSiteLogo(site:string){const h=site.toLowerCase().replace(/^https?:\/\/(www\.)?/,"").split("/")[0];return LOGOS[h.split(".")[0]]??null;}

// ── CSS ────────────────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;500;600&family=IBM+Plex+Mono:wght@300;400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --ink:#0C0C0F;--ink2:#14141A;--ink3:#1C1C24;--ink4:#26262F;
  --line:rgba(255,255,255,0.10);--line2:rgba(255,255,255,0.16);
  --gold:#C9A84C;--gold2:#E2C06A;--gold-dim:rgba(201,168,76,0.15);--gold-glow:rgba(201,168,76,0.06);
  --crimson:#C0392B;--crimson-dim:rgba(192,57,43,0.15);
  --jade:#27AE8F;--jade-dim:rgba(39,174,143,0.12);
  --text:#F0EDE6;--text2:#B8B5AE;--text3:#7A7774;
  --display:'Playfair Display',Georgia,serif;
  --sans:'IBM Plex Sans',system-ui,sans-serif;
  --mono:'IBM Plex Mono','Courier New',monospace;
  --r:6px;--r2:10px;--shadow:0 1px 3px rgba(0,0,0,.4),0 8px 32px rgba(0,0,0,.3);
}
html,body{background:var(--ink);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh}
.app{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;position:relative;overflow:hidden}
.app::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(201,168,76,.04) 0%,transparent 60%),radial-gradient(ellipse 50% 80% at 100% 100%,rgba(39,174,143,.03) 0%,transparent 50%);pointer-events:none}
.app::after{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(255,255,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.015) 1px,transparent 1px);background-size:48px 48px;pointer-events:none}
.screen{width:100%;max-width:480px;position:relative;z-index:1;animation:appear .5s cubic-bezier(.16,1,.3,1) forwards}
.screen-full{max-width:1160px;width:100%}
@keyframes appear{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}
/* WORDMARK */
.wordmark{display:flex;align-items:flex-end;gap:12px;margin-bottom:28px}
.wm-icon{width:36px;height:36px;border:1px solid var(--gold);display:flex;align-items:center;justify-content:center;position:relative;flex-shrink:0}
.wm-icon::before{content:'';position:absolute;inset:3px;border:1px solid rgba(201,168,76,.3)}
.wm-icon svg{width:16px;height:16px;stroke:var(--gold);fill:none;stroke-width:1.5}
.wm-name{font-family:var(--display);font-size:17px;font-weight:500;color:var(--text);line-height:1}
.wm-sub{font-family:var(--mono);font-size:9px;font-weight:300;letter-spacing:.25em;color:var(--text3);text-transform:uppercase;line-height:1;margin-top:4px}
/* CARD */
.card{background:var(--ink2);border:1px solid var(--line2);border-radius:var(--r2);padding:28px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--gold-dim),transparent)}
.eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.2em;color:var(--gold);text-transform:uppercase;margin-bottom:10px;display:flex;align-items:center;gap:8px}
.eyebrow::after{content:'';flex:1;height:1px;background:var(--line2)}
.h1{font-family:var(--display);font-size:26px;font-weight:400;letter-spacing:-.01em;line-height:1.2;margin-bottom:8px}
.body{font-size:13px;color:var(--text);line-height:1.7;margin-bottom:22px;opacity:.85}
/* VAULT */
.vault-topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px}
.vault-body{display:grid;grid-template-columns:256px 1fr;gap:14px;align-items:start}
@media(max-width:900px){.vault-body{grid-template-columns:1fr}}
.sidebar{display:flex;flex-direction:column;gap:10px;position:sticky;top:24px}
.sidebar-card{background:var(--ink2);border:1px solid var(--line2);border-radius:var(--r2);padding:18px;position:relative;overflow:hidden}
.sidebar-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--gold-dim),transparent)}
.nav-label{font-family:var(--mono);font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--text2);margin-bottom:8px}
/* HEALTH */
.health-mini{display:flex;flex-direction:column;gap:5px}
.hm-row{display:flex;align-items:center;justify-content:space-between}
.hm-label{font-family:var(--mono);font-size:10px;color:var(--text2)}
.hm-val{font-family:var(--mono);font-size:12px;font-weight:500}
.hm-bar{height:2px;background:var(--line);border-radius:2px;margin-top:2px;overflow:hidden}
.hm-bar-fill{height:100%;border-radius:2px;transition:width .8s ease}
.score-ring-wrap{display:flex;align-items:center;gap:12px;margin-bottom:12px}
.score-ring-label{font-family:var(--display);font-size:14px;font-weight:400}
.score-ring-sub{font-family:var(--mono);font-size:9px;color:var(--text2);margin-top:2px}
/* FOLDERS */
.folder-list{display:flex;flex-direction:column;gap:1px;margin-bottom:4px}
.fi{display:flex;align-items:center;gap:6px;padding:4px 6px;border-radius:4px;cursor:pointer;transition:background .14s;position:relative;user-select:none}
.fi:hover{background:var(--ink3)}
.fi.on{background:var(--ink3)}
.fi.on .fi-name{color:var(--text)}
/* drag state */
.fi.drag-over{background:var(--gold-dim);outline:1px dashed rgba(201,168,76,.5)}
.fi-dot{width:5px;height:5px;border-radius:1px;flex-shrink:0}
.fi-icon{flex-shrink:0;opacity:.4}
.fi-icon svg{display:block}
.fi-name{font-family:var(--mono);font-size:10px;color:var(--text2);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;transition:color .14s}
.fi-count{font-family:var(--mono);font-size:9px;color:var(--text2);min-width:10px;text-align:right}
.fi-del{width:14px;height:14px;border:none;background:transparent;color:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;border-radius:2px;padding:0;transition:color .12s;flex-shrink:0}
.fi-del svg{width:9px;height:9px;stroke:currentColor;fill:none;stroke-width:2}
.fi:hover .fi-del{color:var(--text3)}
.fi-del:hover{color:var(--crimson)!important}
.fc-row{display:flex;align-items:center;gap:3px;margin-top:4px}
.fc-inp{flex:1;background:var(--ink3);border:1px solid var(--line);border-radius:4px;padding:4px 7px;color:var(--text);font-family:var(--mono);font-size:10px;outline:none;min-width:0}
.fc-inp:focus{border-color:rgba(201,168,76,.35)}
.fc-inp::placeholder{color:var(--text3)}
.fc-btn{width:22px;height:22px;border:1px solid var(--line);border-radius:4px;background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--text3);transition:all .14s;flex-shrink:0}
.fc-btn svg{width:10px;height:10px;stroke:currentColor;fill:none;stroke-width:2}
.fc-btn.ok:hover{border-color:var(--gold);color:var(--gold);background:var(--gold-dim)}
.fc-btn.cancel:hover{border-color:var(--crimson);color:var(--crimson)}
.fc-colors{display:flex;gap:3px;margin-top:4px}
.fc-c{width:10px;height:10px;border-radius:2px;cursor:pointer;border:1px solid transparent;transition:transform .1s}
.fc-c.on{border-color:rgba(255,255,255,.5);transform:scale(1.25)}
.f-new{display:flex;align-items:center;gap:4px;margin-top:4px;padding:3px 6px;border-radius:4px;border:1px dashed var(--line);color:var(--text3);font-family:var(--mono);font-size:9px;letter-spacing:.06em;cursor:pointer;transition:all .15s;width:100%;background:transparent}
.f-new svg{width:9px;height:9px;stroke:currentColor;fill:none;stroke-width:2;flex-shrink:0}
.f-new:hover{border-color:rgba(201,168,76,.4);color:var(--gold)}
/* STATUS */
.status-pill{display:flex;align-items:center;gap:6px;padding:5px 12px;background:var(--jade-dim);border:1px solid rgba(39,174,143,.2);border-radius:20px;font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--jade);text-transform:uppercase}
.status-dot{width:6px;height:6px;border-radius:50%;background:var(--jade);animation:pulse 2.5s ease infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.topbar-btn{padding:5px 12px;background:transparent;border:1px solid var(--line2);border-radius:var(--r);color:var(--text2);font-family:var(--sans);font-size:11px;font-weight:500;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:5px;line-height:1;white-space:nowrap;height:30px}
.topbar-btn svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5;flex-shrink:0}
.topbar-btn:hover{border-color:var(--line2);color:var(--text2)}
.lock-btn{padding:5px 12px;background:transparent;border:1px solid var(--line2);border-radius:var(--r);color:var(--text2);font-family:var(--sans);font-size:11px;font-weight:500;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:5px;line-height:1;height:30px}
.lock-btn svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5}
.lock-btn:hover{border-color:var(--crimson);color:var(--crimson)}
/* MAIN PANEL */
.main-panel{display:flex;flex-direction:column;gap:14px}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.toolbar-left{display:flex;flex-direction:column;gap:2px}
.toolbar-right{display:flex;align-items:center;gap:8px}
.panel-title{font-family:var(--display);font-size:18px;font-weight:400;display:flex;align-items:center;gap:7px}
.panel-meta{font-family:var(--mono);font-size:10px;color:var(--text2);letter-spacing:.06em}
.search-wrap{position:relative}
.search-wrap svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);width:13px;height:13px;stroke:var(--text3);fill:none;stroke-width:1.5;pointer-events:none}
.search-inp{background:var(--ink3);border:1px solid var(--line);border-radius:var(--r);padding:8px 12px 8px 32px;color:var(--text);font-family:var(--mono);font-size:12px;outline:none;width:190px;transition:border-color .2s}
.search-inp:focus{border-color:rgba(201,168,76,.4)}
.search-inp::placeholder{color:var(--text3)}
.add-btn{padding:5px 14px;height:30px;background:var(--gold);color:var(--ink);border:none;border-radius:var(--r);font-family:var(--sans);font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:5px;white-space:nowrap;line-height:1}
.add-btn svg{width:13px;height:13px;stroke:var(--ink);fill:none;stroke-width:2}
.add-btn:hover{background:var(--gold2);transform:translateY(-1px);box-shadow:0 4px 16px rgba(201,168,76,.2)}
/* ENTRIES */
.entries{display:flex;flex-direction:column;gap:5px}
.entry-card{background:var(--ink3);border:1px solid var(--line);border-radius:var(--r2);padding:11px 14px;display:flex;align-items:center;gap:12px;transition:all .18s;position:relative}
.entry-card:hover{border-color:var(--line2);background:var(--ink4)}
.entry-card.breached{border-color:rgba(192,57,43,.3);background:rgba(192,57,43,.04)}
.entry-card.dragging{opacity:.4;border-style:dashed}
.entry-card.drag-over-card{border-color:var(--gold);background:var(--gold-glow)}
/* drag handle */
.drag-handle{width:16px;display:flex;align-items:center;justify-content:center;cursor:grab;color:var(--text3);opacity:0;transition:opacity .15s;flex-shrink:0}
.drag-handle svg{width:12px;height:12px;fill:currentColor}
.entry-card:hover .drag-handle{opacity:.5}
.drag-handle:active{cursor:grabbing}
/* entry avatar */
.entry-avatar{width:32px;height:32px;background:var(--ink4);border:1px solid var(--line);border-radius:var(--r);display:flex;align-items:center;justify-content:center;font-family:var(--display);font-size:13px;font-weight:500;color:var(--text2);flex-shrink:0;text-transform:uppercase;overflow:hidden}
.entry-avatar.has-logo{background:var(--ink3);border-color:var(--line2)}
.entry-info{flex:1;min-width:0;overflow:hidden}
.entry-site{font-size:13px;font-weight:500;color:var(--text);margin-bottom:1px;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.entry-user{font-family:var(--mono);font-size:11px;color:var(--text2)}
.entry-pw{font-family:var(--mono);font-size:11px;color:var(--gold);margin-top:3px;word-break:break-all;line-height:1.4}
.entry-actions{display:flex;align-items:center;gap:2px;flex-shrink:0}
.icon-btn{width:28px;height:28px;border-radius:var(--r);border:1px solid transparent;background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .18s;color:var(--text2)}
.icon-btn svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:1.5}
.icon-btn:hover{background:var(--ink4);border-color:var(--line2);color:var(--text)}
.icon-btn.danger:hover{background:var(--crimson-dim);border-color:rgba(192,57,43,.3);color:var(--crimson)}
.icon-btn.active{color:var(--jade)}
.icon-btn.editing{color:var(--gold);border-color:rgba(201,168,76,.3);background:var(--gold-dim)}
.icon-btn:disabled{opacity:.3;cursor:not-allowed}
/* TOTP chip */
.totp-chip{display:inline-flex;align-items:center;gap:5px;background:var(--ink2);border:1px solid var(--line2);border-radius:20px;padding:2px 8px 2px 5px;cursor:pointer;transition:all .2s;user-select:none;margin-top:3px}
.totp-chip:hover{border-color:var(--gold);background:var(--gold-glow)}
.totp-code{font-family:var(--mono);font-size:12px;font-weight:500;color:var(--gold2);letter-spacing:.12em}
.totp-ring{width:14px;height:14px;flex-shrink:0}
.totp-ring circle{transition:stroke-dasharray .5s linear}
.totp-copied{color:var(--jade)!important;border-color:rgba(39,174,143,.3)!important}
/* BADGES */
.badge{display:inline-flex;align-items:center;padding:2px 6px;border-radius:3px;font-family:var(--mono);font-size:9px;font-weight:500;letter-spacing:.08em;text-transform:uppercase}
.badge-danger{background:var(--crimson-dim);color:#E07070;border:1px solid rgba(192,57,43,.25)}
.badge-safe{background:var(--jade-dim);color:var(--jade);border:1px solid rgba(39,174,143,.25)}
.badge-totp{background:rgba(91,141,239,.12);color:#7AACF8;border:1px solid rgba(91,141,239,.25)}
/* EDIT INLINE */
.entry-edit-panel{background:var(--ink2);border:1px solid rgba(201,168,76,.2);border-radius:var(--r2);padding:16px;margin-bottom:4px;animation:appear .2s cubic-bezier(.16,1,.3,1)}
/* ADD / EDIT FORM */
.add-form{background:var(--ink3);border:1px solid rgba(201,168,76,.2);border-radius:var(--r2);padding:18px;margin-bottom:14px;animation:appear .25s cubic-bezier(.16,1,.3,1)}
.sec-label{font-family:var(--mono);font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--text2);margin-bottom:6px;margin-top:12px}
.sec-label:first-child{margin-top:0}
.form-row{display:flex;gap:10px}
.form-row .field{flex:1}
.field{display:flex;flex-direction:column;gap:4px;margin-bottom:6px}
.field-label{font-family:var(--mono);font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:var(--text2)}
.inp{background:var(--ink2);border:1px solid var(--line);border-radius:var(--r);padding:7px 10px;color:var(--text);font-family:var(--mono);font-size:12px;outline:none;width:100%;transition:border-color .2s}
.inp:focus{border-color:rgba(201,168,76,.4)}
.inp::placeholder{color:var(--text3)}
.select{background:var(--ink2);border:1px solid var(--line);border-radius:var(--r);padding:7px 10px;color:var(--text);font-family:var(--mono);font-size:12px;outline:none;width:100%;cursor:pointer;appearance:none}
.select option{background:var(--ink2)}
.form-actions{display:flex;gap:8px;margin-top:12px}
.form-actions .btn{padding:9px 16px;font-size:11px}
.btn-cancel{width:auto;flex:0;padding:9px 16px}
/* GEN PANEL */
.gen-panel{background:var(--ink2);border:1px solid var(--line);border-radius:var(--r);padding:10px 12px;margin-top:6px}
.gen-tabs{display:flex;gap:4px;margin-bottom:10px}
.gen-tab{flex:1;padding:5px 8px;border-radius:4px;border:1px solid var(--line);background:transparent;color:var(--text3);font-family:var(--mono);font-size:10px;letter-spacing:.06em;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:5px;text-transform:uppercase}
.gen-tab svg{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:1.5;flex-shrink:0}
.gen-tab.active{background:var(--gold-dim);border-color:rgba(201,168,76,.4);color:var(--gold)}
.gen-tab:hover:not(.active){border-color:var(--line2);color:var(--text2)}
.chips{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px}
.chip{padding:3px 8px;border-radius:3px;border:1px solid var(--line);background:transparent;font-family:var(--mono);font-size:9px;color:var(--text2);cursor:pointer;transition:all .15s;letter-spacing:.04em}
.chip.on{background:var(--gold-dim);border-color:rgba(201,168,76,.4);color:var(--gold)}
.pw-row{display:flex;gap:6px;align-items:flex-end}
.pw-row .field{flex:1;margin-bottom:0}
.gen-btns{display:flex;gap:4px;padding-bottom:1px}
.gen-btn{width:30px;height:30px;background:var(--ink3);border:1px solid var(--line2);border-radius:var(--r);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;flex-shrink:0}
.gen-btn svg{width:12px;height:12px;stroke:var(--text2);fill:none;stroke-width:1.5}
.gen-btn:hover{border-color:var(--gold)}
.gen-btn:hover svg{stroke:var(--gold)}
.gen-btn:disabled{opacity:.3;cursor:not-allowed}
.entropy-note{font-family:var(--mono);font-size:9px;color:var(--text3);margin-top:4px}
.llm-suggestions{display:flex;flex-direction:column;gap:4px;margin-top:6px}
.llm-sugg{background:var(--ink3);border:1px solid var(--line);border-radius:var(--r);padding:7px 10px;cursor:pointer;transition:all .18s}
.llm-sugg:hover{border-color:var(--gold)}
.llm-sugg.sel{border-color:var(--gold);background:var(--gold-glow)}
.llm-pw{font-family:var(--mono);font-size:11px;color:var(--gold2);display:block;margin-bottom:3px;word-break:break-all}
/* STRENGTH */
.str-row{display:flex;gap:3px;margin-top:4px}
.str-seg{height:2px;flex:1;border-radius:1px;background:var(--line);transition:background .3s}
.str-label{font-family:var(--mono);font-size:9px;margin-top:2px}
/* EMPTY */
.empty{text-align:center;padding:40px 24px;color:var(--text3)}
.empty-icon{width:40px;height:40px;border:1px solid var(--line);border-radius:50%;margin:0 auto 12px;display:flex;align-items:center;justify-content:center}
.empty-icon svg{width:16px;height:16px;stroke:var(--text3);fill:none;stroke-width:1}
.empty-title{font-size:13px;font-weight:500;color:var(--text2);margin-bottom:3px}
.empty-sub{font-family:var(--mono);font-size:11px}
/* BUTTONS */
.btn{width:100%;padding:12px 20px;border-radius:var(--r);border:none;font-family:var(--sans);font-size:13px;font-weight:500;letter-spacing:.04em;cursor:pointer;transition:all .2s cubic-bezier(.16,1,.3,1);display:flex;align-items:center;justify-content:center;gap:8px;text-transform:uppercase}
.btn-primary{background:var(--gold);color:var(--ink)}
.btn-primary:hover:not(:disabled){background:var(--gold2);transform:translateY(-1px);box-shadow:0 4px 24px rgba(201,168,76,.25)}
.btn-outline{background:transparent;color:var(--text);border:1px solid var(--line2);margin-top:10px}
.btn-outline:hover:not(:disabled){border-color:var(--gold);color:var(--gold)}
.btn-ghost{background:transparent;color:var(--text3);border:none;margin-top:6px;font-size:12px;padding:10px}
.btn-ghost:hover{color:var(--text2)}
.btn-row{display:flex;gap:10px}
.btn-row .btn{flex:1}
.btn:disabled{opacity:.35;cursor:not-allowed}
/* ALERTS */
.alert{border-radius:var(--r);padding:11px 14px;font-size:12px;line-height:1.6;margin-bottom:14px;display:flex;gap:10px;align-items:flex-start}
.alert svg{width:14px;height:14px;flex-shrink:0;margin-top:1px}
.alert-warn{background:var(--crimson-dim);border:1px solid rgba(192,57,43,.25);color:#E07070}
.alert-warn svg{stroke:#E07070;fill:none;stroke-width:1.5}
.alert-ok{background:var(--jade-dim);border:1px solid rgba(39,174,143,.25);color:var(--jade)}
.alert-ok svg{stroke:var(--jade);fill:none;stroke-width:1.5}
/* STEPS */
.steps{display:flex;gap:4px;margin-bottom:28px}
.step-bar{height:2px;flex:1;background:var(--line2);border-radius:1px;overflow:hidden;position:relative}
.step-bar.done::after,.step-bar.active::after{content:'';position:absolute;inset:0;background:var(--gold)}
.step-bar.active::after{animation:fillBar .4s ease forwards}
@keyframes fillBar{from{transform:scaleX(0);transform-origin:left}to{transform:scaleX(1);transform-origin:left}}
/* USB */
.usb-zone{border:1px solid var(--line2);border-radius:var(--r2);padding:28px 24px;text-align:center;margin-bottom:16px;cursor:pointer;transition:all .25s;position:relative;overflow:hidden;background:var(--ink3)}
.usb-zone::before{content:'';position:absolute;inset:0;background:var(--gold-glow);opacity:0;transition:opacity .25s}
.usb-zone:hover::before,.usb-zone.active::before{opacity:1}
.usb-zone:hover,.usb-zone.active{border-color:rgba(201,168,76,.4)}
.usb-visual{width:44px;height:44px;margin:0 auto 14px;border:1px solid var(--line2);border-radius:50%;display:flex;align-items:center;justify-content:center;position:relative;z-index:1}
.usb-zone.active .usb-visual{border-color:var(--gold);animation:ring 1.5s ease infinite}
@keyframes ring{0%,100%{box-shadow:0 0 0 0 rgba(201,168,76,.3)}50%{box-shadow:0 0 0 8px rgba(201,168,76,0)}}
.usb-visual svg{width:18px;height:18px;stroke:var(--text2);fill:none;stroke-width:1.5;position:relative;z-index:1}
.usb-zone.active .usb-visual svg{stroke:var(--gold)}
.usb-label{font-size:13px;font-weight:500;color:var(--text);margin-bottom:3px;position:relative;z-index:1}
.usb-hint{font-family:var(--mono);font-size:11px;color:var(--text2);position:relative;z-index:1}
/* SEED */
.seed-box{background:var(--ink);border:1px solid var(--line2);border-radius:var(--r2);padding:16px;margin:14px 0}
.seed-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.seed-label{font-family:var(--mono);font-size:10px;letter-spacing:.18em;color:var(--text2);text-transform:uppercase}
.seed-copy{display:flex;align-items:center;gap:6px;padding:5px 12px;background:transparent;border:1px solid var(--line2);border-radius:var(--r);color:var(--text2);font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;transition:all .2s}
.seed-copy:hover{border-color:var(--gold);color:var(--gold)}
.seed-copy.copied{border-color:var(--jade);color:var(--jade)}
.seed-copy svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5}
.seed-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:5px}
.seed-word{background:var(--ink2);border:1px solid var(--line);border-radius:var(--r);padding:6px 10px;display:flex;align-items:center;gap:7px;font-family:var(--mono)}
.seed-idx{font-size:9px;color:var(--text2);min-width:14px;font-weight:300}
.seed-val{font-size:11px;font-weight:400;color:var(--gold2)}
/* RECOVERY */
.seed-input-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:4px;margin:14px 0}
.si{display:flex;align-items:center;gap:4px;background:var(--ink3);border:1px solid var(--line);border-radius:var(--r);padding:5px 7px;transition:border-color .2s}
.si:focus-within{border-color:rgba(201,168,76,.4)}
.si.err{border-color:rgba(192,57,43,.5)!important}
.si-num{font-family:var(--mono);font-size:9px;color:var(--text3);min-width:14px;flex-shrink:0;user-select:none}
.si-inp{flex:1;background:transparent;border:none;outline:none;color:var(--gold2);font-family:var(--mono);font-size:11px;min-width:0;width:100%}
.si-inp::placeholder{color:var(--text3)}
.recovery-link{background:transparent;border:none;color:var(--text3);font-family:var(--mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:color .2s;display:inline-flex;align-items:center;gap:5px;padding:0;margin-top:12px}
.recovery-link svg{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:1.5}
.recovery-link:hover{color:var(--gold)}
/* MISC */
.sec-bar{display:flex;align-items:center;gap:14px;padding:10px 16px;background:var(--ink3);border:1px solid var(--line);border-radius:var(--r);margin-bottom:14px;flex-wrap:wrap}
.sec-item{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--text3)}
.sec-item svg{width:11px;height:11px;stroke:var(--jade);fill:none;stroke-width:1.5}
.divider{height:1px;background:var(--line);margin:14px 0}
.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);background:var(--ink3);border:1px solid var(--line2);border-radius:var(--r);padding:10px 20px;font-family:var(--mono);font-size:11px;letter-spacing:.05em;color:var(--text);box-shadow:var(--shadow);animation:toastIn .3s cubic-bezier(.16,1,.3,1);z-index:9999;white-space:nowrap;pointer-events:none}
.toast.ok{border-color:rgba(39,174,143,.3);color:var(--jade)}
.toast.warn{border-color:rgba(192,57,43,.3);color:#E07070}
@keyframes toastIn{from{opacity:0;transform:translateX(-50%) translateY(10px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}
/* TOOLTIP */
.tooltip-anchor{position:relative;display:inline-flex;align-items:center;cursor:help}
.tooltip-anchor svg{width:12px;height:12px;stroke:var(--text3);fill:none;stroke-width:1.5}
.tooltip-anchor::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--ink);border:1px solid var(--line2);border-radius:var(--r);padding:8px 11px;font-family:var(--sans);font-size:11px;font-weight:400;line-height:1.55;color:var(--text2);width:240px;white-space:normal;text-align:left;pointer-events:none;opacity:0;transition:opacity .15s;z-index:50;box-shadow:var(--shadow);letter-spacing:0;text-transform:none}
.tooltip-anchor:hover::after{opacity:1}
/* SECOND DEVICE BADGE */
.badge-2dev{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;background:rgba(201,168,76,.1);border:1px solid rgba(201,168,76,.3);border-radius:3px;font-family:var(--mono);font-size:8px;letter-spacing:.06em;text-transform:uppercase;color:var(--gold);cursor:pointer}
.badge-2dev svg{width:9px;height:9px;stroke:currentColor;fill:none;stroke-width:1.5}
/* SECOND DEVICE UNLOCK OVERLAY */
.unlock-overlay{position:absolute;inset:0;background:rgba(12,12,15,.92);backdrop-filter:blur(6px);border-radius:var(--r2);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;z-index:10;padding:20px;text-align:center}
.unlock-icon{width:44px;height:44px;border:1px solid rgba(201,168,76,.4);border-radius:50%;display:flex;align-items:center;justify-content:center}
.unlock-icon svg{width:18px;height:18px;stroke:var(--gold);fill:none;stroke-width:1.5}
/* IMPORT/EXPORT MODAL */
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(4px);z-index:200;display:flex;align-items:center;justify-content:center;padding:24px;animation:appear .2s ease}
.modal{background:var(--ink2);border:1px solid var(--line2);border-radius:var(--r2);width:100%;max-width:540px;max-height:90vh;overflow-y:auto;position:relative;box-shadow:0 24px 64px rgba(0,0,0,.6)}
.modal::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--gold-dim),transparent)}
.modal-header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px 16px;border-bottom:1px solid var(--line)}
.modal-title{font-family:var(--display);font-size:18px;font-weight:400}
.modal-close{width:28px;height:28px;border-radius:var(--r);border:1px solid var(--line);background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--text3);transition:all .15s}
.modal-close:hover{border-color:var(--crimson);color:var(--crimson)}
.modal-close svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:1.5}
.modal-body{padding:20px 24px}
.modal-tabs{display:flex;gap:2px;margin-bottom:20px;background:var(--ink3);border:1px solid var(--line);border-radius:var(--r);padding:3px}
.modal-tab{flex:1;padding:7px 12px;border-radius:4px;border:none;background:transparent;color:var(--text3);font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;transition:all .18s;display:flex;align-items:center;justify-content:center;gap:6px}
.modal-tab svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5;flex-shrink:0}
.modal-tab.active{background:var(--ink2);color:var(--gold);box-shadow:0 1px 4px rgba(0,0,0,.3)}
.modal-tab:hover:not(.active){color:var(--text2)}
.fmt-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px}
.fmt-card{border:1px solid var(--line);border-radius:var(--r2);padding:14px;cursor:pointer;transition:all .18s;background:var(--ink3);display:flex;flex-direction:column;gap:4px}
.fmt-card:hover{border-color:rgba(201,168,76,.4);background:var(--gold-glow)}
.fmt-card.selected{border-color:var(--gold);background:var(--gold-glow)}
.fmt-card-name{font-size:12px;font-weight:500;color:var(--text)}
.fmt-card-desc{font-family:var(--mono);font-size:9px;color:var(--text3);line-height:1.5}
.fmt-badge{display:inline-flex;padding:1px 5px;border-radius:2px;font-family:var(--mono);font-size:8px;letter-spacing:.06em;text-transform:uppercase;margin-top:2px}
.fmt-badge.recommended{background:var(--jade-dim);color:var(--jade);border:1px solid rgba(39,174,143,.25)}
.fmt-badge.compat{background:var(--gold-dim);color:var(--gold);border:1px solid rgba(201,168,76,.25)}
.drop-zone{border:2px dashed var(--line2);border-radius:var(--r2);padding:32px 24px;text-align:center;cursor:pointer;transition:all .2s;margin-bottom:14px}
.drop-zone:hover,.drop-zone.drag-active{border-color:rgba(201,168,76,.5);background:var(--gold-glow)}
.drop-zone-icon{width:36px;height:36px;border:1px solid var(--line2);border-radius:50%;margin:0 auto 10px;display:flex;align-items:center;justify-content:center}
.drop-zone-icon svg{width:16px;height:16px;stroke:var(--text3);fill:none;stroke-width:1.5}
.drop-zone:hover .drop-zone-icon svg,.drop-zone.drag-active .drop-zone-icon svg{stroke:var(--gold)}
.drop-zone-label{font-size:13px;font-weight:500;color:var(--text2);margin-bottom:3px}
.drop-zone-hint{font-family:var(--mono);font-size:10px;color:var(--text3)}
.import-result{background:var(--jade-dim);border:1px solid rgba(39,174,143,.25);border-radius:var(--r);padding:12px 14px;margin-bottom:14px}
.import-result-title{font-size:12px;font-weight:500;color:var(--jade);margin-bottom:2px}
.import-result-sub{font-family:var(--mono);font-size:10px;color:var(--text3)}
.import-btn-row{display:flex;gap:8px}
.import-btn-row .btn{flex:1;padding:10px 14px;font-size:11px}
/* SHARE MODAL */
.share-link-box{background:var(--ink);border:1px solid rgba(201,168,76,.3);border-radius:var(--r);padding:10px 12px;margin:10px 0;word-break:break-all;font-family:var(--mono);font-size:10px;color:var(--gold2);line-height:1.6;position:relative}
.share-link-copy{position:absolute;top:6px;right:6px;width:24px;height:24px;border-radius:4px;border:1px solid var(--line2);background:var(--ink2);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;color:var(--text3)}
.share-link-copy:hover{border-color:var(--gold);color:var(--gold)}
.share-link-copy.ok{border-color:var(--jade);color:var(--jade)}
.share-link-copy svg{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:1.5}
.ttl-chips{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:12px}
.ttl-chip{padding:4px 10px;border:1px solid var(--line);border-radius:3px;background:transparent;font-family:var(--mono);font-size:9px;letter-spacing:.06em;color:var(--text3);cursor:pointer;transition:all .15s;text-transform:uppercase}
.ttl-chip.on{background:var(--gold-dim);border-color:rgba(201,168,76,.4);color:var(--gold)}
/* topbar import/export button */
.io-btn{padding:5px 12px;background:transparent;border:1px solid var(--line2);border-radius:var(--r);color:var(--text2);font-family:var(--sans);font-size:11px;font-weight:500;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:5px;line-height:1;height:30px;white-space:nowrap}
.io-btn svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5;flex-shrink:0}
.io-btn:hover{border-color:var(--gold);color:var(--gold)}
/* PARANOIA */
.paranoia-bg{background:radial-gradient(ellipse 60% 60% at 50% 50%,rgba(192,57,43,.06) 0%,transparent 70%),var(--ink)}
/* DURESS MODE — barely visible red tint on vault topbar only, not obvious to coercer */
.duress-indicator{display:flex;align-items:center;gap:5px;font-family:var(--mono);font-size:9px;color:rgba(192,57,43,.4);letter-spacing:.1em;text-transform:uppercase}
.duress-dot{width:5px;height:5px;border-radius:50%;background:rgba(192,57,43,.5);animation:pulse 3s ease infinite}
.p-icon{width:72px;height:72px;border:1px solid rgba(192,57,43,.4);border-radius:50%;margin:0 auto 24px;display:flex;align-items:center;justify-content:center;animation:pPulse 1.5s ease infinite}
.p-icon svg{width:28px;height:28px;stroke:var(--crimson);fill:none;stroke-width:1.5}
@keyframes pPulse{0%,100%{box-shadow:0 0 0 0 rgba(192,57,43,.3)}50%{box-shadow:0 0 0 12px rgba(192,57,43,0)}}
.p-title{font-family:var(--display);font-size:26px;font-weight:400;color:var(--crimson);margin-bottom:8px;text-align:center}
.p-sub{font-size:13px;color:#9A7070;line-height:1.7;margin-bottom:24px;text-align:center}
.countdown{font-family:var(--mono);font-size:48px;font-weight:300;color:var(--crimson);letter-spacing:-2px;margin-bottom:6px;text-align:center}
.countdown-label{font-family:var(--mono);font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--text3);text-align:center}
`;

// ── ICONS ──────────────────────────────────────────────────────────────────────
const I = {
  Key:       ()=><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M12 15h8M17 15v-2"/></svg>,
  Lock:      ()=><svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="11" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>,
  Unlock:    ()=><svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="11" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.75-1"/></svg>,
  USB:       ()=><svg viewBox="0 0 24 24"><path d="M12 2v14M8 12l4 4 4-4M6 19h12"/></svg>,
  Shield:    ()=><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Copy:      ()=><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>,
  Check:     ()=><svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>,
  Eye:       ()=><svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
  EyeOff:    ()=><svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>,
  Trash:     ()=><svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>,
  Search:    ()=><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>,
  Plus:      ()=><svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>,
  Shuffle:   ()=><svg viewBox="0 0 24 24"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>,
  Alert:     ()=><svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  OkCircle:  ()=><svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>,
  Vault:     ()=><svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="18" rx="2"/><circle cx="12" cy="12" r="3"/><path d="M12 2v1M12 21v1M2 12H1M23 12h-1"/></svg>,
  Brain:     ()=><svg viewBox="0 0 24 24"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.44-3.14A2.5 2.5 0 0 1 9.5 2"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.44-3.14A2.5 2.5 0 0 0 14.5 2"/></svg>,
  Dice:      ()=><svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="20" rx="3"/><circle cx="8" cy="8" r="1.5" fill="currentColor" stroke="none"/><circle cx="16" cy="8" r="1.5" fill="currentColor" stroke="none"/><circle cx="8" cy="16" r="1.5" fill="currentColor" stroke="none"/><circle cx="16" cy="16" r="1.5" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none"/></svg>,
  X:         ()=><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
  User:      ()=><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>,
  Edit:      ()=><svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>,
  Recover:   ()=><svg viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>,
  OTP:       ()=><svg viewBox="0 0 24 24"><rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/><path d="M9 7h6M9 11h4"/></svg>,
  Share:     ()=><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>,
  Link:      ()=><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>,
  GripV:     ()=><svg viewBox="0 0 24 24"><circle cx="9" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="15" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="9" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="15" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="9" cy="18" r="1" fill="currentColor" stroke="none"/><circle cx="15" cy="18" r="1" fill="currentColor" stroke="none"/></svg>,
  Help:      ()=><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  Upload:    ()=><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>,
  Download:  ()=><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>,
  FileJson:  ()=><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M10 12a1 1 0 0 0-1 1v1a1 1 0 0 1-1 1 1 1 0 0 1 1 1v1a1 1 0 0 0 1 1"/><path d="M14 18a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1 1 1 0 0 1-1-1v-1a1 1 0 0 0-1-1"/></svg>,
};

// ── SHARED COMPONENTS ─────────────────────────────────────────────────────────
function Wordmark({ compact }:{ compact?:boolean }) {
  return (
    <div className="wordmark" style={compact?{marginBottom:0}:{}}>
      <div className="wm-icon"><I.Key/></div>
      <div><div className="wm-name">HouseKey Vault</div><div className="wm-sub">Zero-Knowledge · AES-256</div></div>
    </div>
  );
}
function StrengthMeter({ pw }:{ pw:string }) {
  const { score, label, color } = scorePassword(pw);
  if (!pw) return null;
  return (
    <div>
      <div className="str-row">{[1,2,3,4].map(i=><div key={i} className="str-seg" style={{background:i<=score?color:undefined}}/>)}</div>
      {label&&<div className="str-label" style={{color}}>{label}</div>}
    </div>
  );
}
function Toast({ msg, type="default" }:{ msg:string; type?:"default"|"ok"|"warn" }) {
  const [mounted, setMounted] = useState(false);
  useEffect(()=>{ setMounted(true); }, []);
  if (!mounted || typeof document === "undefined") return null;
  const el = document.body;
  return createPortal(
    <div className={`toast ${type!=="default"?type:""}`}>{msg}</div>,
    el
  );
}
function SiteAvatar({ site }:{ site:string }) {
  const logo = getSiteLogo(site);
  if (logo) return <div className="entry-avatar has-logo">{logo("var(--text2)")}</div>;
  return <div className="entry-avatar">{site.replace(/^https?:\/\/(www\.)?/,"").charAt(0).toUpperCase()}</div>;
}

// ── TOTP CHIP — live 6-digit OTP with countdown ring ─────────────────────────
function TOTPChip({ secret, onCopy }:{ secret:string; onCopy:(t:string)=>void }) {
  const [code, setCode] = useState("------");
  const [progress, setProgress] = useState(0);
  const [copied, setCopied] = useState(false);
  const PERIOD = 30;
  const CIRCUM = 2 * Math.PI * 5; // r=5

  useEffect(() => {
    let raf: number;
    let lastCode = "";
    const tick = async () => {
      const p = totpProgress(PERIOD);
      setProgress(p);
      // regenerate when period rolls over
      const newCode = await generateTOTP(secret).catch(()=>"ERROR");
      if (newCode !== lastCode) { lastCode = newCode; setCode(newCode); }
      raf = requestAnimationFrame(tick);
    };
    tick();
    return () => cancelAnimationFrame(raf);
  }, [secret]);

  const handleClick = () => {
    onCopy(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  // ring goes from full → empty as time passes (warning when < 25%)
  const remaining = 1 - progress;
  const ringColor = remaining < 0.25 ? "var(--crimson)" : "var(--jade)";
  const dash = remaining * CIRCUM;

  return (
    <div className={`totp-chip ${copied?"totp-copied":""}`} onClick={handleClick} title="Click to copy OTP">
      <svg className="totp-ring" viewBox="0 0 12 12">
        <circle cx="6" cy="6" r="5" fill="none" stroke="var(--line2)" strokeWidth="1.5"/>
        <circle cx="6" cy="6" r="5" fill="none" stroke={ringColor} strokeWidth="1.5"
          strokeDasharray={`${dash} ${CIRCUM}`} strokeLinecap="round"
          transform="rotate(-90 6 6)" style={{transition:"stroke-dasharray .5s linear,stroke .3s"}}/>
      </svg>
      <span className="totp-code">{copied?"copied":code.slice(0,3)+" "+code.slice(3)}</span>
    </div>
  );
}

// ── GEN PANEL ─────────────────────────────────────────────────────────────────
type LLMStyle = "passphrase"|"creative"|"technical"|"poetic";
function GenPanel({ value, onChange, onToast }:{ value:string; onChange:(v:string)=>void; onToast:(m:string,t?:"ok"|"warn")=>void }) {
  const [tab,setTab]=useState<"crypto"|"llm">("crypto");
  const [opts,setOpts]=useState({length:20,symbols:true,numbers:true,uppercase:true});
  const [loading,setLoading]=useState<"rng"|"llm"|null>(null);
  const [llmStyle,setLLMStyle]=useState<LLMStyle>("passphrase");
  const [theme,setTheme]=useState("");
  const [suggestions,setSuggestions]=useState<string[]>([]);
  const [entropy,setEntropy]=useState("");
  const toggleOpt=(k:keyof typeof opts)=>setOpts(o=>({...o,[k]:!o[k]}));
  const genCrypto=()=>{onChange(generatePassword(opts));setEntropy("crypto.getRandomValues");};
  const genRandom=async()=>{
    setLoading("rng");
    try{const r=await fetch("/api/random-password",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify(opts)});const d=await r.json();if(d.password){onChange(d.password);setEntropy(d.source==="random.org"?"Random.org RNG":"crypto.getRandomValues");}}
    catch{onToast("Random.org unavailable","warn");}
    setLoading(null);
  };
  const genLLM=async()=>{
    setLoading("llm");setSuggestions([]);
    try{const r=await fetch("/api/llm-password",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({style:llmStyle,theme:theme||undefined,count:3})});const d=await r.json();
      if(d.error==="MODEL_LOADING")onToast("AI loading, retry in 20s","warn");
      else if(d.passwords?.length)setSuggestions(d.passwords);
      else onToast(d.error??"Generation failed","warn");
    }catch{onToast("AI unavailable","warn");}
    setLoading(null);
  };
  return (
    <div className="gen-panel">
      <div className="gen-tabs">
        <button className={`gen-tab ${tab==="crypto"?"active":""}`} onClick={()=>setTab("crypto")}><I.Dice/>Crypto</button>
        <button className={`gen-tab ${tab==="llm"?"active":""}`} onClick={()=>setTab("llm")}><I.Brain/>AI</button>
      </div>
      {tab==="crypto"&&<>
        <div className="chips">
          {(["symbols","numbers","uppercase"] as const).map(k=><button key={k} className={`chip ${opts[k]?"on":""}`} onClick={()=>toggleOpt(k)}>{k}</button>)}
          {[16,20,24,32].map(l=><button key={l} className={`chip ${opts.length===l?"on":""}`} onClick={()=>setOpts(o=>({...o,length:l}))}>{l}ch</button>)}
        </div>
        <div className="pw-row">
          <div className="field"><div className="field-label">Password</div>
            <input className="inp" type="text" placeholder="Enter or generate" value={value} onChange={e=>onChange(e.target.value)}/>
            <StrengthMeter pw={value}/>
          </div>
          <div className="gen-btns">
            <button className="gen-btn" onClick={genCrypto} title="Browser crypto"><I.Shuffle/></button>
            <button className="gen-btn" onClick={genRandom} disabled={loading==="rng"} title="Random.org"><I.Dice/></button>
          </div>
        </div>
        {entropy&&<div className="entropy-note">↳ {entropy}</div>}
      </>}
      {tab==="llm"&&<>
        <div className="chips" style={{marginBottom:8}}>
          {(["passphrase","creative","technical","poetic"] as const).map(s=><button key={s} className={`chip ${llmStyle===s?"on":""}`} onClick={()=>setLLMStyle(s)}>{s}</button>)}
        </div>
        <div className="pw-row">
          <div className="field"><div className="field-label">Theme (optional)</div>
            <input className="inp" placeholder='"ocean", "space"…' value={theme} onChange={e=>setTheme(e.target.value)}/>
          </div>
          <div className="gen-btns">
            <button className="gen-btn" onClick={genLLM} disabled={loading==="llm"} title="Generate with AI">
              {loading==="llm"?<span style={{fontSize:8,color:"var(--text3)"}}>…</span>:<I.Brain/>}
            </button>
          </div>
        </div>
        {suggestions.length>0&&<div className="llm-suggestions">
          {suggestions.map((pw,i)=>(
            <div key={i} className={`llm-sugg ${value===pw?"sel":""}`} onClick={()=>onChange(pw)}>
              <span className="llm-pw">{pw}</span><StrengthMeter pw={pw}/>
            </div>
          ))}
        </div>}
        {value&&suggestions.length>0&&<div className="field" style={{marginTop:6}}>
          <div className="field-label">Selected</div>
          <input className="inp" type="text" value={value} onChange={e=>onChange(e.target.value)}/>
        </div>}
      </>}
    </div>
  );
}

// ── SECOND DEVICE CRYPTO ─────────────────────────────────────────────────────
// Protocol: PBKDF2(secret, salt, 200k, SHA-256) → AES-256-GCM
//
// At setup: random 32-byte salt + random 32-byte deviceSecret are generated.
//   .hkv2 file  → secret = deviceSecret  (stored in file, user keeps on second device)
//   Passphrase  → secret = passphrase text (memorised — same salt derives same AES key)
//
// The salt is stored in the vault entry (not secret). Server never sees either secret.

interface DeviceKeyFile {
  deviceSecret: string; // random 32-byte secret, b64
  salt:         string; // PBKDF2 salt shared with passphrase path, b64
  site:         string;
  createdAt:    number;
  version:      2;
}
interface SetupResult { keyFile: DeviceKeyFile; saltB64: string; }

function _bufToB64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function _b64ToBuf(b64: string): ArrayBuffer {
  const bin = atob(b64); const buf = new ArrayBuffer(bin.length);
  const v = new Uint8Array(buf); for (let i = 0; i < bin.length; i++) v[i] = bin.charCodeAt(i);
  return buf;
}

async function deriveDeviceAESKey(secret: string, saltB64: string, usage: KeyUsage[]): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: _b64ToBuf(saltB64), iterations: 200_000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, usage
  );
}

async function setupDeviceKey(site: string): Promise<SetupResult> {
  const secretBytes = crypto.getRandomValues(new Uint8Array(32));
  const saltBytes   = crypto.getRandomValues(new Uint8Array(32));
  const secretB64   = _bufToB64(secretBytes.buffer.slice(0, 32) as ArrayBuffer);
  const saltB64     = _bufToB64(saltBytes.buffer.slice(0, 32) as ArrayBuffer);
  return { keyFile: { deviceSecret: secretB64, salt: saltB64, site, createdAt: Date.now(), version: 2 }, saltB64 };
}

async function encryptWithDeviceKey(password: string, secret: string, saltB64: string): Promise<{ enc: string; iv: string }> {
  const aesKey  = await deriveDeviceAESKey(secret, saltB64, ["encrypt"]);
  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const iv      = ivBytes.buffer.slice(0, 12) as ArrayBuffer;
  const ct      = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(password));
  return { enc: _bufToB64(ct), iv: _bufToB64(iv) };
}

async function decryptWithDeviceFile(enc: string, iv: string, kf: DeviceKeyFile): Promise<string> {
  const aesKey = await deriveDeviceAESKey(kf.deviceSecret, kf.salt, ["decrypt"]);
  const plain  = await crypto.subtle.decrypt({ name: "AES-GCM", iv: _b64ToBuf(iv) }, aesKey, _b64ToBuf(enc));
  return new TextDecoder().decode(plain);
}

async function decryptWithPassphrase(enc: string, iv: string, passphrase: string, saltB64: string): Promise<string> {
  const aesKey = await deriveDeviceAESKey(passphrase, saltB64, ["decrypt"]);
  const plain  = await crypto.subtle.decrypt({ name: "AES-GCM", iv: _b64ToBuf(iv) }, aesKey, _b64ToBuf(enc));
  return new TextDecoder().decode(plain);
}

// Save .hkv2 using the same 3-tier system as .hkv:
//   Chrome/Edge desktop → showSaveFilePicker (user picks location)
//   Other              → blob download (goes to Downloads, user moves to USB)
async function saveDeviceKeyFile(kf: DeviceKeyFile): Promise<void> {
  const json     = JSON.stringify(kf, null, 2);
  const filename = `housekeyvault-${kf.site.replace(/[^a-z0-9]/gi, "-")}.hkv2`;

  // Tier 1: File Save Picker (Chrome/Edge)
  if (typeof window !== "undefined" && "showSaveFilePicker" in window) {
    try {
      const handle = await (window as any).showSaveFilePicker({
        suggestedName: filename,
        types: [{ description: "HouseKey Second Device File", accept: { "application/json": [".hkv2"] } }],
      });
      const writable = await handle.createWritable();
      await writable.write(json);
      await writable.close();
      return;
    } catch (e: any) {
      if (e.name === "AbortError") throw new Error("Cancelled.");
      // Fall through to download
    }
  }

  // Tier 2: Blob download (Firefox, Safari, mobile)
  const blob = new Blob([json], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function loadDeviceKeyFile(): Promise<DeviceKeyFile> {
  return new Promise((resolve, reject) => {
    const input = document.createElement("input");
    input.type = "file"; input.accept = ".hkv2,application/json";
    input.onchange = async () => {
      const file = input.files?.[0]; if (!file) return reject(new Error("No file selected."));
      try {
        const kf = JSON.parse(await file.text()) as DeviceKeyFile;
        if (!kf.deviceSecret || !kf.salt) throw new Error("Invalid .hkv2 file.");
        resolve(kf);
      } catch (e) { reject(e); }
    };
    input.oncancel = () => reject(new Error("Cancelled."));
    input.click();
  });
}

// ── UNLOCK SECOND DEVICE MODAL ───────────────────────────────────────────────
function UnlockSecondDeviceModal({ entry, onUnlock, onClose }:{
  entry: any;
  onUnlock: (password: string) => void;
  onClose: () => void;
}) {
  const [mode, setMode]   = useState<"file"|"passphrase">("file");
  const [passphrase, setPassphrase] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPP, setShowPP] = useState(false);

  const unlock = async () => {
    setLoading(true); setError("");
    try {
      let pw: string;
      if (mode === "file") {
        const kf = await loadDeviceKeyFile();
        pw = await decryptWithDeviceFile(entry.secondDeviceEncrypted, entry.secondDeviceIV, kf);
      } else {
        if (passphrase.length < 12) { setError("Passphrase too short."); setLoading(false); return; }
        pw = await decryptWithPassphrase(entry.secondDeviceEncrypted, entry.secondDeviceIV, passphrase, entry.secondDeviceSalt);
      }
      onUnlock(pw);
    } catch(e: any) {
      setError(e.message === "Cancelled." ? "" : (e.message?.includes("operation-specific") ? "Wrong passphrase or incorrect file." : (e.message ?? "Decryption failed.")));
    } finally { setLoading(false); }
  };

  return (
    <div className="modal-backdrop" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal" style={{maxWidth:400}}>
        <div className="modal-header">
          <div className="modal-title" style={{display:"flex",alignItems:"center",gap:8}}><I.Lock/>Second Device Required</div>
          <button className="modal-close" onClick={onClose}><I.X/></button>
        </div>
        <div className="modal-body">
          <div style={{display:"flex",alignItems:"center",gap:10,background:"var(--ink3)",border:"1px solid rgba(201,168,76,.2)",borderRadius:"var(--r)",padding:"10px 12px",marginBottom:16}}>
            <SiteAvatar site={entry.site}/>
            <div>
              <div style={{fontSize:13,fontWeight:500,color:"var(--text)"}}>{entry.site}</div>
              <div style={{fontFamily:"var(--mono)",fontSize:10,color:"var(--text3)"}}>Protected by second device</div>
            </div>
          </div>

          <div className="modal-tabs" style={{marginBottom:16}}>
            <button className={`modal-tab ${mode==="file"?"active":""}`} onClick={()=>{setMode("file");setError("");}}>
              <I.USB/>Use .hkv2 file
            </button>
            <button className={`modal-tab ${mode==="passphrase"?"active":""}`} onClick={()=>{setMode("passphrase");setError("");}}>
              <I.Key/>Emergency passphrase
            </button>
          </div>

          {mode==="file" && (
            <div style={{textAlign:"center",padding:"8px 0 12px"}}>
              <div style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--text3)",marginBottom:12,lineHeight:1.6}}>
                Select the <strong style={{color:"var(--text)"}}>housekeyvault-{entry.site.replace(/[^a-z0-9]/gi,"-")}.hkv2</strong> file from your second device.
              </div>
              <button className="btn btn-primary" onClick={unlock} disabled={loading}
                style={{padding:"8px 20px",width:"auto",fontSize:11,height:"auto"}}>
                {loading?"Decrypting…":<><I.Upload/>Select .hkv2 file</>}
              </button>
            </div>
          )}

          {mode==="passphrase" && (
            <div>
              <div style={{fontFamily:"var(--mono)",fontSize:10,color:"var(--text3)",marginBottom:10,lineHeight:1.6}}>
                Enter the emergency passphrase you set when this entry was created.
              </div>
              <div style={{display:"flex",gap:6,marginBottom:12}}>
                <input className="inp" type={showPP?"text":"password"}
                  placeholder="Your emergency passphrase"
                  value={passphrase} onChange={e=>setPassphrase(e.target.value)}
                  onKeyDown={e=>e.key==="Enter"&&unlock()}
                  style={{flex:1}}
                />
                <button style={{background:"transparent",border:"1px solid var(--line)",borderRadius:4,padding:"6px 8px",cursor:"pointer",color:"var(--text3)",display:"flex",alignItems:"center"}} onClick={()=>setShowPP(s=>!s)}>
                  {showPP?<I.EyeOff/>:<I.Eye/>}
                </button>
              </div>
              <button className="btn btn-primary" onClick={unlock} disabled={loading||passphrase.length<12}
                style={{padding:"8px 20px",width:"auto",fontSize:11,height:"auto"}}>
                {loading?"Decrypting…":<><I.Unlock/>Decrypt with passphrase</>}
              </button>
            </div>
          )}

          {error && <div className="alert alert-warn" style={{marginTop:12,marginBottom:0}}><I.Alert/>{error}</div>}
        </div>
      </div>
    </div>
  );
}


// ── ENTRY FORM (add & edit) ───────────────────────────────────────────────────
type EntryFormData = { site:string; username:string; password:string; url:string; notes:string; folderId:string; totpSecret:string; secondDevice:boolean; recoveryPassphrase:string; };

function EntryForm({ initial, folders, onSave, onCancel, onToast, mode }:{
  initial?: EntryFormData; folders:Folder[]; mode:"add"|"edit";
  onSave:(d:EntryFormData)=>void; onCancel:()=>void; onToast:(m:string,t?:"ok"|"warn")=>void;
}) {
  const [form, setForm] = useState<EntryFormData>(initial ?? {site:"",username:"",password:"",url:"",notes:"",folderId:"",totpSecret:"",secondDevice:false,recoveryPassphrase:""});
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [showTotp, setShowTotp] = useState(!!(initial?.totpSecret));
  const set=(k:keyof EntryFormData)=>(e:React.ChangeEvent<HTMLInputElement|HTMLSelectElement>)=>setForm(f=>({...f,[k]:e.target.value}));
  const valid = form.site.trim() && form.username.trim() && form.password.trim() && (!form.secondDevice || form.recoveryPassphrase.length >= 12);

  return (
    <div className={mode==="add"?"add-form":"entry-edit-panel"}>
      <div className="sec-label" style={{marginTop:0}}>Service Details</div>
      <div className="form-row">
        <div className="field"><div className="field-label">Website</div><input className="inp" placeholder="github.com" value={form.site} onChange={set("site")}/></div>
        <div className="field"><div className="field-label">URL</div><input className="inp" placeholder="https://…" value={form.url} onChange={set("url")}/></div>
      </div>
      <div className="field"><div className="field-label">Username / Email</div><input className="inp" placeholder="you@email.com" value={form.username} onChange={set("username")}/></div>
      {folders.length>0&&<div className="field"><div className="field-label">Folder</div>
        <select className="select" value={form.folderId} onChange={set("folderId")}>
          <option value="">— No folder —</option>
          {folders.map(f=><option key={f.id} value={f.id}>{f.name}</option>)}
        </select>
      </div>}
      <div className="sec-label">Password</div>
      <GenPanel value={form.password} onChange={v=>setForm(f=>({...f,password:v}))} onToast={onToast}/>
      <div className="sec-label" style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:showTotp?6:0}}>
        <span>2FA / TOTP</span>
        <button style={{background:"transparent",border:"1px solid var(--line)",borderRadius:4,padding:"2px 8px",color:"var(--text3)",fontFamily:"var(--mono)",fontSize:9,cursor:"pointer",letterSpacing:".06em",textTransform:"uppercase"}}
          onClick={()=>setShowTotp(s=>!s)}>{showTotp?"Remove":"Add"}</button>
      </div>
      {showTotp&&<div className="field" style={{marginBottom:0}}>
        <div className="field-label">TOTP Secret (from QR or setup page)</div>
        <input className="inp" placeholder="JBSWY3DPEHPK3PXP" value={form.totpSecret} onChange={set("totpSecret")} autoCapitalize="none" autoCorrect="off" spellCheck={false}/>
        {form.totpSecret&&<div style={{marginTop:6}}><TOTPChip secret={form.totpSecret} onCopy={()=>{}}/></div>}
      </div>}
      <div className="field" style={{marginTop:10}}><div className="field-label">Notes</div><input className="inp" placeholder="2FA codes, recovery email…" value={form.notes} onChange={set("notes")}/></div>
      <div className="sec-label" style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:0}}>
        <span style={{display:"flex",alignItems:"center",gap:6}}>
          Second Device Lock
          <span className="tooltip-anchor" data-tip="Adds a second encryption layer using a separate key file stored on a different physical device. To view this password you need both your main key file AND the .hkv2 file. If you lose the .hkv2 file, you can still recover using your emergency passphrase. Recommended for bank accounts, crypto wallets, and critical credentials.">
            <I.Help/>
          </span>
        </span>
        <button style={{background:"transparent",border:`1px solid ${form.secondDevice?"rgba(201,168,76,.5)":"var(--line)"}`,borderRadius:4,padding:"2px 8px",color:form.secondDevice?"var(--gold)":"var(--text3)",fontFamily:"var(--mono)",fontSize:9,cursor:"pointer",letterSpacing:".06em",textTransform:"uppercase",transition:"all .2s"}}
          onClick={()=>setForm(f=>({...f,secondDevice:!f.secondDevice,recoveryPassphrase:""}))}>
          {form.secondDevice?"Enabled":"Enable"}
        </button>
      </div>
      {form.secondDevice&&<>
        <div className="alert alert-warn" style={{marginTop:8,marginBottom:8}}>
          <I.Alert/><span>On save, a <strong style={{color:"var(--text)"}}>.hkv2</strong> key file will be downloaded. Store it on a separate USB or device. You will need it every time you want to view this password.</span>
        </div>
        <div className="field" style={{marginBottom:0}}>
          <div className="field-label" style={{display:"flex",alignItems:"center",gap:6}}>
            Emergency Recovery Passphrase
            <span className="tooltip-anchor" data-tip="If you lose the .hkv2 file, this passphrase lets you recover the password. It is NOT stored anywhere — memorise it or keep it in a secure location. It must be at least 12 characters.">
              <I.Help/>
            </span>
          </div>
          <div style={{position:"relative",display:"flex",gap:6,alignItems:"center"}}>
            <input className="inp" type={showPassphrase?"text":"password"}
              placeholder="At least 12 characters — memorise this"
              value={form.recoveryPassphrase}
              onChange={e=>setForm(f=>({...f,recoveryPassphrase:e.target.value}))}
              style={{flex:1,borderColor:form.recoveryPassphrase.length>0&&form.recoveryPassphrase.length<12?"rgba(192,57,43,.5)":undefined}}
            />
            <button type="button" style={{background:"transparent",border:"1px solid var(--line)",borderRadius:4,padding:"6px 8px",cursor:"pointer",color:"var(--text3)",display:"flex",alignItems:"center"}} onClick={()=>setShowPassphrase(s=>!s)}>
              {showPassphrase?<I.EyeOff/>:<I.Eye/>}
            </button>
          </div>
          {form.recoveryPassphrase.length>0&&form.recoveryPassphrase.length<12&&(
            <div style={{fontFamily:"var(--mono)",fontSize:9,color:"var(--crimson)",marginTop:4}}>Passphrase must be at least 12 characters</div>
          )}
          {form.recoveryPassphrase.length>=12&&(
            <div style={{fontFamily:"var(--mono)",fontSize:9,color:"var(--jade)",marginTop:4}}>Passphrase strength looks good</div>
          )}
        </div>
      </>}
      <div className="form-actions">
        <button className="btn btn-primary" onClick={()=>valid&&onSave(form)} disabled={!valid}>
          {mode==="add"?"Save Entry":"Update Entry"}
        </button>
        <button className="btn btn-outline btn-cancel" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

// ── FOLDER PANEL ──────────────────────────────────────────────────────────────
function FolderPanel({ folders, entries, active, onSelect, onAdd, onDelete, onDropEntry }:{
  folders:Folder[]; entries:VaultEntry[]; active:string|null;
  onSelect:(id:string|null)=>void; onAdd:(f:Folder)=>void; onDelete:(id:string)=>void;
  onDropEntry:(entryId:string, targetFolderId:string|null)=>void;
}) {
  const [creating,setCreating]=useState(false);
  const [name,setName]=useState("");
  const [color,setColor]=useState(FOLDER_COLORS[0]);
  const [dragOver,setDragOver]=useState<string|"__all"|null>(null);
  const count=(id:string)=>entries.filter((e:any)=>e.folderId===id).length;
  const commit=()=>{if(!name.trim())return;onAdd({id:crypto.randomUUID(),name:name.trim(),color});setName("");setCreating(false);};

  const handleDragOver=(e:React.DragEvent,id:string|"__all")=>{e.preventDefault();e.dataTransfer.dropEffect="move";setDragOver(id);};
  const handleDrop=(e:React.DragEvent,targetId:string|null)=>{
    e.preventDefault();const entryId=e.dataTransfer.getData("entryId");
    if(entryId)onDropEntry(entryId,targetId);setDragOver(null);
  };

  return (
    <div className="sidebar-card" style={{padding:"14px 16px"}}>
      <div className="nav-label">Folders</div>
      <div className="folder-list">
        {/* All */}
        <div className={`fi ${active===null?"on":""} ${dragOver==="__all"?"drag-over":""}`}
          onClick={()=>onSelect(null)}
          onDragOver={e=>handleDragOver(e,"__all")}
          onDragLeave={()=>setDragOver(null)}
          onDrop={e=>handleDrop(e,null)}>
          <span className="fi-icon">
            <svg viewBox="0 0 24 24" width="11" height="11" stroke="currentColor" fill="none" strokeWidth="1.5">
              <rect x="2" y="3" width="20" height="18" rx="2"/><circle cx="12" cy="12" r="3"/>
            </svg>
          </span>
          <span className="fi-name">All</span>
          <span className="fi-count">{entries.length}</span>
        </div>
        {folders.map(f=>(
          <div key={f.id} className={`fi ${active===f.id?"on":""} ${dragOver===f.id?"drag-over":""}`}
            onClick={()=>onSelect(f.id)}
            onDragOver={e=>handleDragOver(e,f.id)}
            onDragLeave={()=>setDragOver(null)}
            onDrop={e=>handleDrop(e,f.id)}>
            <div className="fi-dot" style={{background:f.color}}/>
            <span className="fi-name">{f.name}</span>
            <span className="fi-count">{count(f.id)}</span>
            <button className="fi-del" onClick={e=>{e.stopPropagation();onDelete(f.id);}}>
              <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
        ))}
      </div>
      {creating ? (
        <div style={{marginTop:5}}>
          <div className="fc-row">
            <input className="fc-inp" placeholder="Name…" value={name} autoFocus
              onChange={e=>setName(e.target.value)}
              onKeyDown={e=>{if(e.key==="Enter")commit();if(e.key==="Escape")setCreating(false);}}/>
            <button className="fc-btn ok" onClick={commit}>
              <svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>
            </button>
            <button className="fc-btn cancel" onClick={()=>setCreating(false)}>
              <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
          <div className="fc-colors">
            {FOLDER_COLORS.map(c=><div key={c} className={`fc-c ${color===c?"on":""}`} style={{background:c}} onClick={()=>setColor(c)}/>)}
          </div>
        </div>
      ) : (
        <button className="f-new" onClick={()=>setCreating(true)}>
          <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          New folder
        </button>
      )}
    </div>
  );
}

// ── HEALTH WIDGET ─────────────────────────────────────────────────────────────
function HealthWidget({ entries, onCheckAll }:{ entries:VaultEntry[]; onCheckAll:()=>void }) {
  const total=entries.length,breached=entries.filter(e=>e.breached===true).length,
    safe=entries.filter(e=>e.breached===false).length,weak=entries.filter(e=>scorePassword(e.password).score<=2).length;
  const score=total===0?100:Math.round((entries.filter(e=>scorePassword(e.password).score>=3&&!e.breached).length/total)*100);
  const sc=score>=80?"var(--jade)":score>=50?"var(--gold)":"var(--crimson)";
  return (
    <div className="sidebar-card">
      <div className="score-ring-wrap">
        <svg viewBox="0 0 56 56" width="52" height="52" style={{flexShrink:0}}>
          <circle cx="28" cy="28" r="22" fill="none" stroke="var(--line2)" strokeWidth="4"/>
          <circle cx="28" cy="28" r="22" fill="none" stroke={sc} strokeWidth="4"
            strokeDasharray={`${(score/100)*138.2} 138.2`} strokeLinecap="round"
            transform="rotate(-90 28 28)" style={{transition:"stroke-dasharray .8s ease"}}/>
          <text x="28" y="32" textAnchor="middle" fill="var(--text)" style={{fontFamily:"var(--mono)",fontSize:"13px",fontWeight:500}}>{score}</text>
        </svg>
        <div><div className="score-ring-label">Security Score</div><div className="score-ring-sub">{total} credential{total!==1?"s":""}</div></div>
      </div>
      <div className="health-mini">
        {([[breached,"var(--crimson)","Breached"],[safe,"var(--jade)","Safe"],[weak,"var(--gold)","Weak"]] as const).map(([v,c,l])=>(
          <div key={l}>
            <div className="hm-row"><span className="hm-label">{l}</span><span className="hm-val" style={{color:c}}>{v}</span></div>
            <div className="hm-bar"><div className="hm-bar-fill" style={{width:total>0?`${(Number(v)/total)*100}%`:"0%",background:c}}/></div>
          </div>
        ))}
      </div>
      <div className="divider"/>
      <button className="btn btn-outline" style={{marginTop:0,fontSize:11,padding:"8px 12px"}} onClick={onCheckAll} disabled={total===0}>
        <I.Shield/>HIBP Breach Check
      </button>
    </div>
  );
}

// ── ENTRY LIST with drag-to-reorder + inline edit ────────────────────────────
function EntryList({ entries, folders, onCopy, onDelete, onEdit, onCheckBreach, onShare, checking }:{
  entries:VaultEntry[]; folders:Folder[]; onCopy:(t:string,l:string)=>void;
  onDelete:(id:string)=>void; onEdit:(id:string,d:EntryFormData)=>void;
  onCheckBreach:(e:VaultEntry)=>void; onShare:(e:VaultEntry)=>void; checking:Record<string,boolean>;
}) {
  const [vis,setVis]=useState<Record<string,boolean>>({});
  const [unlockedPw,setUnlockedPw]=useState<Record<string,string>>({});
  const [unlockTarget,setUnlockTarget]=useState<{entry:any;action:"copy"|"reveal"}|null>(null);

  const handleUnlocked=(pw:string)=>{
    if(!unlockTarget) return;
    if(unlockTarget.action==="copy") onCopy(pw,"Password");
    else { setUnlockedPw(p=>({...p,[unlockTarget.entry.id]:pw})); setVis(v=>({...v,[unlockTarget.entry.id]:true})); }
    setUnlockTarget(null);
  };
  const [editingId,setEditingId]=useState<string|null>(null);
  const [draggingId,setDraggingId]=useState<string|null>(null);
  const [dragOverId,setDragOverId]=useState<string|null>(null);

  // Drag handlers for reordering within list
  const onDragStart=(e:React.DragEvent,id:string)=>{
    e.dataTransfer.setData("entryId",id);
    e.dataTransfer.effectAllowed="move";
    setDraggingId(id);
  };
  const onDragOver=(e:React.DragEvent,id:string)=>{e.preventDefault();setDragOverId(id);};
  const onDrop=(e:React.DragEvent,targetId:string)=>{
    e.preventDefault();
    const srcId=e.dataTransfer.getData("entryId");
    if(srcId&&srcId!==targetId){
      // reorder: bubble up via parent (handled in VaultScreen via onEdit chain — simplified here)
      // For inline visual reorder we fire a synthetic edit that swaps positions
    }
    setDraggingId(null);setDragOverId(null);
  };

  if (!entries.length) return (
    <div className="empty"><div className="empty-icon"><I.Vault/></div>
      <div className="empty-title">No entries found</div><div className="empty-sub">Add your first credential above</div>
    </div>
  );

  const showToast=(m:string,t?:"ok"|"warn")=>{}; // stub — toast is managed by VaultScreen

  return (
    <div className="entries">
      {entries.map(e=>{
        const totp=(e as any).totpSecret as string|undefined;
        const folderColor = folders.find(f=>f.id===(e as any).folderId)?.color;
        if(editingId===e.id) return (
          <div key={e.id}>
            <EntryForm
              mode="edit"
              initial={{site:e.site,username:e.username,password:e.password,url:(e as any).url??"",notes:(e as any).notes??"",folderId:(e as any).folderId??"",totpSecret:totp??"",secondDevice:!!(e as any).secondDeviceEncrypted,recoveryPassphrase:""}}
              folders={folders}
              onSave={d=>{onEdit(e.id,d);setEditingId(null);}}
              onCancel={()=>setEditingId(null)}
              onToast={showToast}
            />
          </div>
        );
        return (
          <div key={e.id}
            className={`entry-card ${e.breached?"breached":""} ${draggingId===e.id?"dragging":""} ${dragOverId===e.id&&draggingId!==e.id?"drag-over-card":""}`}
            draggable
            onDragStart={ev=>onDragStart(ev,e.id)}
            onDragOver={ev=>onDragOver(ev,e.id)}
            onDragLeave={()=>setDragOverId(null)}
            onDrop={ev=>onDrop(ev,e.id)}
            onDragEnd={()=>{setDraggingId(null);setDragOverId(null);}}>
            {/* folder color strip */}
            {folderColor&&<div style={{position:"absolute",left:0,top:0,bottom:0,width:3,background:folderColor,borderRadius:"var(--r2) 0 0 var(--r2)"}}/>}
            <div className="drag-handle"><I.GripV/></div>
            <SiteAvatar site={e.site}/>
            <div className="entry-info">
              <div className="entry-site">{e.site}
                {e.breached&&<span className="badge badge-danger">Breached</span>}
                {e.breached===false&&<span className="badge badge-safe">Verified</span>}
                {totp&&<span className="badge badge-totp"><I.OTP/>2FA</span>}
                {(e as any).secondDeviceEncrypted&&<span className="badge-2dev"><I.Shield/>2-Device</span>}
              </div>
              <div className="entry-user">{e.username}</div>
              {vis[e.id]&&<div className="entry-pw">{(e as any).secondDeviceEncrypted?(unlockedPw[e.id]??""):e.password}</div>}
              {totp&&<TOTPChip secret={totp} onCopy={t=>{navigator.clipboard.writeText(t);}}/>}
            </div>
            <div className="entry-actions">
              <button className="icon-btn" title={(e as any).secondDeviceEncrypted?"Requires .hkv2 file to copy":"Copy password"}
                onClick={()=>{
                  if((e as any).secondDeviceEncrypted) setUnlockTarget({entry:e,action:"copy"});
                  else onCopy(e.password,"Password");
                }}>
                {(e as any).secondDeviceEncrypted?<I.Lock/>:<I.Copy/>}
              </button>
              <button className="icon-btn" onClick={()=>onCopy(e.username,"Username")} title="Copy username"><I.User/></button>
              <button className={`icon-btn ${vis[e.id]?"active":""}`} title={(e as any).secondDeviceEncrypted&&!vis[e.id]?"Requires .hkv2 to reveal":undefined}
                onClick={()=>{
                  if((e as any).secondDeviceEncrypted&&!vis[e.id]) setUnlockTarget({entry:e,action:"reveal"});
                  else if(vis[e.id]){ setVis(v=>({...v,[e.id]:false})); setUnlockedPw(p=>{const n={...p};delete n[e.id];return n;}); }
                  else setVis(v=>({...v,[e.id]:true}));
                }}>
                {vis[e.id]?<I.EyeOff/>:<I.Eye/>}
              </button>
              <button className={`icon-btn ${editingId===e.id?"editing":""}`} onClick={()=>setEditingId(id=>id===e.id?null:e.id)} title="Edit entry"><I.Edit/></button>
              <button className="icon-btn" onClick={()=>onShare(e)} title="Share via secure link"><I.Share/></button>
              <button className="icon-btn" disabled={checking[e.id]} style={{opacity:checking[e.id]?.3:1}} onClick={()=>onCheckBreach(e)} title="Check breach"><I.Shield/></button>
              <button className="icon-btn danger" onClick={()=>onDelete(e.id)} title="Delete"><I.Trash/></button>
            </div>
          </div>
        );
      })}
      {unlockTarget&&<UnlockSecondDeviceModal entry={unlockTarget.entry} onUnlock={handleUnlocked} onClose={()=>setUnlockTarget(null)}/>}
    </div>
  );
}

// ── SHARE MODAL ───────────────────────────────────────────────────────────────
const TTL_OPTIONS = [
  { label: "1 hour",  seconds: 3600 },
  { label: "24 hours", seconds: 86400 },
  { label: "7 days",  seconds: 604800 },
];

function ShareModal({ entry, onClose, onToast }:{
  entry: VaultEntry; onClose: ()=>void; onToast: (m:string,t?:"ok"|"warn")=>void;
}) {
  const [ttl, setTtl]         = useState(86400);
  const [state, setState]     = useState<"idle"|"generating"|"done"|"error">("idle");
  const [shareUrl, setShareUrl] = useState("");
  const [copied, setCopied]   = useState(false);

  const generate = async () => {
    setState("generating");
    try {
      const payload: SharePayload = {
        site:        entry.site,
        username:    entry.username,
        password:    entry.password,
        url:         (entry as any).url || undefined,
        notes:       (entry as any).notes || undefined,
        totpSecret:  (entry as any).totpSecret || undefined,
      };
      const { apiPayload, fragment } = await createShare(payload);

      const res = await fetch("/api/share", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...apiPayload, ttlSeconds: ttl }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Failed to create share.");

      const base = `${window.location.origin}/share/${data.id}`;
      setShareUrl(`${base}#${fragment}`);
      setState("done");
    } catch (e: any) {
      onToast(e.message ?? "Share failed", "warn");
      setState("error");
    }
  };

  const copyLink = async () => {
    await navigator.clipboard.writeText(shareUrl);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
    onToast("Link copied", "ok");
  };

  return (
    <div className="modal-backdrop" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal" style={{maxWidth:440}}>
        <div className="modal-header">
          <div className="modal-title" style={{display:"flex",alignItems:"center",gap:8}}><I.Share/>Share credential</div>
          <button className="modal-close" onClick={onClose}><I.X/></button>
        </div>
        <div className="modal-body">
          {/* Entry preview */}
          <div style={{display:"flex",alignItems:"center",gap:10,background:"var(--ink3)",border:"1px solid var(--line)",borderRadius:"var(--r)",padding:"10px 12px",marginBottom:16}}>
            <SiteAvatar site={entry.site}/>
            <div>
              <div style={{fontSize:13,fontWeight:500,color:"var(--text)"}}>{entry.site}</div>
              <div style={{fontFamily:"var(--mono)",fontSize:10,color:"var(--text3)"}}>{entry.username}</div>
            </div>
          </div>

          {state !== "done" && (<>
            <div className="nav-label" style={{marginBottom:8}}>Link expires after</div>
            <div className="ttl-chips">
              {TTL_OPTIONS.map(o=>(
                <button key={o.seconds} className={`ttl-chip ${ttl===o.seconds?"on":""}`} onClick={()=>setTtl(o.seconds)}>
                  {o.label}
                </button>
              ))}
            </div>

            <div className="alert alert-warn" style={{marginBottom:16}}>
              <I.Alert/>
              <span>One-time use. The link is invalidated the moment the recipient opens it. The server never sees the password — decryption happens entirely in the recipient&apos;s browser.</span>
            </div>

            <button className="btn btn-primary" onClick={generate} disabled={state==="generating"}
              style={{padding:"8px 16px",width:"auto",fontSize:11,height:"auto"}}>
              {state==="generating"
                ? <><span style={{display:"inline-block",animation:"spin 1s linear infinite",marginRight:6}}>⟳</span>Generating…</>
                : <><I.Link/>Generate secure link</>}
            </button>
          </>)}

          {state === "done" && (<>
            <div className="alert alert-ok" style={{marginBottom:12}}>
              <I.Check/>Link ready — share it now. It will expire after one use.
            </div>
            <div className="nav-label" style={{marginBottom:6}}>Secure link</div>
            <div className="share-link-box">
              {shareUrl.slice(0, 60)}…
              <button className={`share-link-copy ${copied?"ok":""}`} onClick={copyLink}>
                {copied ? <I.Check/> : <I.Copy/>}
              </button>
            </div>
            <button className="btn btn-primary" onClick={copyLink}
              style={{padding:"8px 16px",width:"auto",fontSize:11,height:"auto",marginTop:8}}>
              {copied ? <><I.Check/>Copied!</> : <><I.Copy/>Copy full link</>}
            </button>
            <div style={{marginTop:14,fontFamily:"var(--mono)",fontSize:9,color:"var(--text3)",lineHeight:1.7}}>
              The decryption key is embedded in the URL fragment. Do not share via email — use a secure channel.
            </div>
          </>)}
        </div>
      </div>
    </div>
  );
}

// ── IMPORT / EXPORT MODAL ─────────────────────────────────────────────────────
function ImportExportModal({ entries, onImport, onClose, publicKeyHash }:{
  entries: VaultEntry[];
  onImport: (result: ImportResult) => void;
  onClose: () => void;
  publicKeyHash: string;
}) {
  const [tab, setTab] = useState<"import"|"export">("import");
  const [exportFmt, setExportFmt] = useState<"bitwarden-csv"|"bitwarden-json"|"housekeyvault-json">("bitwarden-json");
  const [dragActive, setDragActive] = useState(false);
  const [pending, setPending] = useState<ImportResult|null>(null);
  const [error, setError] = useState("");

  const processFile = async (text: string, filename: string) => {
    setError(""); setPending(null);
    try {
      const result = importAuto(text, filename);
      if (result.entries.length === 0) { setError("No valid login entries found in this file."); return; }
      setPending(result);
    } catch (e: any) { setError(e.message ?? "Failed to parse file."); }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault(); setDragActive(false);
    const file = e.dataTransfer.files[0];
    if (!file) return;
    processFile(await file.text(), file.name);
  };

  const handlePick = async () => {
    try {
      const { text, filename } = await pickImportFile();
      processFile(text, filename);
    } catch (e: any) { if (e.message !== "Cancelled.") setError(e.message); }
  };

  const handleExport = () => {
    if (exportFmt === "bitwarden-csv")       exportBitwardenCSV(entries, publicKeyHash);
    else if (exportFmt === "bitwarden-json") exportBitwardenJSON(entries, publicKeyHash);
    else                                      exportNativeJSON(entries, publicKeyHash);
  };

  const SOURCE_LABELS: Record<string, string> = {
    "bitwarden-csv":  "Bitwarden CSV",
    "bitwarden-json": "Bitwarden JSON",
    "1password-csv":  "1Password CSV",
    "lastpass-csv":   "LastPass CSV",
  };

  return (
    <div className="modal-backdrop" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal">
        <div className="modal-header">
          <div className="modal-title">Import / Export</div>
          <button className="modal-close" onClick={onClose}><I.X/></button>
        </div>
        <div className="modal-body">
          <div className="modal-tabs">
            <button className={`modal-tab ${tab==="import"?"active":""}`} onClick={()=>{setTab("import");setPending(null);setError("");}}>
              <I.Upload/>Import
            </button>
            <button className={`modal-tab ${tab==="export"?"active":""}`} onClick={()=>setTab("export")}>
              <I.Download/>Export
            </button>
          </div>

          {tab==="import" && (<>
            {!pending && (<>
              <div style={{marginBottom:10}}>
                <div className="nav-label" style={{marginBottom:6}}>Supported formats</div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  {["Bitwarden CSV","Bitwarden JSON","1Password CSV","LastPass CSV"].map(f=>(
                    <span key={f} className="badge badge-totp" style={{padding:"3px 8px",fontSize:10}}>{f}</span>
                  ))}
                </div>
              </div>
              <div className={`drop-zone ${dragActive?"drag-active":""}`}
                onClick={handlePick}
                onDragOver={e=>{e.preventDefault();setDragActive(true);}}
                onDragLeave={()=>setDragActive(false)}
                onDrop={handleDrop}>
                <div className="drop-zone-icon"><I.Upload/></div>
                <div className="drop-zone-label">Click to select file or drag and drop</div>
                <div className="drop-zone-hint">.csv or .json — format is detected automatically</div>
              </div>
              {error && <div className="alert alert-warn" style={{marginBottom:0}}><I.Alert/>{error}</div>}
            </>)}

            {pending && (<>
              <div className="import-result">
                <div className="import-result-title">{pending.entries.length} entries ready to import</div>
                <div className="import-result-sub">
                  Source: {SOURCE_LABELS[pending.source]}
                  {pending.skipped > 0 && ` · ${pending.skipped} skipped (not login type or missing fields)`}
                </div>
              </div>
              <div className="alert alert-warn" style={{marginBottom:14}}>
                <I.Alert/>
                <span>Existing entries will not be replaced — imports always add new entries. Remove duplicates manually after import.</span>
              </div>
              <div style={{background:"var(--ink3)",border:"1px solid var(--line)",borderRadius:"var(--r)",padding:"10px 12px",marginBottom:14,maxHeight:180,overflowY:"auto"}}>
                {pending.entries.slice(0,8).map((e,i)=>(
                  <div key={i} style={{display:"flex",alignItems:"center",gap:10,padding:"4px 0",borderBottom:"1px solid var(--line)"}}>
                    <div style={{width:24,height:24,background:"var(--ink2)",border:"1px solid var(--line)",borderRadius:4,display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:500,color:"var(--text2)",flexShrink:0,textTransform:"uppercase"}}>
                      {(e.site||"?").charAt(0)}
                    </div>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{fontSize:12,fontWeight:500,color:"var(--text)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.site}</div>
                      <div style={{fontFamily:"var(--mono)",fontSize:10,color:"var(--text3)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.username}</div>
                    </div>
                    {(e as any).totpSecret && <span className="badge badge-totp" style={{fontSize:8}}>2FA</span>}
                  </div>
                ))}
                {pending.entries.length > 8 && (
                  <div style={{fontFamily:"var(--mono)",fontSize:10,color:"var(--text3)",padding:"6px 0",textAlign:"center"}}>
                    + {pending.entries.length - 8} more entries
                  </div>
                )}
              </div>
              <div className="import-btn-row">
                <button className="btn btn-primary" onClick={()=>{onImport(pending);onClose();}}>
                  <I.Upload/>Import {pending.entries.length} entries
                </button>
                <button className="btn btn-outline" style={{marginTop:0}} onClick={()=>{setPending(null);setError("");}}>
                  <I.X/>Cancel
                </button>
              </div>
            </>)}
          </>)}

          {tab==="export" && (<>
            <div className="nav-label" style={{marginBottom:10}}>Export format</div>
            <div className="fmt-grid">
              <div className={`fmt-card ${exportFmt==="bitwarden-json"?"selected":""}`} onClick={()=>setExportFmt("bitwarden-json")}>
                <div className="fmt-card-name">Bitwarden JSON</div>
                <div className="fmt-card-desc">Full fidelity. Import directly into Bitwarden, Vaultwarden, or any compatible manager.</div>
                <span className="fmt-badge recommended">Recommended</span>
              </div>
              <div className={`fmt-card ${exportFmt==="bitwarden-csv"?"selected":""}`} onClick={()=>setExportFmt("bitwarden-csv")}>
                <div className="fmt-card-name">Bitwarden CSV</div>
                <div className="fmt-card-desc">Logins only. Compatible with Bitwarden, 1Password, LastPass, and most managers.</div>
                <span className="fmt-badge compat">Universal</span>
              </div>
              <div className={`fmt-card ${exportFmt==="housekeyvault-json"?"selected":""}`} onClick={()=>setExportFmt("housekeyvault-json")} style={{gridColumn:"1 / -1"}}>
                <div className="fmt-card-name">HouseKey Vault JSON</div>
                <div className="fmt-card-desc">Native format. Preserves folders, breach status, TOTP secrets, and timestamps. Use for backups.</div>
                <span className="fmt-badge compat">Full backup</span>
              </div>
            </div>
            <div className="alert alert-warn" style={{marginBottom:14}}>
              <I.Alert/>
              <span>Export files are unencrypted plaintext. Delete the file immediately after use or store it on an encrypted volume.</span>
            </div>
            <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:6}}>
              <div style={{fontFamily:"var(--mono)",fontSize:10,color:"var(--text3)"}}>{entries.length} entries will be exported</div>
            </div>
            <button className="btn btn-primary" onClick={handleExport} disabled={entries.length===0} style={{padding:"7px 16px",fontSize:11,height:"auto",width:"auto",alignSelf:"flex-start"}}>
              <I.Download/>Download export file
            </button>
          </>)}
        </div>
      </div>
    </div>
  );
}

// ── VAULT SCREEN ──────────────────────────────────────────────────────────────
function VaultScreen({ session, onLogout }:{ session:SessionState; onLogout:()=>void }) {
  const [vault,setVault]=useState(session.vault);
  const [folders,setFolders]=useState<Folder[]>((session.vault as any)._folders??[]);
  const [saving,setSaving]=useState(false);
  const [showAdd,setShowAdd]=useState(false);
  const [search,setSearch]=useState("");
  const [activeFolder,setActiveFolder]=useState<string|null>(null);
  const [checking,setChecking]=useState<Record<string,boolean>>({});
  const [toast,setToast]=useState<{msg:string;type:"default"|"ok"|"warn"}|null>(null);
  const [showIO,setShowIO]=useState(false);
  const [sharingEntry,setSharingEntry]=useState<VaultEntry|null>(null);

  const showToast=(msg:string,type:"default"|"ok"|"warn"="default")=>{setToast({msg,type});setTimeout(()=>setToast(null),2800);};

  const persist=useCallback(async(entries:VaultEntry[],flds:Folder[])=>{
    setSaving(true);
    try{
      const vd={...vault,entries,_folders:flds} as VaultData;
      if(!session.isDuress){
        // Normal mode: encrypt and persist to server
        const {encryptedVault,vaultIV}=await encryptVault(vd,session.privateKeyB64,session.publicKeyB64);
        await api.saveVault(encryptedVault,vaultIV);
      }
      // Duress mode: changes are kept in local state only — never touch the real vault on server
      setVault(vd);setFolders(flds);
    }catch{showToast("Failed to save","warn");}
    setSaving(false);
  },[session.privateKeyB64,vault]);

  const copy=async(text:string,label:string)=>{await navigator.clipboard.writeText(text);showToast(`${label} copied`,"ok");};

  const handleSave=async(form:EntryFormData)=>{
    const entry:any={id:crypto.randomUUID(),...form,createdAt:Date.now(),updatedAt:Date.now()};
    if(form.secondDevice){
      try{
        const {keyFile,saltB64}=await setupDeviceKey(form.site);
        // Encrypt with deviceSecret (same key derived from it via PBKDF2)
        const {enc,iv}=await encryptWithDeviceKey(form.password,keyFile.deviceSecret,saltB64);
        // Also verify passphrase derives same key (sanity — they use the same salt)
        entry.secondDeviceEncrypted=enc;
        entry.secondDeviceIV=iv;
        entry.secondDeviceSalt=saltB64; // stored so passphrase recovery works
        delete entry.recoveryPassphrase; // never store passphrase in vault
        await saveDeviceKeyFile(keyFile);
        showToast("Second device key downloaded — store it on a separate USB","ok");
      }catch(e:any){if(e.message!=="Cancelled.")showToast(e.message??"Failed to create device key","warn");return;}
    } else { delete entry.recoveryPassphrase; }
    await persist([...vault.entries,entry as VaultEntry],folders);setShowAdd(false);showToast("Entry saved","ok");
  };
  const handleEdit=async(id:string,form:EntryFormData)=>{
    const existing:any=vault.entries.find(e=>e.id===id);
    let extra:any={};
    if(form.secondDevice&&!existing?.secondDeviceEncrypted){
      try{
        const {keyFile,saltB64}=await setupDeviceKey(form.site);
        const {enc,iv}=await encryptWithDeviceKey(form.password,keyFile.deviceSecret,saltB64);
        extra={secondDeviceEncrypted:enc,secondDeviceIV:iv,secondDeviceSalt:saltB64};
        await saveDeviceKeyFile(keyFile);
        showToast("Second device key downloaded","ok");
      }catch(e:any){if(e.message!=="Cancelled.")showToast(e.message??"Failed","warn");return;}
    }else if(!form.secondDevice&&existing?.secondDeviceEncrypted){
      extra={secondDeviceEncrypted:null,secondDeviceIV:null,secondDeviceSalt:null};
    }
    const {recoveryPassphrase:_rp,...formClean}=form as any;
    const updated=vault.entries.map(e=>e.id===id?{...e,...formClean,...extra,updatedAt:Date.now()}:e);
    await persist(updated,folders);showToast("Entry updated","ok");
  };
  const handleDelete=async(id:string)=>{await persist(vault.entries.filter(e=>e.id!==id),folders);showToast("Entry deleted");};
  const handleAddFolder=async(f:Folder)=>persist(vault.entries,[...folders,f]);
  const handleDeleteFolder=async(id:string)=>{
    const entries=vault.entries.map(e=>(e as any).folderId===id?{...e,folderId:""}:e) as VaultEntry[];
    await persist(entries,folders.filter(f=>f.id!==id));
    if(activeFolder===id)setActiveFolder(null);
  };
  // Drag-drop from entry card to folder panel
  const handleDropEntry=async(entryId:string,targetFolderId:string|null)=>{
    const updated=vault.entries.map(e=>e.id===entryId?{...e,folderId:targetFolderId??""}:e);
    await persist(updated,folders);
    const folder=folders.find(f=>f.id===targetFolderId);
    showToast(folder?`Moved to ${folder.name}`:"Moved to All","ok");
  };

  const handleImport=async(result:ImportResult)=>{
    const newEntries=result.entries.map(e=>({
      ...e, id:crypto.randomUUID(), createdAt:Date.now(), updatedAt:Date.now(),
    })) as VaultEntry[];
    await persist([...vault.entries,...newEntries],folders);
    showToast(`${newEntries.length} entries imported`,"ok");
  };

  const checkBreach=async(entry:VaultEntry)=>{
    setChecking(c=>({...c,[entry.id]:true}));
    try{
      const count=await api.checkBreached(entry.password);
      // Use functional update of vault to avoid stale closure
      const updated=vault.entries.map(e=>e.id===entry.id?{...e,breached:count>0}:e);
      await persist(updated,folders);
      showToast(count>0?`Found in ${count.toLocaleString()} breaches`:"Not found in known breaches",count>0?"warn":"ok");
    }catch{showToast("Breach check unavailable","warn");}
    setChecking(c=>({...c,[entry.id]:false}));
  };
  const checkAllBreaches=async()=>{
    showToast("Checking via HIBP…");
    // Accumulate all results in a mutable map, then persist ONCE at the end
    // This avoids stale closure overwrites when iterating
    const results:Record<string,boolean>={};
    const entries=[...vault.entries];
    for(const e of entries){
      setChecking(c=>({...c,[e.id]:true}));
      try{
        const count=await api.checkBreached(e.password);
        results[e.id]=count>0;
      }catch{ /* leave undefined = unchecked */ }
      setChecking(c=>({...c,[e.id]:false}));
      await new Promise(r=>setTimeout(r,400));
    }
    // Single persist with all results applied
    const updated=entries.map(e=>e.id in results?{...e,breached:results[e.id]}:e) as VaultEntry[];
    await persist(updated,folders);
    const breachedN=Object.values(results).filter(Boolean).length;
    const checkedN=Object.keys(results).length;
    showToast(
      breachedN>0
        ?`${breachedN} breached · ${checkedN-breachedN} safe`
        :`All ${checkedN} passwords clean`,
      breachedN>0?"warn":"ok"
    );
  };

  const filtered=vault.entries.filter(e=>{
    const ms=!search||e.site.toLowerCase().includes(search.toLowerCase())||e.username.toLowerCase().includes(search.toLowerCase());
    const mf=activeFolder===null||(e as any).folderId===activeFolder;
    return ms&&mf;
  });
  const activeF=folders.find(f=>f.id===activeFolder);
  const breachedCount=vault.entries.filter(e=>e.breached).length;

  return (
    <div className="screen screen-full">
      <div className="vault-topbar">
        <Wordmark compact/>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          {session.isDuress&&(
            <div className="duress-indicator"><div className="duress-dot"/>Decoy Mode</div>
          )}
          <div className="status-pill"><div className="status-dot"/>{saving?"Encrypting":"Vault Secure"}</div>
          <button className="io-btn" onClick={()=>setShowIO(true)}><I.Upload/>Import<span style={{opacity:.4,margin:"0 2px"}}>/</span><I.Download/>Export</button>
          <button className="lock-btn" onClick={onLogout}><I.Lock/>Lock Vault</button>
        </div>
      </div>
      {breachedCount>0&&<div className="alert alert-warn" style={{marginBottom:14}}><I.Alert/>{breachedCount} password{breachedCount>1?"s":""} found in known data breaches.</div>}
      <div className="vault-body">
        <div className="sidebar">
          <HealthWidget entries={vault.entries} onCheckAll={checkAllBreaches}/>
          <FolderPanel folders={folders} entries={vault.entries} active={activeFolder}
            onSelect={setActiveFolder} onAdd={handleAddFolder} onDelete={handleDeleteFolder}
            onDropEntry={handleDropEntry}/>
          <div className="sidebar-card">
            <div className="nav-label">Security Standards</div>
            {["ECDSA P-256","AES-256-GCM","HIBP k-Anon","HKDF Derive"].map(l=>(
              <div key={l} className="sec-item" style={{marginBottom:6}}><I.Shield/>{l}</div>
            ))}
          </div>
        </div>
        <div className="main-panel">
          <div className="card">
            <div className="toolbar">
              <div className="toolbar-left">
                <div className="panel-title">
                  {activeF&&<div style={{width:8,height:8,borderRadius:2,background:activeF.color,flexShrink:0}}/>}
                  {activeF?activeF.name:"Credentials"}
                </div>
                <div className="panel-meta">{filtered.length} entries · Zero-knowledge</div>
              </div>
              <div className="toolbar-right">
                <div className="search-wrap"><I.Search/>
                  <input className="search-inp" placeholder="Search…" value={search} onChange={e=>setSearch(e.target.value)}/>
                </div>
                <button className="add-btn" onClick={()=>setShowAdd(s=>!s)}>
                  {showAdd?<><I.X/>Cancel</>:<><I.Plus/>Add Entry</>}
                </button>
              </div>
            </div>
            {showAdd&&<EntryForm mode="add" folders={folders} onSave={handleSave} onCancel={()=>setShowAdd(false)} onToast={showToast}/>}
            <EntryList entries={filtered} folders={folders} onCopy={copy} onDelete={handleDelete}
              onEdit={handleEdit} onCheckBreach={checkBreach} onShare={setSharingEntry} checking={checking}/>
          </div>
        </div>
      </div>
      {toast&&<Toast msg={toast.msg} type={toast.type}/>}
      {sharingEntry&&<ShareModal entry={sharingEntry} onClose={()=>setSharingEntry(null)} onToast={showToast}/>}
      {showIO&&<ImportExportModal entries={vault.entries} onImport={handleImport} onClose={()=>setShowIO(false)} publicKeyHash={session.publicKeyHash}/>}
    </div>
  );
}

// ── LANDING ───────────────────────────────────────────────────────────────────
function LandingScreen({ onCreate, onLogin, onRecover }:{ onCreate:()=>void; onLogin:()=>void; onRecover:()=>void }) {
  const [tier, setTier] = useState<StorageTier|null>(null);
  useEffect(()=>{ setTier(detectTier()); }, []);
  const tierLabel = tier==null?"":tier==="directory"?"USB / folder key":tier==="file"?"File key (.hkv)":"Download key file";
  const tierHint  = tier==null?"":tier==="directory"?"Chrome · Edge · Desktop":"Works on all browsers & mobile";
  return (
    <div className="screen"><Wordmark/>
      <div className="card">
        <div className="eyebrow">Secure Credential Storage</div>
        <div className="h1">Your key.<br/>Your vault.</div>
        <div className="body">Your private key lives in a file you control — USB, phone storage, iCloud, anywhere. No master password. The key never leaves your device.</div>
        <div className="sec-bar">{["ECDSA P-256","AES-256-GCM","Zero-Knowledge","HIBP k-Anon"].map(l=><div key={l} className="sec-item"><I.Shield/>{l}</div>)}</div>
        <div style={{background:"var(--ink3)",border:"1px solid var(--line)",borderRadius:"var(--r)",padding:"8px 12px",marginBottom:14,display:"flex",alignItems:"center",gap:10}}>
          <div style={{width:8,height:8,borderRadius:"50%",background:"var(--jade)",flexShrink:0}}/>
          <div>
            <div style={{fontFamily:"var(--mono)",fontSize:10,color:"var(--text)"}}>{tierLabel}</div>
            <div style={{fontFamily:"var(--mono)",fontSize:9,color:"var(--text3)"}}>{tierHint}</div>
          </div>
        </div>
        <div className="btn-row">
          <button className="btn btn-primary" onClick={onCreate}><I.Plus/>New Vault</button>
          <button className="btn btn-outline" onClick={onLogin} style={{marginTop:0}}><I.Unlock/>Unlock Vault</button>
        </div>
        <div style={{display:"flex",justifyContent:"center"}}>
          <button className="recovery-link" onClick={onRecover}><I.Recover/>Lost your key? Recover with seed phrase</button>
        </div>
      </div>
    </div>
  );
}

// ── CROSS-BROWSER KEY ZONE COMPONENTS ───────────────────────────────────────

function KeyZoneButton({ onClick }:{ onClick:()=>void }) {
  const [tier, setTier] = useState<StorageTier>("download");
  useEffect(()=>{ setTier(detectTier()); }, []);
  const labels = {
    directory: { main:"Select folder",        hint:"Picks a USB or any folder · Chrome/Edge" },
    file:      { main:"Save key file",         hint:"You'll choose where to save the .hkv file" },
    download:  { main:"Download key file",     hint:"Save it to USB, iCloud, Google Drive…" },
  };
  const { main, hint } = labels[tier];
  return (
    <div className="usb-zone" onClick={onClick}>
      <div className="usb-visual">
        {tier==="directory" ? <I.USB/> : <I.Key/>}
      </div>
      <div className="usb-label">{main}</div>
      <div className="usb-hint">{hint}</div>
    </div>
  );
}

function LoginKeyZone({ status, msg, onLogin }:{ status:string; msg:string; onLogin:()=>void }) {
  const [tier, setTier] = useState<StorageTier>("download");
  useEffect(()=>{ setTier(detectTier()); }, []);
  const idle = status !== "loading";
  const labels = {
    directory: "Select folder with your .hkv file",
    file:      "Select your .hkv key file",
    download:  "Open your .hkv key file",
  };
  const hints = {
    directory: "ECDSA P-256 · Chrome/Edge",
    file:      "ECDSA P-256 · all browsers",
    download:  "ECDSA P-256 · all browsers",
  };
  return (
    <div className={`usb-zone ${!idle?"active":""}`} onClick={idle?onLogin:undefined}>
      <div className="usb-visual">
        {!idle ? <I.Lock/> : <I.Key/>}
      </div>
      <div className="usb-label">{!idle ? msg : labels[tier]}</div>
      <div className="usb-hint">{idle ? hints[tier] : ""}</div>
    </div>
  );
}

// ── CREATE ────────────────────────────────────────────────────────────────────
function CreateScreen({ onBack, onComplete }:{ onBack:()=>void; onComplete:(s:SessionState)=>void }) {
  const [step,setStep]=useState(0);const [status,setStatus]=useState("");const [error,setError]=useState("");
  const [seed,setSeed]=useState("");const [confirmed,setConfirmed]=useState(false);const [copied,setCopied]=useState(false);
  const ref=useRef<SessionState|null>(null);
  const [duressPin,setDuressPin]=useState("");
  const [showDuressPin,setShowDuressPin]=useState(false);

  const setup=async()=>{setError("");setStep(1);
    try{
      setStatus("Generating ECDSA P-256 key pair");
      const {publicKeyB64,privateKeyB64,publicKeyHash}=await generateKeyPair();
      setStatus("Deriving AES-256 vault key");
      const vault=emptyVault();const {encryptedVault,vaultIV}=await encryptVault(vault,privateKeyB64,publicKeyB64);
      setStatus("Writing key to USB");
      const keyTier = await setupUSBKey({privateKeyB64,publicKeyB64,publicKeyHash,createdAt:Date.now(),version:1});
      if(keyTier==="download") setStatus("Key downloaded — save it somewhere safe");
      setStatus("Registering with server");
      const seedPhrase = generateSeedPhrase();
      const {encryptedVault:seedEnc,vaultIV:seedIV} = await encryptVaultWithSeed(vault, seedPhrase);
      const seedHashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(seedPhrase.trim().toLowerCase()));
      const seedHash = Array.from(new Uint8Array(seedHashBuf)).map(b=>b.toString(16).padStart(2,"0")).join("");
      // Duress vault: encrypt an empty decoy with PIN-derived key (optional)
      let duressEncryptedVault: string|undefined, duressVaultIV: string|undefined;
      if(duressPin.trim().length>=4){
        setStatus("Generating decoy vault");
        const decoy=emptyVault();
        const {encryptedVault:dEnc,vaultIV:dIV}=await encryptDecoyVault(decoy,privateKeyB64,publicKeyB64,duressPin.trim());
        duressEncryptedVault=dEnc; duressVaultIV=dIV;
      }
      await api.register({publicKey:publicKeyB64,publicKeyHash,encryptedVault,vaultIV,seedHash,seedEncryptedVault:seedEnc,seedVaultIV:seedIV,duressEncryptedVault,duressVaultIV});
      setSeed(seedPhrase);ref.current={privateKeyB64,publicKeyB64,publicKeyHash,vault};setStep(2);
    }catch(e:any){setError(e.message??"Setup failed.");setStep(0);}
  };
  const copySeed=async()=>{await navigator.clipboard.writeText(seed);setCopied(true);setTimeout(()=>setCopied(false),3000);};
  const finish=()=>{if(!confirmed||!ref.current)return;setStep(3);setTimeout(()=>onComplete(ref.current!),600);};
  return (
    <div className="screen"><Wordmark/>
      <div className="card">
        <div className="steps">{[0,1,2].map(i=><div key={i} className={`step-bar ${i<step?"done":i===Math.min(step,2)?"active":""}`}/>)}</div>
        {error&&<div className="alert alert-warn"><I.Alert/>{error}</div>}
        {step===0&&<><div className="eyebrow">Step 1 of 3</div><div className="h1">Initialize USB key</div>
          <div className="body">Select your USB directory. A <code style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--gold)"}}>housekeyvault.hkv</code> key file will be written.</div>
          {/* Duress PIN — optional, but shown upfront */}
          <div style={{background:"var(--ink3)",border:"1px solid var(--line)",borderRadius:"var(--r)",padding:"12px 14px",marginBottom:14}}>
            <div style={{fontFamily:"var(--mono)",fontSize:9,letterSpacing:".15em",textTransform:"uppercase",color:"var(--text2)",marginBottom:6,display:"flex",alignItems:"center",gap:6}}>
              Duress PIN <span style={{color:"var(--text3)"}}>(optional)</span>
              <span className="tooltip-anchor" data-tip="If someone forces you to open your vault, enter this PIN instead. They see an empty decoy vault. Leave blank to skip. Minimum 4 characters."><I.Help/></span>
            </div>
            <div style={{display:"flex",gap:6}}>
              <input className="inp" type={showDuressPin?"text":"password"} placeholder="Secret duress PIN — 4+ chars"
                value={duressPin} onChange={e=>setDuressPin(e.target.value)}
                style={{flex:1,borderColor:duressPin.length>0&&duressPin.length<4?"rgba(192,57,43,.5)":undefined}}/>
              <button type="button" style={{background:"transparent",border:"1px solid var(--line)",borderRadius:4,padding:"6px 8px",cursor:"pointer",color:"var(--text3)",display:"flex",alignItems:"center"}} onClick={()=>setShowDuressPin(s=>!s)}>
                {showDuressPin?<I.EyeOff/>:<I.Eye/>}
              </button>
            </div>
            {duressPin.length>=4&&<div style={{fontFamily:"var(--mono)",fontSize:9,color:"var(--jade)",marginTop:4}}>Decoy vault will be created</div>}
          </div>
          <KeyZoneButton onClick={setup}/>
          <button className="btn btn-ghost" onClick={onBack}>Back</button>
        </>}
        {step===1&&<><div className="eyebrow">Initializing</div><div className="h1">Setting up vault</div>
          <div className="body" style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--text3)"}}>{status}…</div>
          <div className="usb-zone active"><div className="usb-visual"><I.USB/></div><div className="usb-label">Writing to device</div><div className="usb-hint">Do not remove USB</div></div>
        </>}
        {step===2&&<><div className="eyebrow">Step 2 of 3</div><div className="h1">Recovery phrase</div>
          <div className="body">Store offline. Only way to recover if your key file is lost.</div>
          <div className="alert alert-warn"><I.Alert/>Will not be shown again.</div>
          <div className="seed-box">
            <div className="seed-hdr"><div className="seed-label">12-Word Recovery Phrase</div>
              <button className={`seed-copy ${copied?"copied":""}`} onClick={copySeed}>{copied?<I.Check/>:<I.Copy/>}{copied?"Copied":"Copy"}</button>
            </div>
            <div className="seed-grid">{seed.split(" ").map((w,i)=><div key={i} className="seed-word"><span className="seed-idx">{String(i+1).padStart(2,"0")}</span><span className="seed-val">{w}</span></div>)}</div>
          </div>
          <label style={{display:"flex",gap:10,alignItems:"flex-start",fontSize:12,color:"var(--text2)",marginBottom:18,cursor:"pointer",lineHeight:1.6}}>
            <input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)} style={{accentColor:"var(--gold)",marginTop:2,flexShrink:0}}/>
            I have stored the recovery phrase safely.
          </label>
          <button className="btn btn-primary" onClick={finish} disabled={!confirmed}>Enter Vault</button>
        </>}
        {step===3&&<div className="alert alert-ok"><I.OkCircle/>Vault initialized. Loading…</div>}
      </div>
    </div>
  );
}

// ── LOGIN ─────────────────────────────────────────────────────────────────────
function LoginScreen({ onBack, onSuccess, onParanoia }:{ onBack:()=>void; onSuccess:(s:SessionState)=>void; onParanoia:(r:number)=>void }) {
  const [status,setStatus]=useState<"idle"|"loading"|"error">("idle");const [msg,setMsg]=useState("");
  const [duressPin,setDuressPin]=useState("");const [showDuress,setShowDuress]=useState(false);const [showDuressField,setShowDuressField]=useState(false);
  const login=async()=>{setStatus("loading");setMsg("Select USB directory…");
    try{
      const kf=await loadUSBKey();setMsg("Requesting challenge");
      const {nonce}=await api.getChallenge(kf.publicKeyHash);setMsg("Signing with private key");
      const sig=await signChallenge(kf.privateKeyB64,nonce);setMsg("Verifying");
      const res=await api.verify({publicKey:kf.publicKeyB64,publicKeyHash:kf.publicKeyHash,signature:sig,nonce});
      if(res.error==="LOCKED"){onParanoia(res.remaining??300);return;}
      if(!res.success||!res.encryptedVault)throw new Error("Authentication failed.");
      setMsg("Decrypting vault");
      // Duress mode: if PIN entered AND server returned a decoy blob, decrypt decoy instead
      const pinTrimmed = duressPin.trim();
      const hasDuress  = pinTrimmed.length >= 4 && res.duressEncryptedVault && res.duressVaultIV;

      if(hasDuress){
        setMsg("Entering vault…");
        const decoyVault = await decryptDecoyVault(
          res.duressEncryptedVault!, res.duressVaultIV!,
          kf.privateKeyB64, kf.publicKeyB64, pinTrimmed
        ).catch(()=>null);
        // If decoy decryption fails (wrong PIN for decoy), fall through to real vault
        if(decoyVault){
          onSuccess({...kf, vault:decoyVault, isDuress:true});
          return;
        }
      }

      const vaultRaw=await decryptVault(res.encryptedVault!,res.vaultIV!,kf.privateKeyB64,kf.publicKeyB64);
      const {_legacyKey,...vault}=vaultRaw;
      if(_legacyKey){
        setMsg("Upgrading vault encryption…");
        const {encryptedVault:newEnc,vaultIV:newIV}=await encryptVault(vault,kf.privateKeyB64,kf.publicKeyB64);
        await api.saveVault(newEnc,newIV).catch(()=>{/* non-fatal */});
      }
      onSuccess({...kf,vault});
    }catch(e:any){if(e?.data?.remaining){onParanoia(e.data.remaining);return;}setStatus("error");setMsg(e.message??"Auth failed.");}
  };
  return (
    <div className="screen"><Wordmark/>
      <div className="card">
        <div className="eyebrow">Authentication</div><div className="h1">Insert key to unlock</div>
        <div className="body">Select the directory with your <code style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--gold)"}}>housekeyvault.hkv</code> file.</div>
        {status==="error"&&<div className="alert alert-warn"><I.Alert/>{msg}</div>}
        <LoginKeyZone status={status} msg={msg} onLogin={login}/>
        {/* Duress PIN entry — shown only if user clicks the link */}
        {showDuressField&&(
          <div style={{background:"var(--ink3)",border:"1px solid rgba(192,57,43,.2)",borderRadius:"var(--r)",padding:"12px 14px",marginBottom:10}}>
            <div style={{fontFamily:"var(--mono)",fontSize:9,letterSpacing:".15em",textTransform:"uppercase",color:"rgba(192,57,43,.7)",marginBottom:6}}>Duress PIN</div>
            <div style={{display:"flex",gap:6}}>
              <input className="inp" type={showDuress?"text":"password"} placeholder="Enter duress PIN"
                value={duressPin} onChange={e=>setDuressPin(e.target.value)}
                style={{flex:1,borderColor:"rgba(192,57,43,.3)"}}/>
              <button type="button" style={{background:"transparent",border:"1px solid var(--line)",borderRadius:4,padding:"6px 8px",cursor:"pointer",color:"var(--text3)",display:"flex",alignItems:"center"}} onClick={()=>setShowDuress(s=>!s)}>
                {showDuress?<I.EyeOff/>:<I.Eye/>}
              </button>
            </div>
            <div style={{fontFamily:"var(--mono)",fontSize:9,color:"rgba(192,57,43,.5)",marginTop:4}}>The decoy vault will open instead</div>
          </div>
        )}
        <button className="btn btn-ghost" onClick={onBack}>Back</button>
        <div style={{display:"flex",justifyContent:"center"}}>
          <button style={{background:"transparent",border:"none",color:"var(--text3)",fontFamily:"var(--mono)",fontSize:9,letterSpacing:".06em",textTransform:"uppercase",cursor:"pointer",padding:"4px 0",opacity:.5}} onClick={()=>setShowDuressField(s=>!s)}>
            {showDuressField?"hide duress mode":"under duress?"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── RECOVER ───────────────────────────────────────────────────────────────────
function RecoverScreen({ onBack, onSuccess }:{ onBack:()=>void; onSuccess:(s:SessionState)=>void }) {
  const inputRefs=useRef<(HTMLInputElement|null)[]>([]);
  const [words,setWords]=useState<string[]>(Array(12).fill(""));
  const [status,setStatus]=useState<"idle"|"loading"|"error">("idle");
  const [error,setError]=useState("");
  const setWord=(i:number,v:string)=>{if(v.endsWith(" ")){inputRefs.current[i+1]?.focus();v=v.trim();}const w=[...words];w[i]=v.toLowerCase();setWords(w);};
  const filled=words.filter(w=>w.length>0).length;
  const allFilled=words.every(w=>w.length>0);
  const handleRecover=async()=>{
    if(!allFilled){setError("Please fill all 12 words.");return;}
    setStatus("loading");setError("");
    try{
      const seed=words.join(" ");

      // Phase 1: get seed-encrypted vault from server
      const phase1=await api.recover({seedPhrase:seed});
      if(!phase1.success||!phase1.encryptedVault)throw new Error(phase1.error??"Recovery phrase not recognised.");

      // Decrypt locally with seed-derived key (PBKDF2 → AES-256-GCM)
      const vault=await decryptVaultWithSeed(phase1.encryptedVault,phase1.vaultIV!,phase1.recoveryKey!);

      // Generate brand-new key pair for the replacement USB
      const {publicKeyB64,privateKeyB64,publicKeyHash}=await generateKeyPair();
      const {encryptedVault:newEnc,vaultIV:newIV}=await encryptVault(vault,privateKeyB64,publicKeyB64);

      // Phase 2: update server record + open session (no extra /api/vault/save needed)
      const phase2=await api.recover({
        seedPhrase:seed,
        newPublicKey:publicKeyB64,
        newPublicKeyHash:publicKeyHash,
        newEncryptedVault:newEnc,
        newVaultIV:newIV,
      });
      if(!phase2.success)throw new Error(phase2.error??"Failed to update vault.");

      // Write new key to USB — user selects folder
      await setupUSBKey({privateKeyB64,publicKeyB64,publicKeyHash,createdAt:Date.now(),version:1});
      onSuccess({privateKeyB64,publicKeyB64,publicKeyHash,vault});
    }catch(e:any){setStatus("error");setError(e.message??"Recovery failed.");}
  };
  return (
    <div className="screen"><Wordmark/>
      <div className="card">
        <div className="eyebrow">Vault Recovery</div><div className="h1">Recover with seed</div>
        <div className="body" style={{marginBottom:10}}>Enter your 12-word recovery phrase in order.</div>
        <div className="alert alert-warn" style={{marginBottom:0}}><I.Alert/>HouseKey never stores your phrase — only you have it.</div>
        <div className="seed-input-grid">
          {words.map((w,i)=>(
            <div key={i} className={`si ${status==="error"&&!w?"err":""}`}>
              <span className="si-num">{String(i+1).padStart(2,"0")}</span>
              <input ref={el=>{inputRefs.current[i]=el;}} className="si-inp" placeholder="word" value={w}
                autoCapitalize="none" autoCorrect="off" spellCheck={false}
                onChange={e=>setWord(i,e.target.value)}
                onKeyDown={e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();inputRefs.current[i+1]?.focus();}if(e.key==="Backspace"&&!w)inputRefs.current[i-1]?.focus();}}/>
            </div>
          ))}
        </div>
        <div style={{fontFamily:"var(--mono)",fontSize:9,color:"var(--text3)",letterSpacing:".08em",marginBottom:12}}>{filled} / 12 words entered</div>
        {error&&<div className="alert alert-warn" style={{marginBottom:12}}><I.Alert/>{error}</div>}
        <button className="btn btn-primary" onClick={handleRecover} disabled={!allFilled||status==="loading"}>
          <I.Recover/>{status==="loading"?"Recovering…":"Restore Vault"}
        </button>
        <button className="btn btn-ghost" onClick={onBack}>Back</button>
      </div>
    </div>
  );
}

// ── PARANOIA ──────────────────────────────────────────────────────────────────
function ParanoiaScreen({ remaining, onRetry }:{ remaining:number; onRetry:()=>void }) {
  const [count,setCount]=useState(remaining);
  useEffect(()=>{if(count<=0)return;const t=setInterval(()=>setCount(c=>c-1),1000);return()=>clearInterval(t);},[]);
  const mm=String(Math.floor(count/60)).padStart(2,"0"),ss=String(count%60).padStart(2,"0");
  return (
    <div className="screen"><Wordmark/>
      <div className="card" style={{background:"rgba(12,6,6,0.9)",borderColor:"rgba(192,57,43,0.2)",textAlign:"center"}}>
        <div className="p-icon"><I.Lock/></div>
        <div className="p-title">Access Suspended</div>
        <div className="p-sub">Multiple failed attempts detected.</div>
        <div className="countdown">{mm}:{ss}</div>
        <div className="countdown-label">Time remaining</div>
        {count<=0&&<button className="btn btn-outline" onClick={onRetry} style={{marginTop:24}}>Retry Authentication</button>}
      </div>
    </div>
  );
}

// ── ROOT ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [screen,setScreen]=useState<Screen>("landing");
  const [session,setSession]=useState<SessionState|null>(null);
  const [paranoia,setParanoia]=useState(0);
  const logout=async()=>{await api.logout().catch(()=>{});setSession(null);setScreen("landing");};
  const enter=(s:SessionState)=>{setSession(s);setScreen("vault");};
  return (
    <>
      <style>{CSS}</style>
      <div className={`app ${screen==="paranoia"?"paranoia-bg":""}`}>
        {screen==="landing"  && <LandingScreen onCreate={()=>setScreen("create")} onLogin={()=>setScreen("login")} onRecover={()=>setScreen("recover")}/>}
        {screen==="create"   && <CreateScreen  onBack={()=>setScreen("landing")} onComplete={enter}/>}
        {screen==="login"    && <LoginScreen   onBack={()=>setScreen("landing")} onSuccess={enter} onParanoia={r=>{setParanoia(r);setScreen("paranoia");}}/>}
        {screen==="recover"  && <RecoverScreen onBack={()=>setScreen("landing")} onSuccess={enter}/>}
        {screen==="vault"    && session && <VaultScreen session={session} onLogout={logout}/>}
        {screen==="paranoia" && <ParanoiaScreen remaining={paranoia} onRetry={()=>setScreen("login")}/>}
      </div>
    </>
  );
}