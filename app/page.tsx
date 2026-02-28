"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import {
  generateKeyPair, signChallenge, encryptVault, decryptVault,
  generateSeedPhrase, generatePassword, scorePassword, emptyVault,
  type VaultData, type VaultEntry, type VaultFolder,
} from "@/lib/crypto-client";
import { setupUSBKey, loadUSBKey, isFileSystemAccessSupported, type KeyFile } from "@/lib/usb-storage";
import { api } from "@/lib/api-client";

type Screen = "landing" | "create" | "login" | "vault" | "paranoia";
interface SessionState {
  privateKeyB64: string;
  publicKeyB64: string;
  publicKeyHash: string;
  vault: VaultData;
}

// ── DESIGN SYSTEM ────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;500;600&family=IBM+Plex+Mono:wght@300;400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --ink:       #0C0C0F;
  --ink2:      #14141A;
  --ink3:      #1C1C24;
  --ink4:      #26262F;
  --line:      rgba(255,255,255,0.07);
  --line2:     rgba(255,255,255,0.12);
  --gold:      #C9A84C;
  --gold2:     #E2C06A;
  --gold-dim:  rgba(201,168,76,0.15);
  --gold-glow: rgba(201,168,76,0.06);
  --crimson:   #C0392B;
  --crimson-dim: rgba(192,57,43,0.15);
  --jade:      #27AE8F;
  --jade-dim:  rgba(39,174,143,0.12);
  --text:      #E8E6E0;
  --text2:     #9A9890;
  --text3:     #5A5856;
  --display:   'Playfair Display', Georgia, serif;
  --sans:      'IBM Plex Sans', system-ui, sans-serif;
  --mono:      'IBM Plex Mono', 'Courier New', monospace;
  --radius:    6px;
  --radius2:   10px;
  --shadow:    0 1px 3px rgba(0,0,0,0.4), 0 8px 32px rgba(0,0,0,0.3);
}

html, body {
  background: var(--ink);
  color: var(--text);
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  min-height: 100vh;
}

/* ── LAYOUT ── */
.app {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  position: relative;
  overflow: hidden;
}

.app::before {
  content: '';
  position: fixed;
  inset: 0;
  background:
    radial-gradient(ellipse 80% 50% at 50% -10%, rgba(201,168,76,0.04) 0%, transparent 60%),
    radial-gradient(ellipse 50% 80% at 100% 100%, rgba(39,174,143,0.03) 0%, transparent 50%);
  pointer-events: none;
}

.app::after {
  content: '';
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px);
  background-size: 48px 48px;
  pointer-events: none;
}

.screen {
  width: 100%;
  max-width: 480px;
  position: relative;
  z-index: 1;
  animation: appear 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}

.screen-wide { max-width: 720px; }

@keyframes appear {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* ── WORDMARK ── */
.wordmark {
  margin-bottom: 40px;
  display: flex;
  align-items: flex-end;
  gap: 12px;
}

.wordmark-icon {
  width: 36px;
  height: 36px;
  border: 1px solid var(--gold);
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  flex-shrink: 0;
}

.wordmark-icon::before {
  content: '';
  position: absolute;
  inset: 3px;
  border: 1px solid rgba(201,168,76,0.3);
}

.wordmark-icon svg {
  width: 16px;
  height: 16px;
  stroke: var(--gold);
  fill: none;
  stroke-width: 1.5;
}

.wordmark-text {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.wordmark-primary {
  font-family: var(--display);
  font-size: 17px;
  font-weight: 500;
  letter-spacing: 0.02em;
  color: var(--text);
  line-height: 1;
}

.wordmark-secondary {
  font-family: var(--mono);
  font-size: 9px;
  font-weight: 300;
  letter-spacing: 0.25em;
  color: var(--text3);
  text-transform: uppercase;
  line-height: 1;
  margin-top: 4px;
}

/* ── CARD ── */
.card {
  background: var(--ink2);
  border: 1px solid var(--line2);
  border-radius: var(--radius2);
  padding: 36px;
  box-shadow: var(--shadow);
  position: relative;
  overflow: hidden;
}

.card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--gold-dim), transparent);
}

.card-eyebrow {
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 400;
  letter-spacing: 0.2em;
  color: var(--gold);
  text-transform: uppercase;
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.card-eyebrow::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--line);
}

.card-title {
  font-family: var(--display);
  font-size: 26px;
  font-weight: 400;
  letter-spacing: -0.01em;
  line-height: 1.2;
  margin-bottom: 8px;
  color: var(--text);
}

.card-body {
  font-size: 13px;
  color: var(--text2);
  line-height: 1.7;
  margin-bottom: 28px;
}

/* ── BUTTONS ── */
.btn {
  width: 100%;
  padding: 13px 20px;
  border-radius: var(--radius);
  border: none;
  font-family: var(--sans);
  font-size: 13px;
  font-weight: 500;
  letter-spacing: 0.04em;
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  text-transform: uppercase;
}

.btn-primary {
  background: var(--gold);
  color: var(--ink);
}

.btn-primary:hover:not(:disabled) {
  background: var(--gold2);
  transform: translateY(-1px);
  box-shadow: 0 4px 24px rgba(201,168,76,0.25);
}

.btn-primary:active:not(:disabled) { transform: none; box-shadow: none; }

.btn-outline {
  background: transparent;
  color: var(--text2);
  border: 1px solid var(--line2);
  margin-top: 10px;
}

.btn-outline:hover:not(:disabled) {
  border-color: var(--gold);
  color: var(--gold);
}

.btn-ghost {
  background: transparent;
  color: var(--text3);
  border: none;
  margin-top: 6px;
  font-size: 12px;
  padding: 10px;
}

.btn-ghost:hover { color: var(--text2); }

.btn-row { display: flex; gap: 10px; }
.btn-row .btn { flex: 1; }

.btn:disabled { opacity: 0.35; cursor: not-allowed; }

/* ── DIVIDER ── */
.divider {
  height: 1px;
  background: var(--line);
  margin: 24px 0;
}

/* ── STEP INDICATOR ── */
.steps {
  display: flex;
  gap: 4px;
  margin-bottom: 28px;
}

.step-bar {
  height: 2px;
  flex: 1;
  background: var(--line2);
  border-radius: 1px;
  overflow: hidden;
  position: relative;
}

.step-bar.active::after, .step-bar.done::after {
  content: '';
  position: absolute;
  inset: 0;
  background: var(--gold);
  animation: fillBar 0.4s ease forwards;
}

.step-bar.done::after { animation: none; transform: scaleX(1); transform-origin: left; }
.step-bar.active::after { animation: fillBar 0.4s ease forwards; }

@keyframes fillBar {
  from { transform: scaleX(0); transform-origin: left; }
  to   { transform: scaleX(1); transform-origin: left; }
}

/* ── USB ZONE ── */
.usb-zone {
  border: 1px solid var(--line2);
  border-radius: var(--radius2);
  padding: 32px 24px;
  text-align: center;
  margin-bottom: 20px;
  cursor: pointer;
  transition: all 0.25s ease;
  position: relative;
  overflow: hidden;
  background: var(--ink3);
}

.usb-zone::before {
  content: '';
  position: absolute;
  inset: 0;
  background: var(--gold-glow);
  opacity: 0;
  transition: opacity 0.25s;
}

.usb-zone:hover::before, .usb-zone.active::before { opacity: 1; }
.usb-zone:hover, .usb-zone.active { border-color: rgba(201,168,76,0.4); }

.usb-visual {
  width: 48px;
  height: 48px;
  margin: 0 auto 16px;
  border: 1px solid var(--line2);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  z-index: 1;
}

.usb-zone.active .usb-visual {
  border-color: var(--gold);
  animation: pulseRing 1.5s ease infinite;
}

@keyframes pulseRing {
  0%, 100% { box-shadow: 0 0 0 0 rgba(201,168,76,0.3); }
  50% { box-shadow: 0 0 0 8px rgba(201,168,76,0); }
}

.usb-visual svg {
  width: 20px;
  height: 20px;
  stroke: var(--text2);
  fill: none;
  stroke-width: 1.5;
  position: relative;
  z-index: 1;
}

.usb-zone.active .usb-visual svg { stroke: var(--gold); }

.usb-label {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  margin-bottom: 4px;
  position: relative;
  z-index: 1;
}

.usb-hint {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
  position: relative;
  z-index: 1;
}

/* ── ALERTS ── */
.alert {
  border-radius: var(--radius);
  padding: 12px 16px;
  font-size: 12px;
  line-height: 1.6;
  margin-bottom: 16px;
  display: flex;
  gap: 10px;
  align-items: flex-start;
}

.alert svg {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
  margin-top: 1px;
}

.alert-warn {
  background: var(--crimson-dim);
  border: 1px solid rgba(192,57,43,0.25);
  color: #E07070;
}

.alert-warn svg { stroke: #E07070; fill: none; stroke-width: 1.5; }

.alert-ok {
  background: var(--jade-dim);
  border: 1px solid rgba(39,174,143,0.25);
  color: var(--jade);
}

.alert-ok svg { stroke: var(--jade); fill: none; stroke-width: 1.5; }

.alert-info {
  background: var(--gold-glow);
  border: 1px solid rgba(201,168,76,0.2);
  color: var(--text2);
}

.alert-info svg { stroke: var(--gold); fill: none; stroke-width: 1.5; }

/* ── SEED PHRASE ── */
.seed-container {
  background: var(--ink);
  border: 1px solid var(--line2);
  border-radius: var(--radius2);
  padding: 20px;
  margin: 20px 0;
}

.seed-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}

.seed-label {
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.18em;
  color: var(--text3);
  text-transform: uppercase;
}

.seed-copy-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  background: transparent;
  border: 1px solid var(--line2);
  border-radius: var(--radius);
  color: var(--text2);
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  cursor: pointer;
  transition: all 0.2s;
}

.seed-copy-btn:hover { border-color: var(--gold); color: var(--gold); }
.seed-copy-btn.copied { border-color: var(--jade); color: var(--jade); }

.seed-copy-btn svg {
  width: 12px;
  height: 12px;
  stroke: currentColor;
  fill: none;
  stroke-width: 1.5;
}

.seed-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 6px;
}

.seed-word {
  background: var(--ink2);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 7px 10px;
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: var(--mono);
}

.seed-idx {
  font-size: 9px;
  color: var(--text3);
  min-width: 14px;
  font-weight: 300;
}

.seed-val {
  font-size: 11.5px;
  font-weight: 400;
  color: var(--gold2);
  letter-spacing: 0.02em;
}

/* ── VAULT HEADER ── */
.vault-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 28px;
  flex-wrap: wrap;
  gap: 12px;
}

.vault-status-pill {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  background: var(--jade-dim);
  border: 1px solid rgba(39,174,143,0.2);
  border-radius: 20px;
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.1em;
  color: var(--jade);
  text-transform: uppercase;
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--jade);
  animation: statusPulse 2.5s ease infinite;
}

@keyframes statusPulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

.lock-btn {
  padding: 6px 14px;
  background: transparent;
  border: 1px solid var(--line2);
  border-radius: var(--radius);
  color: var(--text3);
  font-family: var(--sans);
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 6px;
}

.lock-btn svg { width: 12px; height: 12px; stroke: currentColor; fill: none; stroke-width: 1.5; }
.lock-btn:hover { border-color: var(--crimson); color: var(--crimson); }

/* ── VAULT TOOLBAR ── */
.vault-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
  gap: 12px;
  flex-wrap: wrap;
}

.vault-info-row {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.vault-title {
  font-family: var(--display);
  font-size: 20px;
  font-weight: 400;
}

.vault-meta {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  letter-spacing: 0.06em;
}

.toolbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.search-wrap {
  position: relative;
}

.search-wrap svg {
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-50%);
  width: 13px;
  height: 13px;
  stroke: var(--text3);
  fill: none;
  stroke-width: 1.5;
  pointer-events: none;
}

.search-inp {
  background: var(--ink3);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 8px 12px 8px 32px;
  color: var(--text);
  font-family: var(--mono);
  font-size: 12px;
  outline: none;
  width: 180px;
  transition: border-color 0.2s;
}

.search-inp:focus { border-color: rgba(201,168,76,0.4); }
.search-inp::placeholder { color: var(--text3); }

.add-btn {
  padding: 8px 16px;
  background: var(--gold);
  color: var(--ink);
  border: none;
  border-radius: var(--radius);
  font-family: var(--sans);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}

.add-btn svg { width: 13px; height: 13px; stroke: var(--ink); fill: none; stroke-width: 2; }
.add-btn:hover { background: var(--gold2); transform: translateY(-1px); box-shadow: 0 4px 16px rgba(201,168,76,0.2); }

/* ── FOLDER BAR ── */
.folder-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 20px;
  align-items: center;
}

.folder-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 5px 12px;
  background: var(--ink3);
  border: 1px solid var(--line);
  border-radius: 20px;
  color: var(--text2);
  font-family: var(--mono);
  font-size: 11px;
  cursor: pointer;
  transition: all 0.18s;
  white-space: nowrap;
}

.folder-chip:hover { border-color: var(--gold); color: var(--gold); }
.folder-chip.active { background: var(--gold-dim); border-color: rgba(201,168,76,0.4); color: var(--gold); }

.folder-del {
  font-size: 15px;
  line-height: 1;
  color: var(--text3);
  margin-left: 2px;
  padding: 0 2px;
  transition: color 0.15s;
}
.folder-del:hover { color: var(--crimson); }

.folder-new-row {
  display: flex;
  gap: 6px;
  align-items: center;
  flex-wrap: wrap;
}

.folder-new-row .inp {
  width: 160px;
  padding: 5px 10px;
  font-size: 11px;
}

.folder-new-row .btn {
  width: auto;
  padding: 6px 14px;
  font-size: 10px;
  margin-top: 0;
}

/* ── ENTRY CARDS ── */
.entries { display: flex; flex-direction: column; gap: 6px; }

.entry-card {
  background: var(--ink3);
  border: 1px solid var(--line);
  border-radius: var(--radius2);
  padding: 14px 16px;
  display: flex;
  align-items: center;
  gap: 14px;
  transition: all 0.2s;
  cursor: default;
}

.entry-card:hover { border-color: var(--line2); background: var(--ink4); }
.entry-card.breached { border-color: rgba(192,57,43,0.3); background: rgba(192,57,43,0.04); }

.entry-avatar {
  width: 34px;
  height: 34px;
  background: var(--ink4);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--display);
  font-size: 14px;
  font-weight: 500;
  color: var(--text2);
  flex-shrink: 0;
  text-transform: uppercase;
}

.entry-info { flex: 1; min-width: 0; overflow: hidden; }

.entry-site {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  margin-bottom: 2px;
  display: flex;
  align-items: center;
  gap: 8px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.entry-user {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.entry-pw-reveal {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--gold);
  margin-top: 4px;
  word-break: break-all;
  line-height: 1.4;
}

.entry-actions {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-shrink: 0;
}

.icon-btn {
  width: 28px;
  height: 28px;
  border-radius: var(--radius);
  border: 1px solid transparent;
  background: transparent;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.18s;
  color: var(--text3);
}

.icon-btn svg { width: 13px; height: 13px; stroke: currentColor; fill: none; stroke-width: 1.5; }
.icon-btn:hover { background: var(--ink4); border-color: var(--line2); color: var(--text); }
.icon-btn.danger:hover { background: var(--crimson-dim); border-color: rgba(192,57,43,0.3); color: var(--crimson); }
.icon-btn.active { color: var(--jade); }

/* ── BADGE ── */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  padding: 2px 7px;
  border-radius: 3px;
  font-family: var(--mono);
  font-size: 9px;
  font-weight: 500;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.badge-danger { background: var(--crimson-dim); color: #E07070; border: 1px solid rgba(192,57,43,0.25); }
.badge-safe { background: var(--jade-dim); color: var(--jade); border: 1px solid rgba(39,174,143,0.25); }

/* ── ADD FORM ── */
.add-form {
  background: var(--ink3);
  border: 1px solid rgba(201,168,76,0.2);
  border-radius: var(--radius2);
  padding: 20px;
  margin-bottom: 14px;
  animation: appear 0.25s cubic-bezier(0.16,1,0.3,1);
}

.form-section-label {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 10px;
  margin-top: 16px;
}

.form-section-label:first-child { margin-top: 0; }

.form-row { display: flex; gap: 10px; }
.form-row .field { flex: 1; }

.field { display: flex; flex-direction: column; gap: 5px; margin-bottom: 10px; }
.field:last-child { margin-bottom: 0; }

.field-label {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: var(--text3);
}

.inp {
  background: var(--ink2);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 9px 12px;
  color: var(--text);
  font-family: var(--mono);
  font-size: 12px;
  outline: none;
  width: 100%;
  transition: border-color 0.2s;
}

.inp:focus { border-color: rgba(201,168,76,0.4); }
.inp::placeholder { color: var(--text3); }

.pw-field-row { display: flex; gap: 8px; align-items: flex-start; }
.pw-field-row .field { flex: 1; }

.gen-btn {
  width: 36px;
  height: 36px;
  background: var(--ink2);
  border: 1px solid var(--line2);
  border-radius: var(--radius);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
  flex-shrink: 0;
  margin-top: 24px;
}

.gen-btn svg { width: 14px; height: 14px; stroke: var(--text2); fill: none; stroke-width: 1.5; }
.gen-btn:hover { border-color: var(--gold); }
.gen-btn:hover svg { stroke: var(--gold); }

/* ── STRENGTH METER ── */
.strength-row { display: flex; gap: 3px; margin-top: 5px; }

.strength-seg {
  height: 2px;
  flex: 1;
  border-radius: 1px;
  background: var(--line);
  transition: background 0.3s;
}

.strength-label {
  font-family: var(--mono);
  font-size: 9px;
  margin-top: 3px;
  letter-spacing: 0.05em;
}

/* ── GEN OPTIONS ── */
.gen-options {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 10px;
}

.gen-chip {
  padding: 4px 10px;
  border-radius: 3px;
  border: 1px solid var(--line);
  background: transparent;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  cursor: pointer;
  transition: all 0.15s;
  letter-spacing: 0.05em;
}

.gen-chip.on { background: var(--gold-dim); border-color: rgba(201,168,76,0.4); color: var(--gold); }

/* ── FORM ACTIONS ── */
.form-actions { display: flex; gap: 8px; margin-top: 16px; }
.form-actions .btn { padding: 10px 16px; font-size: 11px; }
.form-cancel { width: auto; flex: 0; padding: 10px 16px !important; }

/* ── EMPTY STATE ── */
.empty-state {
  text-align: center;
  padding: 48px 24px;
  color: var(--text3);
}

.empty-icon {
  width: 48px;
  height: 48px;
  border: 1px solid var(--line);
  border-radius: 50%;
  margin: 0 auto 16px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.empty-icon svg { width: 20px; height: 20px; stroke: var(--text3); fill: none; stroke-width: 1; }
.empty-title { font-size: 13px; font-weight: 500; color: var(--text2); margin-bottom: 4px; }
.empty-sub { font-family: var(--mono); font-size: 11px; color: var(--text3); }

/* ── TOAST ── */
.toast {
  position: fixed;
  bottom: 28px;
  left: 50%;
  transform: translateX(-50%);
  background: var(--ink3);
  border: 1px solid var(--line2);
  border-radius: var(--radius);
  padding: 10px 20px;
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: 0.05em;
  color: var(--text);
  box-shadow: var(--shadow);
  animation: toastIn 0.3s cubic-bezier(0.16,1,0.3,1);
  z-index: 999;
  white-space: nowrap;
}

.toast.ok { border-color: rgba(39,174,143,0.3); color: var(--jade); }
.toast.warn { border-color: rgba(192,57,43,0.3); color: #E07070; }

@keyframes toastIn {
  from { opacity: 0; transform: translateX(-50%) translateY(10px); }
  to   { opacity: 1; transform: translateX(-50%) translateY(0); }
}

/* ── PARANOIA ── */
.paranoia-screen {
  background:
    radial-gradient(ellipse 60% 60% at 50% 50%, rgba(192,57,43,0.06) 0%, transparent 70%),
    var(--ink);
}

.paranoia-card {
  background: rgba(12,6,6,0.9);
  border-color: rgba(192,57,43,0.2);
  text-align: center;
}

.paranoia-icon {
  width: 72px;
  height: 72px;
  border: 1px solid rgba(192,57,43,0.4);
  border-radius: 50%;
  margin: 0 auto 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  animation: paranoiaPulse 1.5s ease infinite;
}

.paranoia-icon svg { width: 28px; height: 28px; stroke: var(--crimson); fill: none; stroke-width: 1.5; }

@keyframes paranoiaPulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(192,57,43,0.3); }
  50%       { box-shadow: 0 0 0 12px rgba(192,57,43,0); }
}

.paranoia-title {
  font-family: var(--display);
  font-size: 28px;
  font-weight: 400;
  color: var(--crimson);
  margin-bottom: 8px;
  letter-spacing: 0.02em;
}

.paranoia-sub { font-size: 13px; color: #9A7070; line-height: 1.7; margin-bottom: 24px; }

.countdown {
  font-family: var(--mono);
  font-size: 48px;
  font-weight: 300;
  color: var(--crimson);
  letter-spacing: -2px;
  margin-bottom: 8px;
}

.countdown-label {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--text3);
}

/* ── SECURITY INDICATORS ── */
.security-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 10px 16px;
  background: var(--ink3);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  margin-bottom: 14px;
  flex-wrap: wrap;
}

.security-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text3);
}

.security-item svg { width: 11px; height: 11px; stroke: var(--jade); fill: none; stroke-width: 1.5; }
`;

// ── SVG ICONS ────────────────────────────────────────────────────────────────
const Icon = {
  Key: () => (
    <svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M12 15h8M17 15v-2"/></svg>
  ),
  Lock: () => (
    <svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="11" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
  ),
  Unlock: () => (
    <svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="11" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.75-1"/></svg>
  ),
  USB: () => (
    <svg viewBox="0 0 24 24"><path d="M12 2v14M8 12l4 4 4-4M6 19h12"/></svg>
  ),
  Shield: () => (
    <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
  ),
  Copy: () => (
    <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
  ),
  Check: () => (
    <svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>
  ),
  Eye: () => (
    <svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
  ),
  EyeOff: () => (
    <svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
  ),
  Trash: () => (
    <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
  ),
  Search: () => (
    <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
  ),
  Plus: () => (
    <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
  ),
  Shuffle: () => (
    <svg viewBox="0 0 24 24"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>
  ),
  Alert: () => (
    <svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
  ),
  CheckCircle: () => (
    <svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
  ),
  Info: () => (
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
  ),
  Vault: () => (
    <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="18" rx="2"/><circle cx="12" cy="12" r="3"/><path d="M12 2v1M12 21v1M2 12H1M23 12h-1M4.22 4.22l.71.71M19.07 19.07l.71.71M4.22 19.78l.71-.71M19.07 4.93l.71-.71"/></svg>
  ),
};

// ── WORDMARK ─────────────────────────────────────────────────────────────────
function Wordmark() {
  return (
    <div className="wordmark">
      <div className="wordmark-icon">
        <Icon.Key />
      </div>
      <div className="wordmark-text">
        <div className="wordmark-primary">HouseKey Vault</div>
        <div className="wordmark-secondary">Zero-Knowledge · AES-256</div>
      </div>
    </div>
  );
}

// ── STRENGTH METER ────────────────────────────────────────────────────────────
function StrengthMeter({ password }: { password: string }) {
  const { score, label, color } = scorePassword(password);
  return (
    <div>
      <div className="strength-row">
        {[1,2,3,4].map(i => (
          <div key={i} className="strength-seg" style={{ background: i <= score ? color : undefined }} />
        ))}
      </div>
      {label && <div className="strength-label" style={{ color }}>{label}</div>}
    </div>
  );
}

// ── TOAST ─────────────────────────────────────────────────────────────────────
function Toast({ msg, type = "default" }: { msg: string; type?: "default"|"ok"|"warn" }) {
  return <div className={`toast ${type !== "default" ? type : ""}`}>{msg}</div>;
}

// ── LANDING ───────────────────────────────────────────────────────────────────
function LandingScreen({ onCreate, onLogin }: { onCreate: () => void; onLogin: () => void }) {
  const supported = isFileSystemAccessSupported();
  return (
    <div className="screen">
      <Wordmark />
      <div className="card">
        <div className="card-eyebrow">Secure Credential Storage</div>
        <div className="card-title">Your key.<br />Your vault.</div>
        <div className="card-body">
          Authentication via cryptographic key pair stored on your USB device.
          No master password. No shared secrets. The private key never leaves your hardware.
        </div>
        {!supported && (
          <div className="alert alert-warn">
            <Icon.Alert />
            File System Access API requires Chrome or Edge 86+.
          </div>
        )}
        <div className="security-bar">
          {[["ECDSA P-256","Shield"],["AES-256-GCM","Shield"],["Zero-Knowledge","Shield"],["HIBP Checked","Shield"]].map(([label]) => (
            <div key={label} className="security-item">
              <Icon.Shield />
              {label}
            </div>
          ))}
        </div>
        <div className="btn-row">
          <button className="btn btn-primary" onClick={onCreate} disabled={!supported}>
            <Icon.Plus />
            New Vault
          </button>
          <button className="btn btn-outline" onClick={onLogin} disabled={!supported} style={{marginTop:0}}>
            <Icon.Unlock />
            Unlock Vault
          </button>
        </div>
      </div>
    </div>
  );
}

// ── CREATE ────────────────────────────────────────────────────────────────────
function CreateScreen({ onBack, onComplete }: { onBack: () => void; onComplete: (s: SessionState) => void }) {
  const [step, setStep] = useState(0);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [seedPhrase, setSeedPhrase] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [seedCopied, setSeedCopied] = useState(false);
  const sessionRef = useRef<SessionState | null>(null);

  const handleSetup = async () => {
    setError(""); setStep(1);
    try {
      setStatus("Generating ECDSA P-256 key pair");
      const { publicKeyB64, privateKeyB64, publicKeyHash } = await generateKeyPair();
      setStatus("Deriving vault encryption key via HKDF");
      const vault = emptyVault();
      const { encryptedVault, vaultIV } = await encryptVault(vault, privateKeyB64);
      setStatus("Writing private key to USB device");
      const keyFile: KeyFile = { privateKeyB64, publicKeyB64, publicKeyHash, createdAt: Date.now(), version: 1 };
      await setupUSBKey(keyFile);
      setStatus("Registering public key with server");
      await api.register({ publicKey: publicKeyB64, publicKeyHash, encryptedVault, vaultIV });
      setSeedPhrase(generateSeedPhrase());
      sessionRef.current = { privateKeyB64, publicKeyB64, publicKeyHash, vault };
      setStep(2);
    } catch (err: any) {
      setError(err.message ?? "Setup failed.");
      setStep(0);
    }
  };

  const copySeed = async () => {
    await navigator.clipboard.writeText(seedPhrase);
    setSeedCopied(true);
    setTimeout(() => setSeedCopied(false), 3000);
  };

  const handleFinish = () => {
    if (!confirmed || !sessionRef.current) return;
    setStep(3);
    setTimeout(() => onComplete(sessionRef.current!), 600);
  };

  return (
    <div className="screen">
      <Wordmark />
      <div className="card">
        <div className="steps">
          {[0,1,2].map(i => (
            <div key={i} className={`step-bar ${i < step ? "done" : i === Math.min(step,2) ? "active" : ""}`} />
          ))}
        </div>

        {error && <div className="alert alert-warn"><Icon.Alert />{error}</div>}

        {step === 0 && <>
          <div className="card-eyebrow">Step 1 of 3</div>
          <div className="card-title">Initialize USB key</div>
          <div className="card-body">
            Select your USB drive directory. A private key file
            (<code style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--gold)"}}>housekeyvault.hkv</code>) will be written to it.
            It never leaves your device.
          </div>
          <div className="usb-zone" onClick={handleSetup}>
            <div className="usb-visual"><Icon.USB /></div>
            <div className="usb-label">Select USB directory</div>
            <div className="usb-hint">Browser will prompt for folder access</div>
          </div>
          <button className="btn btn-ghost" onClick={onBack}>Back</button>
        </>}

        {step === 1 && <>
          <div className="card-eyebrow">Initializing</div>
          <div className="card-title">Setting up vault</div>
          <div className="card-body" style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--text3)"}}>
            {status}...
          </div>
          <div className="usb-zone active">
            <div className="usb-visual"><Icon.USB /></div>
            <div className="usb-label">Writing to device</div>
            <div className="usb-hint">Do not remove USB</div>
          </div>
        </>}

        {step === 2 && <>
          <div className="card-eyebrow">Step 2 of 3</div>
          <div className="card-title">Recovery phrase</div>
          <div className="card-body">
            Store this phrase in a secure offline location. It is the only way to recover your vault if the USB device is lost or damaged.
          </div>
          <div className="alert alert-warn">
            <Icon.Alert />
            This phrase will not be shown again. Write it down or copy it now.
          </div>
          <div className="seed-container">
            <div className="seed-header">
              <div className="seed-label">12-Word Recovery Phrase</div>
              <button className={`seed-copy-btn ${seedCopied ? "copied" : ""}`} onClick={copySeed}>
                {seedCopied ? <Icon.Check /> : <Icon.Copy />}
                {seedCopied ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="seed-grid">
              {seedPhrase.split(" ").map((word, i) => (
                <div key={i} className="seed-word">
                  <span className="seed-idx">{i+1}</span>
                  <span className="seed-val">{word}</span>
                </div>
              ))}
            </div>
          </div>
          <label style={{display:"flex",alignItems:"center",gap:10,fontSize:12,color:"var(--text2)",cursor:"pointer",marginBottom:20}}>
            <input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)}
              style={{accentColor:"var(--gold)"}} />
            I have securely stored my recovery phrase
          </label>
          <button className="btn btn-primary" onClick={handleFinish} disabled={!confirmed}>
            <Icon.Check />
            Complete Setup
          </button>
        </>}

        {step === 3 && <>
          <div className="card-eyebrow">Complete</div>
          <div className="card-title">Vault ready</div>
          <div className="alert alert-ok"><Icon.CheckCircle />Your vault has been created successfully.</div>
        </>}
      </div>
    </div>
  );
}

// ── LOGIN ─────────────────────────────────────────────────────────────────────
function LoginScreen({ onBack, onSuccess, onParanoia }: {
  onBack: () => void;
  onSuccess: (s: SessionState) => void;
  onParanoia: (remaining: number) => void;
}) {
  const [status, setStatus] = useState<"idle"|"loading"|"error">("idle");
  const [message, setMessage] = useState("");

  const handleLogin = async () => {
    setStatus("loading"); setMessage("Reading key file");
    try {
      const keyFile = await loadUSBKey();
      if (!keyFile) { setStatus("error"); setMessage("Key file not found on device."); return; }
      setMessage("Requesting challenge");
      const { challenge } = await api.getChallenge(keyFile.publicKeyHash);
      setMessage("Signing challenge");
      const signature = await signChallenge(keyFile.privateKeyB64, challenge);
      setMessage("Verifying signature");
      const result = await api.verify({ publicKeyHash: keyFile.publicKeyHash, challenge, signature });
      if (result.locked) { setTimeout(() => onParanoia(result.remaining ?? 300), 300); return; }
      if (!result.success || !result.encryptedVault) throw new Error("Authentication failed.");
      setMessage("Decrypting vault");
      const vault = await decryptVault(result.encryptedVault!, result.vaultIV!, keyFile.privateKeyB64);
      onSuccess({ ...keyFile, vault });
    } catch (err: any) {
      if (err?.data?.remaining) { onParanoia(err.data.remaining); return; }
      setStatus("error");
      setMessage(err.message ?? "Authentication failed.");
    }
  };

  return (
    <div className="screen">
      <Wordmark />
      <div className="card">
        <div className="card-eyebrow">Authentication</div>
        <div className="card-title">Insert key to unlock</div>
        <div className="card-body">
          Select the directory containing your{" "}
          <code style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--gold)"}}>housekeyvault.hkv</code>{" "}
          file. Authentication is performed via cryptographic challenge-response.
        </div>
        {status === "error" && (
          <div className="alert alert-warn"><Icon.Alert />{message}</div>
        )}
        <div className={`usb-zone ${status === "loading" ? "active" : ""}`}
          onClick={status !== "loading" ? handleLogin : undefined}>
          <div className="usb-visual">
            {status === "loading" ? <Icon.Lock /> : <Icon.Key />}
          </div>
          <div className="usb-label">
            {status === "loading" ? message : "Click to authenticate"}
          </div>
          <div className="usb-hint">
            {status === "idle" ? "ECDSA P-256 challenge-response" : ""}
          </div>
        </div>
        <button className="btn btn-ghost" onClick={onBack}>Back</button>
      </div>
    </div>
  );
}

// ── PARANOIA ──────────────────────────────────────────────────────────────────
function ParanoiaScreen({ remaining, onRetry }: { remaining: number; onRetry: () => void }) {
  const [count, setCount] = useState(remaining);
  useEffect(() => {
    if (count <= 0) return;
    const t = setInterval(() => setCount(c => c - 1), 1000);
    return () => clearInterval(t);
  }, []);
  const mm = String(Math.floor(count / 60)).padStart(2, "0");
  const ss = String(count % 60).padStart(2, "0");
  return (
    <div className="screen">
      <Wordmark />
      <div className="card paranoia-card">
        <div className="paranoia-icon"><Icon.Lock /></div>
        <div className="paranoia-title">Access Suspended</div>
        <div className="paranoia-sub">
          Multiple failed authentication attempts have been detected.
          Access to this vault has been temporarily suspended.
        </div>
        <div className="countdown">{mm}:{ss}</div>
        <div className="countdown-label">Time remaining</div>
        {count <= 0 && (
          <button className="btn btn-outline" onClick={onRetry} style={{marginTop: 24}}>
            Retry Authentication
          </button>
        )}
      </div>
    </div>
  );
}

// ── VAULT ─────────────────────────────────────────────────────────────────────
function VaultScreen({ session, onLogout }: { session: SessionState; onLogout: () => void }) {
  const [vault, setVault] = useState(session.vault);
  const [showAdd, setShowAdd] = useState(false);
  const [saving, setSaving] = useState(false);
  const [search, setSearch] = useState("");
  const [toast, setToast] = useState<{msg:string;type:"default"|"ok"|"warn"} | null>(null);
  const [visiblePw, setVisiblePw] = useState<Record<string,boolean>>({});
  const [checking, setChecking] = useState<Record<string,boolean>>({});
  const [newEntry, setNewEntry] = useState({ site: "", username: "", password: "", url: "", notes: "" });
  const [genOpts, setGenOpts] = useState({ length: 20, symbols: true, numbers: true, uppercase: true });

  // ── Folder state ──
  const [activeFolder, setActiveFolder] = useState<string | null>(null); // null = "All"
  const [showNewFolder, setShowNewFolder] = useState(false);
  const [newFolderName, setNewFolderName] = useState("");

  const showToast = (msg: string, type: "default"|"ok"|"warn" = "default") => {
    setToast({msg, type});
    setTimeout(() => setToast(null), 2500);
  };

  const persist = useCallback(async (updated: VaultData) => {
    setSaving(true);
    try {
      const { encryptedVault, vaultIV } = await encryptVault(updated, session.privateKeyB64);
      await api.saveVault(encryptedVault, vaultIV);
      setVault(updated);
    } catch { showToast("Failed to save vault", "warn"); }
    setSaving(false);
  }, [session.privateKeyB64]);

  const copy = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    showToast(`${label} copied to clipboard`, "ok");
  };

  // ── Folder handlers ──
  const addFolder = async () => {
    if (!newFolderName.trim()) return;
    const folder: VaultFolder = {
      id: crypto.randomUUID(),
      name: newFolderName.trim(),
      createdAt: Date.now(),
    };
    const updated = { ...vault, folders: [...(vault.folders ?? []), folder] };
    await persist(updated);
    setNewFolderName("");
    setShowNewFolder(false);
    showToast("Folder created", "ok");
  };

  const deleteFolder = async (id: string) => {
    const updatedEntries = vault.entries.map(e =>
      e.folderId === id ? { ...e, folderId: undefined } : e
    );
    const updated = {
      ...vault,
      folders: (vault.folders ?? []).filter(f => f.id !== id),
      entries: updatedEntries,
    };
    await persist(updated);
    if (activeFolder === id) setActiveFolder(null);
    showToast("Folder deleted");
  };

  // ── Entry handlers ──
  const addEntry = async () => {
    if (!newEntry.site || !newEntry.username || !newEntry.password) return;
    const entry: VaultEntry = {
      id: crypto.randomUUID(), ...newEntry,
      folderId: activeFolder ?? undefined,
      createdAt: Date.now(), updatedAt: Date.now(),
    };
    await persist({ ...vault, entries: [...vault.entries, entry] });
    setNewEntry({ site: "", username: "", password: "", url: "", notes: "" });
    setShowAdd(false);
    showToast("Entry saved", "ok");
  };

  const deleteEntry = async (id: string) => {
    await persist({ ...vault, entries: vault.entries.filter(e => e.id !== id) });
    showToast("Entry deleted");
  };

  const checkBreach = async (entry: VaultEntry) => {
    setChecking(c => ({ ...c, [entry.id]: true }));
    try {
      const count = await api.checkBreached(entry.password);
      const updated = vault.entries.map(e => e.id === entry.id ? { ...e, breached: count > 0 } : e);
      await persist({ ...vault, entries: updated });
      if (count > 0) showToast(`Found in ${count.toLocaleString()} breaches — update immediately`, "warn");
      else showToast("Password not found in known breaches", "ok");
    } catch { showToast("Breach check unavailable", "warn"); }
    setChecking(c => ({ ...c, [entry.id]: false }));
  };

  const genPw = () => setNewEntry(e => ({ ...e, password: generatePassword(genOpts) }));
  const toggleOpt = (k: keyof typeof genOpts) => setGenOpts(o => ({ ...o, [k]: !o[k] }));

  const folders = vault.folders ?? [];

  const filtered = vault.entries.filter(e => {
    const matchesSearch = !search ||
      e.site.toLowerCase().includes(search.toLowerCase()) ||
      e.username.toLowerCase().includes(search.toLowerCase());
    const matchesFolder = activeFolder === null || e.folderId === activeFolder;
    return matchesSearch && matchesFolder;
  });

  const breachedCount = vault.entries.filter(e => e.breached).length;

  return (
    <div className="screen screen-wide">
      <div className="vault-topbar">
        <Wordmark />
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div className="vault-status-pill">
            <div className="status-dot" />
            {saving ? "Encrypting" : "Vault Secure"}
          </div>
          <button className="lock-btn" onClick={onLogout}>
            <Icon.Lock />
            Lock Vault
          </button>
        </div>
      </div>

      <div className="card">
        {breachedCount > 0 && (
          <div className="alert alert-warn" style={{marginBottom:16}}>
            <Icon.Alert />
            {breachedCount} password{breachedCount > 1 ? "s" : ""} found in known data breaches. Update them immediately.
          </div>
        )}

        <div className="vault-toolbar">
          <div className="vault-info-row">
            <div className="vault-title">Credentials</div>
            <div className="vault-meta">{vault.entries.length} entries · AES-256-GCM · Zero-knowledge</div>
          </div>
          <div className="toolbar-right">
            <div className="search-wrap">
              <Icon.Search />
              <input
                className="search-inp"
                placeholder="Search..."
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <button className="add-btn" onClick={() => setShowAdd(s => !s)}>
              {showAdd ? <>
                <svg viewBox="0 0 24 24" width="13" height="13" stroke="var(--ink)" fill="none" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
                Cancel
              </> : <>
                <Icon.Plus />
                Add Entry
              </>}
            </button>
          </div>
        </div>

        {/* ── FOLDER BAR ── */}
        <div className="folder-bar">
          <button
            className={`folder-chip ${activeFolder === null ? "active" : ""}`}
            onClick={() => setActiveFolder(null)}
          >
            All
          </button>
          {folders.map(f => (
            <button
              key={f.id}
              className={`folder-chip ${activeFolder === f.id ? "active" : ""}`}
              onClick={() => setActiveFolder(f.id)}
            >
              📁 {f.name}
              <span
                className="folder-del"
                onClick={e => { e.stopPropagation(); deleteFolder(f.id); }}
                title="Delete folder"
              >×</span>
            </button>
          ))}
          {showNewFolder ? (
            <div className="folder-new-row">
              <input
                className="inp"
                placeholder="Folder name"
                value={newFolderName}
                onChange={e => setNewFolderName(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") addFolder(); if (e.key === "Escape") setShowNewFolder(false); }}
                autoFocus
              />
              <button className="btn btn-primary" onClick={addFolder}>Add</button>
              <button className="btn btn-outline" onClick={() => { setShowNewFolder(false); setNewFolderName(""); }}>Cancel</button>
            </div>
          ) : (
            <button className="folder-chip" onClick={() => setShowNewFolder(true)}>+ New Folder</button>
          )}
        </div>

        {showAdd && (
          <div className="add-form">
            <div className="form-section-label">Service Details</div>
            <div className="form-row">
              <div className="field">
                <div className="field-label">Website / Service</div>
                <input className="inp" placeholder="github.com" value={newEntry.site}
                  onChange={e => setNewEntry(n => ({...n, site: e.target.value}))} />
              </div>
              <div className="field">
                <div className="field-label">URL (optional)</div>
                <input className="inp" placeholder="https://..." value={newEntry.url}
                  onChange={e => setNewEntry(n => ({...n, url: e.target.value}))} />
              </div>
            </div>
            <div className="field">
              <div className="field-label">Username / Email</div>
              <input className="inp" placeholder="you@email.com" value={newEntry.username}
                onChange={e => setNewEntry(n => ({...n, username: e.target.value}))} />
            </div>
            <div className="form-section-label">Password</div>
            <div className="gen-options">
              {(["symbols","numbers","uppercase"] as const).map(k => (
                <button key={k} className={`gen-chip ${genOpts[k] ? "on" : ""}`} onClick={() => toggleOpt(k)}>
                  {k}
                </button>
              ))}
              {[16, 20, 24, 32].map(l => (
                <button key={l} className={`gen-chip ${genOpts.length === l ? "on" : ""}`}
                  onClick={() => setGenOpts(o => ({...o, length: l}))}>
                  {l} chars
                </button>
              ))}
            </div>
            <div className="pw-field-row">
              <div className="field">
                <div className="field-label">Password</div>
                <input className="inp" type="text" placeholder="Enter or generate"
                  value={newEntry.password}
                  onChange={e => setNewEntry(n => ({...n, password: e.target.value}))} />
                <StrengthMeter password={newEntry.password} />
              </div>
              <button className="gen-btn" onClick={genPw} title="Generate password">
                <Icon.Shuffle />
              </button>
            </div>
            <div className="field">
              <div className="field-label">Notes (optional)</div>
              <input className="inp" placeholder="2FA backup codes, recovery email..."
                value={newEntry.notes}
                onChange={e => setNewEntry(n => ({...n, notes: e.target.value}))} />
            </div>
            {activeFolder && (
              <div style={{fontFamily:"var(--mono)",fontSize:10,color:"var(--gold)",marginTop:8,letterSpacing:"0.05em"}}>
                📁 Will be saved to: {folders.find(f => f.id === activeFolder)?.name}
              </div>
            )}
            <div className="form-actions">
              <button className="btn btn-primary" onClick={addEntry}
                disabled={!newEntry.site || !newEntry.username || !newEntry.password}>
                Save Entry
              </button>
              <button className="btn btn-outline form-cancel" onClick={() => setShowAdd(false)}>
                Cancel
              </button>
            </div>
          </div>
        )}

        {filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon"><Icon.Vault /></div>
            <div className="empty-title">{search ? "No results found" : activeFolder ? "This folder is empty" : "Vault is empty"}</div>
            <div className="empty-sub">
              {search ? "Try a different search term" : "Add your first credential above"}
            </div>
          </div>
        ) : (
          <div className="entries">
            {filtered.map(entry => (
              <div key={entry.id} className={`entry-card ${entry.breached ? "breached" : ""}`}>
                <div className="entry-avatar">
                  {entry.site.replace(/^https?:\/\//, "").charAt(0)}
                </div>
                <div className="entry-info">
                  <div className="entry-site">
                    {entry.site}
                    {entry.breached && <span className="badge badge-danger">Breached</span>}
                    {entry.breached === false && <span className="badge badge-safe">Verified</span>}
                    {entry.folderId && activeFolder === null && (
                      <span className="badge" style={{background:"var(--gold-dim)",color:"var(--gold)",border:"1px solid rgba(201,168,76,0.2)"}}>
                        📁 {folders.find(f => f.id === entry.folderId)?.name}
                      </span>
                    )}
                  </div>
                  <div className="entry-user">{entry.username}</div>
                  {visiblePw[entry.id] && (
                    <div className="entry-pw-reveal">{entry.password}</div>
                  )}
                </div>
                <div className="entry-actions">
                  <button className="icon-btn" title="Copy password" onClick={() => copy(entry.password, "Password")}>
                    <Icon.Copy />
                  </button>
                  <button className="icon-btn" title="Copy username" onClick={() => copy(entry.username, "Username")}>
                    <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" strokeWidth="1.5">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
                    </svg>
                  </button>
                  <button className={`icon-btn ${visiblePw[entry.id] ? "active" : ""}`}
                    title="Toggle visibility"
                    onClick={() => setVisiblePw(v => ({...v, [entry.id]: !v[entry.id]}))}>
                    {visiblePw[entry.id] ? <Icon.EyeOff /> : <Icon.Eye />}
                  </button>
                  <button className="icon-btn" title="Check for breaches"
                    disabled={checking[entry.id]}
                    onClick={() => checkBreach(entry)}
                    style={{opacity: checking[entry.id] ? 0.4 : 1}}>
                    <Icon.Shield />
                  </button>
                  <button className="icon-btn danger" title="Delete entry" onClick={() => deleteEntry(entry.id)}>
                    <Icon.Trash />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      {toast && <Toast msg={toast.msg} type={toast.type} />}
    </div>
  );
}

// ── ROOT ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [screen, setScreen] = useState<Screen>("landing");
  const [session, setSession] = useState<SessionState | null>(null);
  const [paranoia, setParanoia] = useState(0);

  const handleLogout = async () => {
    await api.logout().catch(() => {});
    setSession(null);
    setScreen("landing");
  };

  return (
    <>
      <style>{CSS}</style>
      <div className={`app ${screen === "paranoia" ? "paranoia-screen" : ""}`}>
        {screen === "landing" && (
          <LandingScreen onCreate={() => setScreen("create")} onLogin={() => setScreen("login")} />
        )}
        {screen === "create" && (
          <CreateScreen onBack={() => setScreen("landing")} onComplete={s => { setSession(s); setScreen("vault"); }} />
        )}
        {screen === "login" && (
          <LoginScreen onBack={() => setScreen("landing")}
            onSuccess={s => { setSession(s); setScreen("vault"); }}
            onParanoia={r => { setParanoia(r); setScreen("paranoia"); }} />
        )}
        {screen === "vault" && session && (
          <VaultScreen session={session} onLogout={handleLogout} />
        )}
        {screen === "paranoia" && (
          <ParanoiaScreen remaining={paranoia} onRetry={() => setScreen("login")} />
        )}
      </div>
    </>
  );
}
