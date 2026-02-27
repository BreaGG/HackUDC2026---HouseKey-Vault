"use client";

import { useState, useCallback, useRef } from "react";
import {
  generateKeyPair, signChallenge, encryptVault, decryptVault,
  generateSeedPhrase, generatePassword, scorePassword, emptyVault,
  type VaultData, type VaultEntry,
} from "@/lib/crypto-client";
import { setupUSBKey, loadUSBKey, isFileSystemAccessSupported, type KeyFile } from "@/lib/usb-storage";
import { api } from "@/lib/api-client";

type Screen = "landing" | "create" | "login" | "vault" | "paranoia";
interface SessionState {
  privateKeyB64: string; publicKeyB64: string;
  publicKeyHash: string; vault: VaultData;
}

// ─────────────────────────────────────────────────────────────────────────────
// DESIGN SYSTEM
// ─────────────────────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;500;600&family=IBM+Plex+Mono:wght@300;400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root {
  --ink:        #0C0C0F;
  --ink2:       #14141A;
  --ink3:       #1C1C24;
  --ink4:       #26262F;
  --line:       rgba(255,255,255,0.07);
  --line2:      rgba(255,255,255,0.12);
  --gold:       #C9A84C;
  --gold2:      #E2C06A;
  --gold-dim:   rgba(201,168,76,0.15);
  --gold-glow:  rgba(201,168,76,0.06);
  --crimson:    #C0392B;
  --crimson-dim:rgba(192,57,43,0.15);
  --jade:       #27AE8F;
  --jade-dim:   rgba(39,174,143,0.12);
  --text:       #E8E6E0;
  --text2:      #9A9890;
  --text3:      #5A5856;
  --display:    'Playfair Display', Georgia, serif;
  --sans:       'IBM Plex Sans', system-ui, sans-serif;
  --mono:       'IBM Plex Mono', 'Courier New', monospace;
  --r:          6px;
  --r2:         10px;
  --shadow:     0 1px 3px rgba(0,0,0,.4),0 8px 32px rgba(0,0,0,.3);
}

html,body{background:var(--ink);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh}

/* ── APP SHELL ── */
.app{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;position:relative;overflow:hidden}
.app::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(201,168,76,.04) 0%,transparent 60%),radial-gradient(ellipse 50% 80% at 100% 100%,rgba(39,174,143,.03) 0%,transparent 50%);pointer-events:none}
.app::after{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(255,255,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.015) 1px,transparent 1px);background-size:48px 48px;pointer-events:none}

/* ── SCREENS ── */
.screen{width:100%;max-width:480px;position:relative;z-index:1;animation:appear .5s cubic-bezier(.16,1,.3,1) forwards}
.screen-full{max-width:1100px;width:100%}

@keyframes appear{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}

/* ── WORDMARK ── */
.wordmark{display:flex;align-items:flex-end;gap:12px;margin-bottom:28px}
.wm-icon{width:36px;height:36px;border:1px solid var(--gold);display:flex;align-items:center;justify-content:center;position:relative;flex-shrink:0}
.wm-icon::before{content:'';position:absolute;inset:3px;border:1px solid rgba(201,168,76,.3)}
.wm-icon svg{width:16px;height:16px;stroke:var(--gold);fill:none;stroke-width:1.5}
.wm-name{font-family:var(--display);font-size:17px;font-weight:500;color:var(--text);line-height:1}
.wm-sub{font-family:var(--mono);font-size:9px;font-weight:300;letter-spacing:.25em;color:var(--text3);text-transform:uppercase;line-height:1;margin-top:4px}

/* ── CARD ── */
.card{background:var(--ink2);border:1px solid var(--line2);border-radius:var(--r2);padding:28px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--gold-dim),transparent)}

.eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.2em;color:var(--gold);text-transform:uppercase;margin-bottom:10px;display:flex;align-items:center;gap:8px}
.eyebrow::after{content:'';flex:1;height:1px;background:var(--line)}
.h1{font-family:var(--display);font-size:26px;font-weight:400;letter-spacing:-.01em;line-height:1.2;margin-bottom:8px}
.h2{font-family:var(--display);font-size:20px;font-weight:400;margin-bottom:4px}
.body{font-size:13px;color:var(--text2);line-height:1.7;margin-bottom:22px}

/* ── VAULT LAYOUT (horizontal 2-col) ── */
.vault-shell{display:flex;flex-direction:column;gap:0;width:100%}

.vault-topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px}

.vault-body{display:grid;grid-template-columns:280px 1fr;gap:14px;align-items:start}

@media(max-width:860px){.vault-body{grid-template-columns:1fr}}

/* ── SIDEBAR ── */
.sidebar{display:flex;flex-direction:column;gap:10px;position:sticky;top:24px}

.sidebar-card{background:var(--ink2);border:1px solid var(--line2);border-radius:var(--r2);padding:20px;position:relative;overflow:hidden}
.sidebar-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--gold-dim),transparent)}

.nav-label{font-family:var(--mono);font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--text3);margin-bottom:10px}

.nav-btn{width:100%;padding:9px 12px;border-radius:var(--r);border:none;background:transparent;color:var(--text3);font-family:var(--sans);font-size:12px;font-weight:500;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:9px;text-align:left}
.nav-btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:1.5;flex-shrink:0}
.nav-btn:hover{background:var(--ink3);color:var(--text)}
.nav-btn.active{background:var(--gold-dim);color:var(--gold);border:1px solid rgba(201,168,76,.25)}
.nav-badge{margin-left:auto;background:var(--crimson);color:#fff;font-family:var(--mono);font-size:9px;padding:1px 6px;border-radius:10px}

.health-mini{display:flex;flex-direction:column;gap:6px}
.hm-row{display:flex;align-items:center;justify-content:space-between}
.hm-label{font-family:var(--mono);font-size:10px;color:var(--text3)}
.hm-val{font-family:var(--mono);font-size:13px;font-weight:500}
.hm-bar{height:3px;background:var(--line);border-radius:2px;margin-top:2px;overflow:hidden}
.hm-bar-fill{height:100%;border-radius:2px;transition:width .8s ease}

.score-ring-wrap{display:flex;align-items:center;gap:14px;margin-bottom:14px}
.score-ring-label{font-family:var(--display);font-size:15px;font-weight:400}
.score-ring-sub{font-family:var(--mono);font-size:9px;color:var(--text3);margin-top:2px}

/* ── STATUS PILL ── */
.status-pill{display:flex;align-items:center;gap:6px;padding:5px 12px;background:var(--jade-dim);border:1px solid rgba(39,174,143,.2);border-radius:20px;font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--jade);text-transform:uppercase}
.status-dot{width:6px;height:6px;border-radius:50%;background:var(--jade);animation:pulse 2.5s ease infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* ── LOCK BTN ── */
.lock-btn{padding:6px 14px;background:transparent;border:1px solid var(--line2);border-radius:var(--r);color:var(--text3);font-family:var(--sans);font-size:11px;font-weight:500;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:6px}
.lock-btn svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5}
.lock-btn:hover{border-color:var(--crimson);color:var(--crimson)}

/* ── MAIN PANEL ── */
.main-panel{display:flex;flex-direction:column;gap:14px}

/* ── TOOLBAR ── */
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.toolbar-left{display:flex;flex-direction:column;gap:2px}
.toolbar-right{display:flex;align-items:center;gap:8px}

.panel-title{font-family:var(--display);font-size:18px;font-weight:400}
.panel-meta{font-family:var(--mono);font-size:10px;color:var(--text3);letter-spacing:.06em}

/* ── SEARCH ── */
.search-wrap{position:relative}
.search-wrap svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);width:13px;height:13px;stroke:var(--text3);fill:none;stroke-width:1.5;pointer-events:none}
.search-inp{background:var(--ink3);border:1px solid var(--line);border-radius:var(--r);padding:8px 12px 8px 32px;color:var(--text);font-family:var(--mono);font-size:12px;outline:none;width:190px;transition:border-color .2s}
.search-inp:focus{border-color:rgba(201,168,76,.4)}
.search-inp::placeholder{color:var(--text3)}

/* ── ADD BTN ── */
.add-btn{padding:8px 16px;background:var(--gold);color:var(--ink);border:none;border-radius:var(--r);font-family:var(--sans);font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:6px;white-space:nowrap}
.add-btn svg{width:13px;height:13px;stroke:var(--ink);fill:none;stroke-width:2}
.add-btn:hover{background:var(--gold2);transform:translateY(-1px);box-shadow:0 4px 16px rgba(201,168,76,.2)}

/* ── ENTRIES ── */
.entries{display:flex;flex-direction:column;gap:5px}

.entry-card{background:var(--ink3);border:1px solid var(--line);border-radius:var(--r2);padding:12px 14px;display:flex;align-items:center;gap:12px;transition:all .18s}
.entry-card:hover{border-color:var(--line2);background:var(--ink4)}
.entry-card.breached{border-color:rgba(192,57,43,.3);background:rgba(192,57,43,.04)}

.entry-avatar{width:32px;height:32px;background:var(--ink4);border:1px solid var(--line);border-radius:var(--r);display:flex;align-items:center;justify-content:center;font-family:var(--display);font-size:13px;font-weight:500;color:var(--text2);flex-shrink:0;text-transform:uppercase}
.entry-info{flex:1;min-width:0;overflow:hidden}
.entry-site{font-size:13px;font-weight:500;color:var(--text);margin-bottom:2px;display:flex;align-items:center;gap:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.entry-user{font-family:var(--mono);font-size:11px;color:var(--text3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.entry-pw{font-family:var(--mono);font-size:11px;color:var(--gold);margin-top:3px;word-break:break-all;line-height:1.4}
.entry-actions{display:flex;align-items:center;gap:3px;flex-shrink:0}

.icon-btn{width:28px;height:28px;border-radius:var(--r);border:1px solid transparent;background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .18s;color:var(--text3)}
.icon-btn svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:1.5}
.icon-btn:hover{background:var(--ink4);border-color:var(--line2);color:var(--text)}
.icon-btn.danger:hover{background:var(--crimson-dim);border-color:rgba(192,57,43,.3);color:var(--crimson)}
.icon-btn.active{color:var(--jade)}
.icon-btn:disabled{opacity:.3;cursor:not-allowed}

/* ── BADGES ── */
.badge{display:inline-flex;align-items:center;padding:2px 7px;border-radius:3px;font-family:var(--mono);font-size:9px;font-weight:500;letter-spacing:.08em;text-transform:uppercase}
.badge-danger{background:var(--crimson-dim);color:#E07070;border:1px solid rgba(192,57,43,.25)}
.badge-safe{background:var(--jade-dim);color:var(--jade);border:1px solid rgba(39,174,143,.25)}

/* ── ADD FORM ── */
.add-form{background:var(--ink3);border:1px solid rgba(201,168,76,.2);border-radius:var(--r2);padding:20px;animation:appear .25s cubic-bezier(.16,1,.3,1)}

.sec-label{font-family:var(--mono);font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--text3);margin-bottom:8px;margin-top:14px}
.sec-label:first-child{margin-top:0}

.form-row{display:flex;gap:10px}
.form-row .field{flex:1}
.field{display:flex;flex-direction:column;gap:5px;margin-bottom:8px}
.field-label{font-family:var(--mono);font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:var(--text3)}

.inp{background:var(--ink2);border:1px solid var(--line);border-radius:var(--r);padding:8px 12px;color:var(--text);font-family:var(--mono);font-size:12px;outline:none;width:100%;transition:border-color .2s}
.inp:focus{border-color:rgba(201,168,76,.4)}
.inp::placeholder{color:var(--text3)}

/* ── GEN MODE ── */
.gen-mode-row{display:flex;gap:6px;margin-bottom:10px}
.mode-btn{flex:1;padding:8px 10px;border-radius:var(--r);border:1px solid var(--line);background:transparent;color:var(--text3);font-family:var(--sans);font-size:11px;font-weight:500;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.mode-btn svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5}
.mode-btn:hover{border-color:var(--line2);color:var(--text2)}
.mode-btn.active{background:var(--gold-dim);border-color:rgba(201,168,76,.4);color:var(--gold)}

/* ── GEN CHIPS ── */
.chips{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px}
.chip{padding:4px 10px;border-radius:3px;border:1px solid var(--line);background:transparent;font-family:var(--mono);font-size:10px;color:var(--text3);cursor:pointer;transition:all .15s}
.chip.on{background:var(--gold-dim);border-color:rgba(201,168,76,.4);color:var(--gold)}

/* ── PW ROW ── */
.pw-row{display:flex;gap:8px;align-items:flex-start}
.pw-row .field{flex:1}
.gen-btns{display:flex;flex-direction:column;gap:4px;padding-top:22px}

.gen-btn{width:34px;height:34px;background:var(--ink2);border:1px solid var(--line2);border-radius:var(--r);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;flex-shrink:0}
.gen-btn svg{width:13px;height:13px;stroke:var(--text2);fill:none;stroke-width:1.5}
.gen-btn:hover{border-color:var(--gold)}
.gen-btn:hover svg{stroke:var(--gold)}
.gen-btn:disabled{opacity:.3;cursor:not-allowed}
.gen-btn:disabled:hover{border-color:var(--line2)}
.gen-btn:disabled:hover svg{stroke:var(--text2)}

.entropy-note{font-family:var(--mono);font-size:9px;color:var(--text3);padding:0 2px;margin-top:-4px}

/* ── STRENGTH ── */
.str-row{display:flex;gap:3px;margin-top:5px}
.str-seg{height:2px;flex:1;border-radius:1px;background:var(--line);transition:background .3s}
.str-label{font-family:var(--mono);font-size:9px;margin-top:3px}

/* ── LLM PANEL ── */
.llm-panel{display:flex;flex-direction:column;gap:8px}
.llm-styles{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:2px}
.llm-suggestions{display:flex;flex-direction:column;gap:5px}

.llm-sugg{background:var(--ink2);border:1px solid var(--line);border-radius:var(--r);padding:10px 14px;cursor:pointer;transition:all .18s}
.llm-sugg:hover{border-color:var(--gold)}
.llm-sugg.selected{border-color:var(--gold);background:var(--gold-glow)}
.llm-pw{font-family:var(--mono);font-size:13px;color:var(--gold2);display:block;margin-bottom:4px;word-break:break-all}

/* ── FORM ACTIONS ── */
.form-actions{display:flex;gap:8px;margin-top:14px}
.form-actions .btn{padding:10px 16px;font-size:11px}
.btn-cancel{width:auto;flex:0;padding:10px 16px}

/* ── EMPTY ── */
.empty{text-align:center;padding:48px 24px;color:var(--text3)}
.empty-icon{width:44px;height:44px;border:1px solid var(--line);border-radius:50%;margin:0 auto 14px;display:flex;align-items:center;justify-content:center}
.empty-icon svg{width:18px;height:18px;stroke:var(--text3);fill:none;stroke-width:1}
.empty-title{font-size:13px;font-weight:500;color:var(--text2);margin-bottom:4px}
.empty-sub{font-family:var(--mono);font-size:11px;color:var(--text3)}

/* ── BUTTONS ── */
.btn{width:100%;padding:12px 20px;border-radius:var(--r);border:none;font-family:var(--sans);font-size:13px;font-weight:500;letter-spacing:.04em;cursor:pointer;transition:all .2s cubic-bezier(.16,1,.3,1);display:flex;align-items:center;justify-content:center;gap:8px;text-transform:uppercase}
.btn-primary{background:var(--gold);color:var(--ink)}
.btn-primary:hover:not(:disabled){background:var(--gold2);transform:translateY(-1px);box-shadow:0 4px 24px rgba(201,168,76,.25)}
.btn-outline{background:transparent;color:var(--text2);border:1px solid var(--line2);margin-top:10px}
.btn-outline:hover:not(:disabled){border-color:var(--gold);color:var(--gold)}
.btn-ghost{background:transparent;color:var(--text3);border:none;margin-top:6px;font-size:12px;padding:10px}
.btn-ghost:hover{color:var(--text2)}
.btn-row{display:flex;gap:10px}
.btn-row .btn{flex:1}
.btn:disabled{opacity:.35;cursor:not-allowed}

/* ── ALERTS ── */
.alert{border-radius:var(--r);padding:11px 14px;font-size:12px;line-height:1.6;margin-bottom:14px;display:flex;gap:10px;align-items:flex-start}
.alert svg{width:14px;height:14px;flex-shrink:0;margin-top:1px}
.alert-warn{background:var(--crimson-dim);border:1px solid rgba(192,57,43,.25);color:#E07070}
.alert-warn svg{stroke:#E07070;fill:none;stroke-width:1.5}
.alert-ok{background:var(--jade-dim);border:1px solid rgba(39,174,143,.25);color:var(--jade)}
.alert-ok svg{stroke:var(--jade);fill:none;stroke-width:1.5}

/* ── STEPS ── */
.steps{display:flex;gap:4px;margin-bottom:28px}
.step-bar{height:2px;flex:1;background:var(--line2);border-radius:1px;overflow:hidden;position:relative}
.step-bar.done::after{content:'';position:absolute;inset:0;background:var(--gold)}
.step-bar.active::after{content:'';position:absolute;inset:0;background:var(--gold);animation:fillBar .4s ease forwards}
@keyframes fillBar{from{transform:scaleX(0);transform-origin:left}to{transform:scaleX(1);transform-origin:left}}

/* ── USB ZONE ── */
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
.usb-hint{font-family:var(--mono);font-size:11px;color:var(--text3);position:relative;z-index:1}

/* ── SEED ── */
.seed-box{background:var(--ink);border:1px solid var(--line2);border-radius:var(--r2);padding:16px;margin:14px 0}
.seed-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.seed-label{font-family:var(--mono);font-size:10px;letter-spacing:.18em;color:var(--text3);text-transform:uppercase}
.seed-copy{display:flex;align-items:center;gap:6px;padding:5px 12px;background:transparent;border:1px solid var(--line2);border-radius:var(--r);color:var(--text2);font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;transition:all .2s}
.seed-copy:hover{border-color:var(--gold);color:var(--gold)}
.seed-copy.copied{border-color:var(--jade);color:var(--jade)}
.seed-copy svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5}
.seed-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:5px}
.seed-word{background:var(--ink2);border:1px solid var(--line);border-radius:var(--r);padding:6px 10px;display:flex;align-items:center;gap:7px;font-family:var(--mono)}
.seed-idx{font-size:9px;color:var(--text3);min-width:14px;font-weight:300}
.seed-val{font-size:11px;font-weight:400;color:var(--gold2)}

/* ── SECURITY BAR ── */
.sec-bar{display:flex;align-items:center;gap:14px;padding:10px 16px;background:var(--ink3);border:1px solid var(--line);border-radius:var(--r);margin-bottom:14px;flex-wrap:wrap}
.sec-item{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--text3)}
.sec-item svg{width:11px;height:11px;stroke:var(--jade);fill:none;stroke-width:1.5}

/* ── DIVIDER ── */
.divider{height:1px;background:var(--line);margin:18px 0}

/* ── TOAST ── */
.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);background:var(--ink3);border:1px solid var(--line2);border-radius:var(--r);padding:10px 20px;font-family:var(--mono);font-size:11px;letter-spacing:.05em;color:var(--text);box-shadow:var(--shadow);animation:toastIn .3s cubic-bezier(.16,1,.3,1);z-index:999;white-space:nowrap}
.toast.ok{border-color:rgba(39,174,143,.3);color:var(--jade)}
.toast.warn{border-color:rgba(192,57,43,.3);color:#E07070}
@keyframes toastIn{from{opacity:0;transform:translateX(-50%) translateY(10px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}

/* ── PARANOIA ── */
.paranoia-bg{background:radial-gradient(ellipse 60% 60% at 50% 50%,rgba(192,57,43,.06) 0%,transparent 70%),var(--ink)}
.p-icon{width:72px;height:72px;border:1px solid rgba(192,57,43,.4);border-radius:50%;margin:0 auto 24px;display:flex;align-items:center;justify-content:center;animation:pPulse 1.5s ease infinite}
.p-icon svg{width:28px;height:28px;stroke:var(--crimson);fill:none;stroke-width:1.5}
@keyframes pPulse{0%,100%{box-shadow:0 0 0 0 rgba(192,57,43,.3)}50%{box-shadow:0 0 0 12px rgba(192,57,43,0)}}
.p-title{font-family:var(--display);font-size:26px;font-weight:400;color:var(--crimson);margin-bottom:8px;text-align:center}
.p-sub{font-size:13px;color:#9A7070;line-height:1.7;margin-bottom:24px;text-align:center}
.countdown{font-family:var(--mono);font-size:48px;font-weight:300;color:var(--crimson);letter-spacing:-2px;margin-bottom:6px;text-align:center}
.countdown-label{font-family:var(--mono);font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--text3);text-align:center}
`;

// ─────────────────────────────────────────────────────────────────────────────
// ICONS
// ─────────────────────────────────────────────────────────────────────────────
const I = {
  Key:     ()=><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M12 15h8M17 15v-2"/></svg>,
  Lock:    ()=><svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="11" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>,
  Unlock:  ()=><svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="11" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.75-1"/></svg>,
  USB:     ()=><svg viewBox="0 0 24 24"><path d="M12 2v14M8 12l4 4 4-4M6 19h12"/></svg>,
  Shield:  ()=><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Copy:    ()=><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>,
  Check:   ()=><svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>,
  Eye:     ()=><svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
  EyeOff:  ()=><svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>,
  Trash:   ()=><svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>,
  Search:  ()=><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>,
  Plus:    ()=><svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>,
  Shuffle: ()=><svg viewBox="0 0 24 24"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>,
  Alert:   ()=><svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  OkCircle:()=><svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>,
  Vault:   ()=><svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="18" rx="2"/><circle cx="12" cy="12" r="3"/><path d="M12 2v1M12 21v1M2 12H1M23 12h-1"/></svg>,
  Brain:   ()=><svg viewBox="0 0 24 24"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.44-3.14A2.5 2.5 0 0 1 9.5 2"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.44-3.14A2.5 2.5 0 0 0 14.5 2"/></svg>,
  Dice:    ()=><svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="20" rx="3"/><circle cx="8" cy="8" r="1.5" fill="currentColor" stroke="none"/><circle cx="16" cy="8" r="1.5" fill="currentColor" stroke="none"/><circle cx="8" cy="16" r="1.5" fill="currentColor" stroke="none"/><circle cx="16" cy="16" r="1.5" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none"/></svg>,
  X:       ()=><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
};

// ─────────────────────────────────────────────────────────────────────────────
// SHARED COMPONENTS
// ─────────────────────────────────────────────────────────────────────────────

function Wordmark({ compact }: { compact?: boolean }) {
  return (
    <div className="wordmark" style={compact ? { marginBottom: 0 } : {}}>
      <div className="wm-icon"><I.Key /></div>
      <div>
        <div className="wm-name">HouseKey Vault</div>
        <div className="wm-sub">Zero-Knowledge · AES-256</div>
      </div>
    </div>
  );
}

function StrengthMeter({ pw }: { pw: string }) {
  const { score, label, color } = scorePassword(pw);
  return (
    <div>
      <div className="str-row">
        {[1,2,3,4].map(i => (
          <div key={i} className="str-seg" style={{ background: i <= score ? color : undefined }} />
        ))}
      </div>
      {label && <div className="str-label" style={{ color }}>{label}</div>}
    </div>
  );
}

function Toast({ msg, type = "default" }: { msg: string; type?: "default"|"ok"|"warn" }) {
  return <div className={`toast ${type !== "default" ? type : ""}`}>{msg}</div>;
}

// ─────────────────────────────────────────────────────────────────────────────
// PASSWORD GENERATOR PANEL (used in add form)
// ─────────────────────────────────────────────────────────────────────────────
type GenMode = "crypto" | "llm";
type LLMStyle = "passphrase" | "creative" | "technical" | "poetic";

interface GenPanelProps {
  value: string;
  onChange: (v: string) => void;
  onToast: (msg: string, type?: "ok"|"warn") => void;
}

function GenPanel({ value, onChange, onToast }: GenPanelProps) {
  const [mode, setMode] = useState<GenMode>("crypto");
  const [opts, setOpts] = useState({ length: 20, symbols: true, numbers: true, uppercase: true });
  const [loading, setLoading] = useState<"rng"|"llm"|null>(null);
  const [llmStyle, setLLMStyle] = useState<LLMStyle>("passphrase");
  const [theme, setTheme] = useState("");
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [entropy, setEntropy] = useState("");

  const toggleOpt = (k: keyof typeof opts) => setOpts(o => ({ ...o, [k]: !o[k] }));

  const genCrypto = () => {
    onChange(generatePassword(opts));
    setEntropy("Browser crypto.getRandomValues");
  };

  const genRandom = async () => {
    setLoading("rng");
    try {
      const res = await fetch("/api/random-password", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(opts),
      });
      const data = await res.json();
      if (data.password) {
        onChange(data.password);
        const src = data.source === "random.org" ? "Random.org hardware RNG" : "crypto.getRandomValues";
        setEntropy(src);
        onToast(`Entropy: ${src}`, "ok");
      }
    } catch { onToast("Random.org unavailable", "warn"); }
    setLoading(null);
  };

  const genLLM = async () => {
    setLoading("llm"); setSuggestions([]);
    try {
      const res = await fetch("/api/llm-password", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ style: llmStyle, theme: theme || undefined, count: 3 }),
      });
      const data = await res.json();
      if (data.error === "MODEL_LOADING") onToast("AI model loading, retry in 20s", "warn");
      else if (data.passwords?.length) setSuggestions(data.passwords);
      else onToast(data.error ?? "Generation failed", "warn");
    } catch { onToast("AI service unavailable", "warn"); }
    setLoading(null);
  };

  return (
    <div>
      <div className="sec-label">Password Generation</div>
      <div className="gen-mode-row">
        <button className={`mode-btn ${mode === "crypto" ? "active" : ""}`} onClick={() => setMode("crypto")}>
          <I.Dice />Cryptographic
        </button>
        <button className={`mode-btn ${mode === "llm" ? "active" : ""}`} onClick={() => setMode("llm")}>
          <I.Brain />AI Creative
        </button>
      </div>

      {mode === "crypto" && (
        <>
          <div className="chips">
            {(["symbols","numbers","uppercase"] as const).map(k => (
              <button key={k} className={`chip ${opts[k] ? "on" : ""}`} onClick={() => toggleOpt(k)}>{k}</button>
            ))}
            {[16,20,24,32].map(l => (
              <button key={l} className={`chip ${opts.length === l ? "on" : ""}`}
                onClick={() => setOpts(o => ({...o,length:l}))}>{l} chars</button>
            ))}
          </div>
          <div className="pw-row">
            <div className="field">
              <div className="field-label">Password</div>
              <input className="inp" type="text" placeholder="Enter or generate"
                value={value} onChange={e => onChange(e.target.value)} />
              <StrengthMeter pw={value} />
            </div>
            <div className="gen-btns">
              <button className="gen-btn" onClick={genCrypto} title="crypto.getRandomValues"><I.Shuffle /></button>
              <button className="gen-btn" onClick={genRandom} disabled={loading === "rng"} title="Random.org hardware entropy"><I.Dice /></button>
            </div>
          </div>
          {entropy && <div className="entropy-note">Source: {entropy}</div>}
        </>
      )}

      {mode === "llm" && (
        <div className="llm-panel">
          <div className="llm-styles">
            {(["passphrase","creative","technical","poetic"] as const).map(s => (
              <button key={s} className={`chip ${llmStyle === s ? "on" : ""}`} onClick={() => setLLMStyle(s)}>{s}</button>
            ))}
          </div>
          <div className="field">
            <div className="field-label">Theme (optional)</div>
            <input className="inp" placeholder='e.g. "ocean", "mythology", "space"'
              value={theme} onChange={e => setTheme(e.target.value)} />
          </div>
          <button className="btn btn-outline" onClick={genLLM} disabled={loading === "llm"} style={{marginBottom:8}}>
            <I.Brain />{loading === "llm" ? "Generating..." : "Generate with Mistral 7B"}
          </button>
          {suggestions.length > 0 && (
            <div className="llm-suggestions">
              <div className="field-label" style={{marginBottom:6}}>Select a suggestion:</div>
              {suggestions.map((pw,i) => (
                <div key={i} className={`llm-sugg ${value === pw ? "selected" : ""}`}
                  onClick={() => onChange(pw)}>
                  <span className="llm-pw">{pw}</span>
                  <StrengthMeter pw={pw} />
                </div>
              ))}
            </div>
          )}
          {value && (
            <div className="field" style={{marginTop:6}}>
              <div className="field-label">Selected</div>
              <input className="inp" type="text" value={value} onChange={e => onChange(e.target.value)} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ADD ENTRY FORM
// ─────────────────────────────────────────────────────────────────────────────
interface AddFormProps {
  onSave: (entry: Omit<VaultEntry,"id"|"createdAt"|"updatedAt">) => void;
  onCancel: () => void;
  onToast: (msg: string, type?: "ok"|"warn") => void;
}

function AddForm({ onSave, onCancel, onToast }: AddFormProps) {
  const [form, setForm] = useState({ site:"", username:"", password:"", url:"", notes:"" });
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(f => ({...f, [k]: e.target.value}));

  return (
    <div className="add-form" style={{marginBottom:14}}>
      <div className="sec-label">Service Details</div>
      <div className="form-row">
        <div className="field">
          <div className="field-label">Website / Service</div>
          <input className="inp" placeholder="github.com" value={form.site} onChange={set("site")} />
        </div>
        <div className="field">
          <div className="field-label">URL (optional)</div>
          <input className="inp" placeholder="https://..." value={form.url} onChange={set("url")} />
        </div>
      </div>
      <div className="field">
        <div className="field-label">Username / Email</div>
        <input className="inp" placeholder="you@email.com" value={form.username} onChange={set("username")} />
      </div>

      <GenPanel value={form.password} onChange={v => setForm(f=>({...f,password:v}))} onToast={onToast} />

      <div className="field" style={{marginTop:10}}>
        <div className="field-label">Notes (optional)</div>
        <input className="inp" placeholder="2FA codes, recovery email..." value={form.notes} onChange={set("notes")} />
      </div>

      <div className="form-actions">
        <button className="btn btn-primary" onClick={() => onSave(form)}
          disabled={!form.site || !form.username || !form.password}>
          Save Entry
        </button>
        <button className="btn btn-outline btn-cancel" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// HEALTH SIDEBAR WIDGET
// ─────────────────────────────────────────────────────────────────────────────
interface HealthWidgetProps {
  entries: VaultEntry[];
  onCheckAll: () => void;
}

function HealthWidget({ entries, onCheckAll }: HealthWidgetProps) {
  const total = entries.length;
  const breached = entries.filter(e => e.breached === true).length;
  const safe = entries.filter(e => e.breached === false).length;
  const weak = entries.filter(e => scorePassword(e.password).score <= 2).length;
  const score = total === 0 ? 100 :
    Math.round((entries.filter(e => scorePassword(e.password).score >= 3 && !e.breached).length / total) * 100);

  const scoreColor = score >= 80 ? "var(--jade)" : score >= 50 ? "var(--gold)" : "var(--crimson)";

  return (
    <div className="sidebar-card">
      <div className="score-ring-wrap">
        <svg viewBox="0 0 56 56" width="56" height="56" style={{flexShrink:0}}>
          <circle cx="28" cy="28" r="22" fill="none" stroke="var(--line2)" strokeWidth="4"/>
          <circle cx="28" cy="28" r="22" fill="none"
            stroke={scoreColor} strokeWidth="4"
            strokeDasharray={`${(score/100)*138.2} 138.2`}
            strokeLinecap="round"
            transform="rotate(-90 28 28)"
            style={{transition:"stroke-dasharray .8s ease"}}
          />
          <text x="28" y="32" textAnchor="middle" fill="var(--text)"
            style={{fontFamily:"var(--mono)",fontSize:"13px",fontWeight:500}}>
            {score}
          </text>
        </svg>
        <div>
          <div className="score-ring-label">Security Score</div>
          <div className="score-ring-sub">{total} credential{total !== 1 ? "s" : ""}</div>
        </div>
      </div>

      <div className="health-mini">
        {[
          [breached, "var(--crimson)", "Breached", total],
          [safe, "var(--jade)", "Verified safe", total],
          [weak, "var(--gold)", "Weak passwords", total],
        ].map(([val, color, label, tot]) => (
          <div key={String(label)}>
            <div className="hm-row">
              <span className="hm-label">{label}</span>
              <span className="hm-val" style={{color:String(color)}}>{val}</span>
            </div>
            <div className="hm-bar">
              <div className="hm-bar-fill" style={{
                width: Number(tot) > 0 ? `${(Number(val)/Number(tot))*100}%` : "0%",
                background: String(color),
              }}/>
            </div>
          </div>
        ))}
      </div>

      <div className="divider"/>

      <button className="btn btn-outline" style={{marginTop:0,fontSize:11,padding:"9px 12px"}}
        onClick={onCheckAll} disabled={total === 0}>
        <I.Shield />HIBP Breach Check
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY LIST
// ─────────────────────────────────────────────────────────────────────────────
interface EntryListProps {
  entries: VaultEntry[];
  onCopy: (text: string, label: string) => void;
  onDelete: (id: string) => void;
  onCheckBreach: (entry: VaultEntry) => void;
  checking: Record<string,boolean>;
}

function EntryList({ entries, onCopy, onDelete, onCheckBreach, checking }: EntryListProps) {
  const [visible, setVisible] = useState<Record<string,boolean>>({});
  const toggle = (id: string) => setVisible(v => ({...v,[id]:!v[id]}));

  if (entries.length === 0) return (
    <div className="empty">
      <div className="empty-icon"><I.Vault /></div>
      <div className="empty-title">No entries found</div>
      <div className="empty-sub">Add your first credential above</div>
    </div>
  );

  return (
    <div className="entries">
      {entries.map(entry => (
        <div key={entry.id} className={`entry-card ${entry.breached ? "breached" : ""}`}>
          <div className="entry-avatar">{entry.site.replace(/^https?:\/\//,"").charAt(0)}</div>
          <div className="entry-info">
            <div className="entry-site">
              {entry.site}
              {entry.breached && <span className="badge badge-danger">Breached</span>}
              {entry.breached === false && <span className="badge badge-safe">Verified</span>}
            </div>
            <div className="entry-user">{entry.username}</div>
            {visible[entry.id] && <div className="entry-pw">{entry.password}</div>}
          </div>
          <div className="entry-actions">
            <button className="icon-btn" title="Copy password" onClick={() => onCopy(entry.password,"Password")}><I.Copy /></button>
            <button className="icon-btn" title="Copy username" onClick={() => onCopy(entry.username,"Username")}>
              <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" strokeWidth="1.5">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
              </svg>
            </button>
            <button className={`icon-btn ${visible[entry.id] ? "active" : ""}`} onClick={() => toggle(entry.id)}>
              {visible[entry.id] ? <I.EyeOff /> : <I.Eye />}
            </button>
            <button className="icon-btn" disabled={checking[entry.id]}
              style={{opacity:checking[entry.id]?0.3:1}} onClick={() => onCheckBreach(entry)}>
              <I.Shield />
            </button>
            <button className="icon-btn danger" onClick={() => onDelete(entry.id)}><I.Trash /></button>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// VAULT SCREEN
// ─────────────────────────────────────────────────────────────────────────────
function VaultScreen({ session, onLogout }: { session: SessionState; onLogout: () => void }) {
  const [vault, setVault] = useState(session.vault);
  const [saving, setSaving] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [search, setSearch] = useState("");
  const [checking, setChecking] = useState<Record<string,boolean>>({});
  const [toast, setToast] = useState<{msg:string;type:"default"|"ok"|"warn"}|null>(null);

  const showToast = (msg: string, type: "default"|"ok"|"warn" = "default") => {
    setToast({msg,type});
    setTimeout(() => setToast(null), 2800);
  };

  const persist = useCallback(async (updated: VaultData) => {
    setSaving(true);
    try {
      const { encryptedVault, vaultIV } = await encryptVault(updated, session.privateKeyB64);
      await api.saveVault(encryptedVault, vaultIV);
      setVault(updated);
    } catch { showToast("Failed to save vault","warn"); }
    setSaving(false);
  }, [session.privateKeyB64]);

  const copy = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    showToast(`${label} copied`, "ok");
  };

  const handleSave = async (form: Omit<VaultEntry,"id"|"createdAt"|"updatedAt">) => {
    const entry: VaultEntry = { id: crypto.randomUUID(), ...form, createdAt: Date.now(), updatedAt: Date.now() };
    await persist({ ...vault, entries: [...vault.entries, entry] });
    setShowAdd(false);
    showToast("Entry saved","ok");
  };

  const handleDelete = async (id: string) => {
    await persist({ ...vault, entries: vault.entries.filter(e => e.id !== id) });
    showToast("Entry deleted");
  };

  const checkBreach = async (entry: VaultEntry) => {
    setChecking(c => ({...c,[entry.id]:true}));
    try {
      const count = await api.checkBreached(entry.password);
      const updated = vault.entries.map(e => e.id === entry.id ? {...e, breached: count > 0} : e);
      await persist({...vault, entries: updated});
      if (count > 0) showToast(`Found in ${count.toLocaleString()} breaches — update immediately`,"warn");
      else showToast("Password not found in known breaches","ok");
    } catch { showToast("Breach check unavailable","warn"); }
    setChecking(c => ({...c,[entry.id]:false}));
  };

  const checkAllBreaches = async () => {
    showToast("Checking all via HIBP k-Anonymity...");
    for (const entry of vault.entries) {
      await checkBreach(entry);
      await new Promise(r => setTimeout(r, 400));
    }
    showToast("Breach check complete","ok");
  };

  const filtered = vault.entries.filter(e =>
    !search ||
    e.site.toLowerCase().includes(search.toLowerCase()) ||
    e.username.toLowerCase().includes(search.toLowerCase())
  );

  const breachedCount = vault.entries.filter(e => e.breached).length;

  return (
    <div className="screen screen-full">
      {/* TOP BAR */}
      <div className="vault-topbar">
        <Wordmark compact />
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div className="status-pill">
            <div className="status-dot"/>
            {saving ? "Encrypting" : "Vault Secure"}
          </div>
          <button className="lock-btn" onClick={onLogout}><I.Lock />Lock Vault</button>
        </div>
      </div>

      {/* BREACH ALERT */}
      {breachedCount > 0 && (
        <div className="alert alert-warn" style={{marginBottom:14}}>
          <I.Alert />
          {breachedCount} password{breachedCount > 1 ? "s" : ""} found in known data breaches. Update them immediately.
        </div>
      )}

      {/* 2-COL BODY */}
      <div className="vault-body">

        {/* LEFT SIDEBAR */}
        <div className="sidebar">
          <HealthWidget entries={vault.entries} onCheckAll={checkAllBreaches} />

          <div className="sidebar-card">
            <div className="nav-label">Security Standards</div>
            {["ECDSA P-256 Auth","AES-256-GCM Vault","HIBP k-Anonymity","HKDF Key Derivation"].map(l => (
              <div key={l} className="sec-item" style={{marginBottom:7}}>
                <I.Shield />{l}
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT MAIN */}
        <div className="main-panel">
          <div className="card">
            <div className="toolbar">
              <div className="toolbar-left">
                <div className="panel-title">Credentials</div>
                <div className="panel-meta">{vault.entries.length} entries · Zero-knowledge encrypted</div>
              </div>
              <div className="toolbar-right">
                <div className="search-wrap">
                  <I.Search />
                  <input className="search-inp" placeholder="Search..." value={search}
                    onChange={e => setSearch(e.target.value)} />
                </div>
                <button className="add-btn" onClick={() => setShowAdd(s => !s)}>
                  {showAdd ? <><I.X />Cancel</> : <><I.Plus />Add Entry</>}
                </button>
              </div>
            </div>

            {showAdd && (
              <AddForm
                onSave={handleSave}
                onCancel={() => setShowAdd(false)}
                onToast={showToast}
              />
            )}

            <EntryList
              entries={filtered}
              onCopy={copy}
              onDelete={handleDelete}
              onCheckBreach={checkBreach}
              checking={checking}
            />
          </div>
        </div>
      </div>

      {toast && <Toast msg={toast.msg} type={toast.type} />}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// LANDING
// ─────────────────────────────────────────────────────────────────────────────
function LandingScreen({ onCreate, onLogin }: { onCreate: ()=>void; onLogin: ()=>void }) {
  const supported = isFileSystemAccessSupported();
  return (
    <div className="screen">
      <Wordmark />
      <div className="card">
        <div className="eyebrow">Secure Credential Storage</div>
        <div className="h1">Your key.<br />Your vault.</div>
        <div className="body">
          Authentication via cryptographic key pair stored on your USB device.
          No master password. No shared secrets. The private key never leaves your hardware.
        </div>
        {!supported && (
          <div className="alert alert-warn"><I.Alert />File System Access API requires Chrome or Edge 86+.</div>
        )}
        <div className="sec-bar">
          {["ECDSA P-256","AES-256-GCM","Zero-Knowledge","HIBP k-Anon"].map(l => (
            <div key={l} className="sec-item"><I.Shield />{l}</div>
          ))}
        </div>
        <div className="btn-row">
          <button className="btn btn-primary" onClick={onCreate} disabled={!supported}><I.Plus />New Vault</button>
          <button className="btn btn-outline" onClick={onLogin} disabled={!supported} style={{marginTop:0}}>
            <I.Unlock />Unlock Vault
          </button>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// CREATE
// ─────────────────────────────────────────────────────────────────────────────
function CreateScreen({ onBack, onComplete }: { onBack: ()=>void; onComplete: (s: SessionState)=>void }) {
  const [step, setStep] = useState(0);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [seed, setSeed] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [copied, setCopied] = useState(false);
  const sessionRef = useRef<SessionState|null>(null);

  const handleSetup = async () => {
    setError(""); setStep(1);
    try {
      setStatus("Generating ECDSA P-256 key pair");
      const { publicKeyB64, privateKeyB64, publicKeyHash } = await generateKeyPair();
      setStatus("Deriving AES-256 vault key via HKDF");
      const vault = emptyVault();
      const { encryptedVault, vaultIV } = await encryptVault(vault, privateKeyB64);
      setStatus("Writing private key to USB");
      const keyFile: KeyFile = { privateKeyB64, publicKeyB64, publicKeyHash, createdAt: Date.now(), version: 1 };
      await setupUSBKey(keyFile);
      setStatus("Registering with server");
      await api.register({ publicKey: publicKeyB64, publicKeyHash, encryptedVault, vaultIV });
      setSeed(generateSeedPhrase());
      sessionRef.current = { privateKeyB64, publicKeyB64, publicKeyHash, vault };
      setStep(2);
    } catch (err: any) {
      setError(err.message ?? "Setup failed.");
      setStep(0);
    }
  };

  const copySeed = async () => {
    await navigator.clipboard.writeText(seed);
    setCopied(true); setTimeout(() => setCopied(false), 3000);
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
            <div key={i} className={`step-bar ${i < step ? "done" : i === Math.min(step,2) ? "active" : ""}`}/>
          ))}
        </div>
        {error && <div className="alert alert-warn"><I.Alert />{error}</div>}

        {step === 0 && <>
          <div className="eyebrow">Step 1 of 3</div>
          <div className="h1">Initialize USB key</div>
          <div className="body">
            Select your USB directory. A key file (<code style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--gold)"}}>housekeyvault.hkv</code>) will be written to it. Your private key never leaves this device.
          </div>
          <div className="usb-zone" onClick={handleSetup}>
            <div className="usb-visual"><I.USB /></div>
            <div className="usb-label">Select USB directory</div>
            <div className="usb-hint">Browser will prompt for folder access</div>
          </div>
          <button className="btn btn-ghost" onClick={onBack}>Back</button>
        </>}

        {step === 1 && <>
          <div className="eyebrow">Initializing</div>
          <div className="h1">Setting up vault</div>
          <div className="body" style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--text3)"}}>{status}...</div>
          <div className="usb-zone active">
            <div className="usb-visual"><I.USB /></div>
            <div className="usb-label">Writing to device</div>
            <div className="usb-hint">Do not remove USB</div>
          </div>
        </>}

        {step === 2 && <>
          <div className="eyebrow">Step 2 of 3</div>
          <div className="h1">Recovery phrase</div>
          <div className="body">Store this phrase offline. It is the only way to recover your vault if the USB is lost.</div>
          <div className="alert alert-warn"><I.Alert />This phrase will not be shown again.</div>
          <div className="seed-box">
            <div className="seed-hdr">
              <div className="seed-label">12-Word Recovery Phrase</div>
              <button className={`seed-copy ${copied ? "copied" : ""}`} onClick={copySeed}>
                {copied ? <I.Check /> : <I.Copy />}{copied ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="seed-grid">
              {seed.split(" ").map((w,i) => (
                <div key={i} className="seed-word">
                  <span className="seed-idx">{String(i+1).padStart(2,"0")}</span>
                  <span className="seed-val">{w}</span>
                </div>
              ))}
            </div>
          </div>
          <label style={{display:"flex",gap:10,alignItems:"flex-start",fontSize:12,color:"var(--text2)",marginBottom:18,cursor:"pointer",lineHeight:1.6}}>
            <input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)}
              style={{accentColor:"var(--gold)",marginTop:2,flexShrink:0}}/>
            I have stored the recovery phrase in a safe location.
          </label>
          <button className="btn btn-primary" onClick={handleFinish} disabled={!confirmed}>Enter Vault</button>
        </>}

        {step === 3 && <div className="alert alert-ok"><I.OkCircle />Vault initialized. Loading...</div>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────────────────────────────────────
function LoginScreen({ onBack, onSuccess, onParanoia }: {
  onBack: ()=>void; onSuccess: (s: SessionState)=>void; onParanoia: (r: number)=>void;
}) {
  const [status, setStatus] = useState<"idle"|"loading"|"error">("idle");
  const [message, setMessage] = useState("");

  const handleLogin = async () => {
    setStatus("loading"); setMessage("Select USB directory...");
    try {
      const keyFile = await loadUSBKey();
      setMessage("Requesting challenge");
      const { nonce } = await api.getChallenge(keyFile.publicKeyHash);
      setMessage("Signing with private key");
      const signature = await signChallenge(keyFile.privateKeyB64, nonce);
      setMessage("Verifying");
      const result = await api.verify({ publicKey: keyFile.publicKeyB64, publicKeyHash: keyFile.publicKeyHash, signature, nonce });
      if (result.error === "LOCKED") { onParanoia(result.remaining ?? 300); return; }
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
        <div className="eyebrow">Authentication</div>
        <div className="h1">Insert key to unlock</div>
        <div className="body">
          Select the directory with your <code style={{fontFamily:"var(--mono)",fontSize:11,color:"var(--gold)"}}>housekeyvault.hkv</code> file. Uses ECDSA P-256 challenge-response.
        </div>
        {status === "error" && <div className="alert alert-warn"><I.Alert />{message}</div>}
        <div className={`usb-zone ${status === "loading" ? "active" : ""}`}
          onClick={status !== "loading" ? handleLogin : undefined}>
          <div className="usb-visual">{status === "loading" ? <I.Lock /> : <I.Key />}</div>
          <div className="usb-label">{status === "loading" ? message : "Click to authenticate"}</div>
          <div className="usb-hint">{status === "idle" ? "ECDSA P-256 challenge-response" : ""}</div>
        </div>
        <button className="btn btn-ghost" onClick={onBack}>Back</button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// PARANOIA
// ─────────────────────────────────────────────────────────────────────────────
function ParanoiaScreen({ remaining, onRetry }: { remaining: number; onRetry: ()=>void }) {
  const [count, setCount] = useState(remaining);
  const { useEffect } = require("react");
  useEffect(() => {
    if (count <= 0) return;
    const t = setInterval(() => setCount(c => c-1), 1000);
    return () => clearInterval(t);
  }, []);
  const mm = String(Math.floor(count/60)).padStart(2,"0");
  const ss = String(count%60).padStart(2,"0");
  return (
    <div className="screen">
      <Wordmark />
      <div className="card" style={{background:"rgba(12,6,6,0.9)",borderColor:"rgba(192,57,43,0.2)",textAlign:"center"}}>
        <div className="p-icon"><I.Lock /></div>
        <div className="p-title">Access Suspended</div>
        <div className="p-sub">Multiple failed authentication attempts detected. Access temporarily suspended.</div>
        <div className="countdown">{mm}:{ss}</div>
        <div className="countdown-label">Time remaining</div>
        {count <= 0 && <button className="btn btn-outline" onClick={onRetry} style={{marginTop:24}}>Retry Authentication</button>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ROOT
// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  const [screen, setScreen] = useState<Screen>("landing");
  const [session, setSession] = useState<SessionState|null>(null);
  const [paranoia, setParanoia] = useState(0);

  const handleLogout = async () => {
    await api.logout().catch(()=>{});
    setSession(null); setScreen("landing");
  };

  return (
    <>
      <style>{CSS}</style>
      <div className={`app ${screen === "paranoia" ? "paranoia-bg" : ""}`}>
        {screen === "landing" && <LandingScreen onCreate={() => setScreen("create")} onLogin={() => setScreen("login")} />}
        {screen === "create" && <CreateScreen onBack={() => setScreen("landing")} onComplete={s => { setSession(s); setScreen("vault"); }} />}
        {screen === "login" && <LoginScreen onBack={() => setScreen("landing")}
          onSuccess={s => { setSession(s); setScreen("vault"); }}
          onParanoia={r => { setParanoia(r); setScreen("paranoia"); }} />}
        {screen === "vault" && session && <VaultScreen session={session} onLogout={handleLogout} />}
        {screen === "paranoia" && <ParanoiaScreen remaining={paranoia} onRetry={() => setScreen("login")} />}
      </div>
    </>
  );
}