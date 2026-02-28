"use client";
// app/share/[id]/page.tsx
// Public page — zero auth required.
// The AES key is in the URL fragment (#key=...) — never sent to the server.

import React, { useState, useEffect } from "react";

// ── CRYPTO (inline, no server imports) ───────────────────────────────────────

function b64ToBuf(b64: string): ArrayBuffer {
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i);
  return buf;
}

async function decryptShare(
  ciphertext: string, iv: string, senderPubKeyB64: string, recipientPrivKeyB64: string
): Promise<string> {
  const recipientPrivKey = await crypto.subtle.importKey(
    "pkcs8", b64ToBuf(recipientPrivKeyB64),
    { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]
  );
  const senderPubKey = await crypto.subtle.importKey(
    "spki", b64ToBuf(senderPubKeyB64),
    { name: "ECDH", namedCurve: "P-256" }, false, []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: senderPubKey }, recipientPrivKey, 256
  );
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, { name: "HKDF" }, false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("housekeyvault-share-v1") },
    hkdfKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(iv) }, aesKey, b64ToBuf(ciphertext)
  );
  return new TextDecoder().decode(plain);
}

// ── TOTP live chip ────────────────────────────────────────────────────────────

function TOTPChip({ secret }: { secret: string }) {
  const [code, setCode] = useState("------");
  const [rem, setRem] = useState(1);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    let raf: number;
    const b32 = (s: string) => {
      const C = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      const cl = s.toUpperCase().replace(/[= ]/g, "");
      let bits = 0, val = 0; const out: number[] = [];
      for (const c of cl) { const i = C.indexOf(c); if (i < 0) continue; val = (val << 5) | i; bits += 5; if (bits >= 8) { bits -= 8; out.push((val >> bits) & 0xff); } }
      return new Uint8Array(out);
    };
    const tick = async () => {
      const P = 30, now = Date.now() / 1000;
      setRem(1 - (now % P) / P);
      const raw = b32(secret);
      const kb = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer;
      const ctr = Math.floor(now / P);
      const buf = new ArrayBuffer(8); new DataView(buf).setUint32(4, ctr, false);
      const k = await crypto.subtle.importKey("raw", kb, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
      const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, buf));
      const off = sig[19] & 0xf;
      const n = ((sig[off] & 0x7f) << 24 | (sig[off+1] & 0xff) << 16 | (sig[off+2] & 0xff) << 8 | (sig[off+3] & 0xff)) % 1_000_000;
      setCode(String(n).padStart(6, "0"));
      raf = requestAnimationFrame(tick);
    };
    tick(); return () => cancelAnimationFrame(raf);
  }, [secret]);
  const CIRCUM = 2 * Math.PI * 5;
  const ringColor = rem < 0.25 ? "#C0392B" : "#27AE8F";
  return (
    <div onClick={async () => { await navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      style={{ display: "inline-flex", alignItems: "center", gap: 6, background: "rgba(255,255,255,.05)", border: `1px solid ${copied ? "rgba(39,174,143,.4)" : "rgba(255,255,255,.1)"}`, borderRadius: 20, padding: "3px 10px 3px 6px", cursor: "pointer", transition: "border-color .2s" }}>
      <svg width="14" height="14" viewBox="0 0 12 12">
        <circle cx="6" cy="6" r="5" fill="none" stroke="rgba(255,255,255,.15)" strokeWidth="1.5" />
        <circle cx="6" cy="6" r="5" fill="none" stroke={ringColor} strokeWidth="1.5"
          strokeDasharray={`${rem * CIRCUM} ${CIRCUM}`} strokeLinecap="round" transform="rotate(-90 6 6)"
          style={{ transition: "stroke-dasharray .5s linear" }} />
      </svg>
      <span style={{ fontFamily: "monospace", fontSize: 14, fontWeight: 500, letterSpacing: "0.12em", color: copied ? "#27AE8F" : "#E2C06A" }}>
        {copied ? "copied" : `${code.slice(0, 3)} ${code.slice(3)}`}
      </span>
    </div>
  );
}

// ── MAIN ──────────────────────────────────────────────────────────────────────

interface Cred { site: string; username: string; password: string; url?: string; notes?: string; totpSecret?: string; }
type State = "loading" | "decrypting" | "ready" | "error";

export default function SharePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = React.use(params);
  const [state, setState] = useState<State>("loading");
  const [cred, setCred] = useState<Cred | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState<string | null>(null);
  const [pwVisible, setPwVisible] = useState(false);

  const copy = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label); setTimeout(() => setCopied(null), 2000);
  };

  useEffect(() => {
    (async () => {
      try {
        const frag = window.location.hash.slice(1);
        const privKeyB64 = new URLSearchParams(frag).get("key");
        if (!privKeyB64) { setError("Invalid link — decryption key missing."); setState("error"); return; }

        setState("loading");
        const res = await fetch(`/api/share?id=${id}`);
        const data = await res.json();
        if (!res.ok) { setError(data.error ?? "Link not found or already used."); setState("error"); return; }

        setState("decrypting");
        const plain = await decryptShare(data.ciphertext, data.iv, data.senderPubKey, privKeyB64);
        setCred(JSON.parse(plain));
        setState("ready");
      } catch (e: any) {
        setError(e.message?.includes("operation-specific") ? "Decryption failed — link may be corrupted." : (e.message ?? "Unknown error."));
        setState("error");
      }
    })();
  }, [id]);

  const CSS = `
    @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;500&family=IBM+Plex+Mono:wght@300;400;500&family=IBM+Plex+Sans:wght@300;400;500&display=swap');
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html,body{background:#0C0C0F;color:#E8E6E0;font-family:'IBM Plex Sans',system-ui,sans-serif;min-height:100vh;-webkit-font-smoothing:antialiased}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;position:relative;overflow:hidden}
    .wrap::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(201,168,76,.04),transparent 60%);pointer-events:none}
    .wrap::after{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(255,255,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.015) 1px,transparent 1px);background-size:48px 48px;pointer-events:none}
    .card{background:#14141A;border:1px solid rgba(255,255,255,.12);border-radius:10px;width:100%;max-width:460px;padding:28px;position:relative;overflow:hidden;z-index:1;box-shadow:0 1px 3px rgba(0,0,0,.4),0 8px 32px rgba(0,0,0,.3)}
    .card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(201,168,76,.25),transparent)}
    .wm{display:flex;align-items:flex-end;gap:10px;margin-bottom:24px}
    .wm-icon{width:28px;height:28px;border:1px solid #C9A84C;display:flex;align-items:center;justify-content:center;flex-shrink:0;position:relative}
    .wm-icon::before{content:'';position:absolute;inset:3px;border:1px solid rgba(201,168,76,.3)}
    .wm-icon svg{width:12px;height:12px;stroke:#C9A84C;fill:none;stroke-width:1.5}
    .wm-name{font-family:'Playfair Display',Georgia,serif;font-size:14px;font-weight:500;line-height:1}
    .wm-tag{font-family:'IBM Plex Mono',monospace;font-size:8px;letter-spacing:.2em;color:#5A5856;text-transform:uppercase;margin-top:3px}
    .eyebrow{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.2em;color:#C9A84C;text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:8px}
    .eyebrow::after{content:'';flex:1;height:1px;background:rgba(255,255,255,.07)}
    .h1{font-family:'Playfair Display',Georgia,serif;font-size:20px;font-weight:400;margin-bottom:18px}
    .one-time-badge{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;background:rgba(192,57,43,.1);border:1px solid rgba(192,57,43,.25);border-radius:3px;font-family:'IBM Plex Mono',monospace;font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:#E07070;margin-bottom:18px}
    .one-time-badge svg{width:10px;height:10px;stroke:currentColor;fill:none;stroke-width:1.5}
    .field{margin-bottom:12px}
    .field-label{font-family:'IBM Plex Mono',monospace;font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:#5A5856;margin-bottom:5px}
    .field-row{background:#1C1C24;border:1px solid rgba(255,255,255,.07);border-radius:6px;padding:9px 12px;display:flex;align-items:center;gap:8px}
    .field-text{font-family:'IBM Plex Mono',monospace;font-size:12px;color:#E8E6E0;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .field-text.pw{color:#E2C06A;letter-spacing:.06em}
    .field-text.blurred{filter:blur(5px);user-select:none;transition:filter .2s}
    .field-text.blurred:hover{filter:blur(0)}
    .icon-btn{width:26px;height:26px;border-radius:4px;border:1px solid rgba(255,255,255,.1);background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;color:#5A5856;flex-shrink:0}
    .icon-btn:hover{border-color:#C9A84C;color:#C9A84C}
    .icon-btn.ok{border-color:#27AE8F;color:#27AE8F}
    .icon-btn svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5}
    .notes-box{background:#1C1C24;border:1px solid rgba(255,255,255,.07);border-radius:6px;padding:9px 12px;font-size:12px;color:#9A9890;line-height:1.6;margin-bottom:12px;white-space:pre-wrap;word-break:break-word}
    .divider{height:1px;background:rgba(255,255,255,.07);margin:16px 0}
    .security-note{font-family:'IBM Plex Mono',monospace;font-size:9px;color:#5A5856;line-height:1.7}
    .state-center{text-align:center;padding:16px 0}
    .spinner-ring{animation:spin 1s linear infinite;stroke:#C9A84C;fill:none;stroke-width:2}
    @keyframes spin{to{transform:rotate(360deg)}}
    .error-icon{width:48px;height:48px;border-radius:50%;border:1px solid rgba(192,57,43,.4);display:flex;align-items:center;justify-content:center;margin:0 auto 16px}
    .error-icon svg{width:20px;height:20px;stroke:#C0392B;fill:none;stroke-width:1.5}
    .error-msg{font-size:13px;color:#E07070;margin-bottom:6px;font-weight:500}
    .error-sub{font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5A5856}
  `;

  const KeySVG = () => <svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M12 15h8M17 15v-2"/></svg>;
  const AlertSVG = () => <svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
  const CopySVG  = () => <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>;
  const CheckSVG = () => <svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>;
  const EyeSVG   = () => <svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>;
  const EyeOffSVG= () => <svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>;

  return (
    <>
      <style>{CSS}</style>
      <div className="wrap">
        <div className="card">
          {/* Wordmark */}
          <div className="wm">
            <div className="wm-icon"><KeySVG /></div>
            <div><div className="wm-name">HouseKey Vault</div><div className="wm-tag">Secure Share</div></div>
          </div>

          {/* Loading */}
          {(state === "loading" || state === "decrypting") && (
            <div className="state-center">
              <svg width="48" height="48" viewBox="0 0 48 48" style={{ display: "block", margin: "0 auto 16px" }}>
                <circle cx="24" cy="24" r="20" fill="none" stroke="rgba(255,255,255,.07)" strokeWidth="3" />
                <circle cx="24" cy="24" r="20" fill="none" strokeWidth="3" strokeDasharray="31 96" strokeLinecap="round" className="spinner-ring" />
              </svg>
              <div style={{ fontFamily: "monospace", fontSize: 11, color: "#5A5856", letterSpacing: ".06em" }}>
                {state === "decrypting" ? "Decrypting client-side…" : "Retrieving encrypted payload…"}
              </div>
            </div>
          )}

          {/* Error */}
          {state === "error" && (
            <div className="state-center">
              <div className="error-icon"><AlertSVG /></div>
              <div className="error-msg">{error}</div>
              <div className="error-sub">This link may have expired or already been opened.</div>
            </div>
          )}

          {/* Ready */}
          {state === "ready" && cred && (<>
            <div className="eyebrow">Shared credential</div>
            {cred.url ? (
              <a
                href={cred.url.startsWith("http") ? cred.url : `https://${cred.url}`}
                target="_blank" rel="noopener noreferrer"
                className="h1"
                style={{ display:"inline-flex", alignItems:"center", gap:8, color:"inherit", textDecoration:"none", borderBottom:"1px solid rgba(201,168,76,.3)", paddingBottom:2, marginBottom:18, transition:"border-color .2s" }}
                onMouseEnter={e=>(e.currentTarget.style.borderColor="rgba(201,168,76,.8)")}
                onMouseLeave={e=>(e.currentTarget.style.borderColor="rgba(201,168,76,.3)")}
              >
                {cred.site}
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#C9A84C" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{flexShrink:0,opacity:.7}}>
                  <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                  <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                </svg>
              </a>
            ) : (
              <div className="h1">{cred.site}</div>
            )}
            <br />
            <div className="one-time-badge">
              <AlertSVG />
              One-time link — already consumed
            </div>

            {/* Username */}
            <div className="field">
              <div className="field-label">Username / Email</div>
              <div className="field-row">
                <span className="field-text">{cred.username}</span>
                <button className={`icon-btn ${copied==="username"?"ok":""}`} onClick={() => copy(cred.username, "username")}>
                  {copied === "username" ? <CheckSVG /> : <CopySVG />}
                </button>
              </div>
            </div>

            {/* Password */}
            <div className="field">
              <div className="field-label">Password</div>
              <div className="field-row">
                <span className={`field-text pw ${!pwVisible ? "blurred" : ""}`}>{cred.password}</span>
                <button className="icon-btn" onClick={() => setPwVisible(v => !v)}>
                  {pwVisible ? <EyeOffSVG /> : <EyeSVG />}
                </button>
                <button className={`icon-btn ${copied==="password"?"ok":""}`} onClick={() => copy(cred.password, "password")}>
                  {copied === "password" ? <CheckSVG /> : <CopySVG />}
                </button>
              </div>
            </div>

            {/* TOTP */}
            {cred.totpSecret && (
              <div className="field">
                <div className="field-label">Two-Factor Code</div>
                <TOTPChip secret={cred.totpSecret} />
              </div>
            )}

            {/* Notes */}
            {cred.notes && (<>
              <div className="field-label" style={{ marginBottom: 5 }}>Notes</div>
              <div className="notes-box">{cred.notes}</div>
            </>)}

            <div className="divider" />
            <div className="security-note">
              This link was single-use and has now been invalidated. The password was decrypted
              entirely in your browser — the HouseKey server never saw it. Save these credentials
              to your own vault if you need them again.
            </div>
          </>)}
        </div>
      </div>
    </>
  );
}