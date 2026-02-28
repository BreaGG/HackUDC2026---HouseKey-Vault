// lib/share-crypto.ts
// Client-side ECDH share creation.
// Creates a one-time shareable link where the AES key lives ONLY in the URL fragment.

import { bufToB64 } from "@/lib/crypto-client";

export interface SharePayload {
  site:        string;
  username:    string;
  password:    string;
  url?:        string;
  notes?:      string;
  totpSecret?: string;
}

/**
 * Generates an encrypted share and returns:
 *  - the data to POST to /api/share  (ciphertext, iv, senderPubKey)
 *  - the URL fragment (#key=...) to append to the share link
 *
 * Protocol:
 *  1. Generate ephemeral ECDH key pair (sender)
 *  2. Generate ephemeral ECDH key pair (recipient) — private key goes in the URL fragment
 *  3. Derive shared secret via ECDH between sender-private × recipient-public
 *  4. HKDF(shared-secret) → AES-256-GCM key
 *  5. Encrypt payload
 *  6. Server stores: ciphertext + iv + sender-public-key
 *  7. URL fragment contains: recipient-private-key
 *
 * The server never sees the recipient private key (fragments aren't sent in HTTP requests).
 * The server never sees the AES key (derived client-side from the ECDH exchange).
 */
export async function createShare(payload: SharePayload): Promise<{
  apiPayload: { ciphertext: string; iv: string; senderPubKey: string };
  fragment:   string; // e.g. "key=base64..."
}> {
  // 1 & 2 — Generate two ephemeral ECDH key pairs
  const [senderPair, recipientPair] = await Promise.all([
    crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]),
    crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]),
  ]);

  // 3 — ECDH: sender-private × recipient-public → shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: recipientPair.publicKey },
    senderPair.privateKey,
    256
  );

  // 4 — HKDF → AES-256-GCM key
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, { name: "HKDF" }, false, ["deriveKey"]);
  const aesKey  = await crypto.subtle.deriveKey(
    {
      name: "HKDF", hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode("housekeyvault-share-v1"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  // 5 — Encrypt
  const ivBytes   = crypto.getRandomValues(new Uint8Array(12));
  const iv        = ivBytes.buffer.slice(0, 12) as ArrayBuffer;
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);

  // 6 — Export keys for transport
  const [senderPubRaw, recipientPrivRaw] = await Promise.all([
    crypto.subtle.exportKey("spki",  senderPair.publicKey),
    crypto.subtle.exportKey("pkcs8", recipientPair.privateKey),
  ]);

  return {
    apiPayload: {
      ciphertext:   bufToB64(cipherBuf),
      iv:           bufToB64(iv),
      senderPubKey: bufToB64(senderPubRaw),
    },
    fragment: `key=${encodeURIComponent(bufToB64(recipientPrivRaw))}`,
  };
}