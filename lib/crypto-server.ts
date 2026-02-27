import { createHash, randomBytes } from "crypto";

export function generateNonce(): string {
  return randomBytes(32).toString("hex");
}

export async function verifyECDSASignature(
  publicKeyB64: string,
  challenge: string,
  signatureB64: string
): Promise<boolean> {
  try {
    const publicKeyBytes = Buffer.from(publicKeyB64, "base64");
    const signatureBytes = Buffer.from(signatureB64, "base64");
    const challengeBytes = Buffer.from(challenge, "utf-8");

    const publicKey = await crypto.subtle.importKey(
      "spki",
      publicKeyBytes,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );

    return await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      publicKey,
      signatureBytes,
      challengeBytes
    );
  } catch {
    return false;
  }
}

export function hashPublicKey(publicKeyB64: string): string {
  return createHash("sha256").update(publicKeyB64).digest("hex");
}

export function generateSessionToken(): string {
  return randomBytes(48).toString("hex");
}