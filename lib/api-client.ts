// lib/api-client.ts

async function apiPost<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(data.error ?? "Request failed"), { status: res.status, data });
  return data as T;
}

export const api = {
  register: (payload: {
    publicKey: string;
    publicKeyHash: string;
    encryptedVault: string;
    vaultIV: string;
    seedHash: string;
    seedEncryptedVault: string;
    seedVaultIV: string;
  }) => apiPost<{ userId: string }>("/api/auth/register", payload),

  getChallenge: (publicKeyHash: string) =>
    apiPost<{ nonce: string }>("/api/auth/challenge", { publicKeyHash }),

  verify: (payload: {
    publicKey: string;
    publicKeyHash: string;
    signature: string;
    nonce: string;
  }) => apiPost<{
    success: boolean;
    encryptedVault?: string;
    vaultIV?: string;
    error?: string;
    remaining?: number;
    failsLeft?: number;
  }>("/api/auth/verify", payload),

  saveVault: (encryptedVault: string, vaultIV: string) =>
    apiPost<{ success: boolean }>("/api/vault/save", { encryptedVault, vaultIV }),

  logout: () => apiPost<{ success: boolean }>("/api/auth/logout", {}),

  recover: (payload: {
    seedPhrase: string;
    newPublicKey?: string;
    newPublicKeyHash?: string;
    newEncryptedVault?: string;
    newVaultIV?: string;
  }) =>
    apiPost<{
      success: boolean;
      encryptedVault?: string;
      vaultIV?: string;
      recoveryKey?: string;
      error?: string;
    }>("/api/auth/recover", payload),

  async checkBreached(password: string): Promise<number> {
    const hashBuf = await crypto.subtle.digest(
      "SHA-1",
      new TextEncoder().encode(password)
    );
    const hash = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await fetch(`/api/hibp?prefix=${prefix}`);
    if (!res.ok) return 0;
    const text = await res.text();
    const match = text.split("\n").find(l => l.startsWith(suffix));
    return match ? parseInt(match.split(":")[1], 10) : 0;
  },
};