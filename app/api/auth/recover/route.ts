// app/api/auth/recover/route.ts
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase-server";
import { generateSessionToken } from "@/lib/crypto-server";

export async function POST(req: NextRequest) {
  try {
    const supabaseAdmin = getSupabaseAdmin();

    const { seedPhrase, newPublicKey, newPublicKeyHash, newEncryptedVault, newVaultIV } = z.object({
      seedPhrase:        z.string().min(10),
      // After the client decrypts + re-encrypts with new key it sends these
      // so we can update the user record and open a session in one round-trip
      newPublicKey:          z.string().optional(),
      newPublicKeyHash:      z.string().length(64).optional(),
      newEncryptedVault:     z.string().optional(),
      newVaultIV:            z.string().optional(),
    }).parse(await req.json());

    const seedHash = await hashSeed(seedPhrase.trim().toLowerCase());

    const { data: user, error } = await supabaseAdmin
      .from("users")
      .select("id, seed_encrypted_vault, seed_vault_iv")
      .eq("seed_hash", seedHash)
      .single();

    if (error || !user) {
      return NextResponse.json(
        { success: false, error: "Recovery phrase not found." },
        { status: 404 }
      );
    }

    // PHASE 1 — client just sent the seed, return the encrypted vault
    if (!newPublicKey || !newPublicKeyHash || !newEncryptedVault || !newVaultIV) {
      return NextResponse.json({
        success: true,
        encryptedVault: user.seed_encrypted_vault,
        vaultIV: user.seed_vault_iv,
        recoveryKey: seedPhrase.trim(),
      });
    }

    // PHASE 2 — client decrypted, generated new key pair, re-encrypted
    // Update the user record with the new key and vault
    const { error: updateError } = await supabaseAdmin
      .from("users")
      .update({
        public_key:      newPublicKey,
        public_key_hash: newPublicKeyHash,
        encrypted_vault: newEncryptedVault,
        vault_iv:        newVaultIV,
      })
      .eq("id", user.id);

    if (updateError) throw updateError;

    // Also clear lockout if any
    await supabaseAdmin
      .from("lockouts")
      .upsert({ user_id: user.id, fail_count: 0, locked_until: null });

    // Create a session so the client is immediately authenticated
    const token = generateSessionToken();
    await supabaseAdmin.from("sessions").insert({
      user_id:    user.id,
      token,
      expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    });

    const res = NextResponse.json({ success: true });
    res.cookies.set("hkv_session", token, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge:   900,
      path:     "/",
    });
    return res;

  } catch (err) {
    console.error("[recover]", err);
    return NextResponse.json({ success: false, error: "Server error." }, { status: 500 });
  }
}

async function hashSeed(seed: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(seed)
  );
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}