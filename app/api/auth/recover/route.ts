// app/api/auth/recover/route.ts
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase-server";

export async function POST(req: NextRequest) {
  try {
    const supabaseAdmin = getSupabaseAdmin();

    const { seedPhrase } = z.object({
      seedPhrase: z.string().min(10),
    }).parse(await req.json());

    const seedHash = await hashSeed(seedPhrase.trim().toLowerCase());

    const { data: user, error } = await supabaseAdmin
      .from("users")
      .select("id, seed_encrypted_vault, seed_vault_iv")
      .eq("seed_hash", seedHash)
      .single();

    if (error || !user) {
      // Generic — don't reveal whether the seed exists
      return NextResponse.json(
        { success: false, error: "Recovery phrase not found." },
        { status: 404 }
      );
    }

    // Return the seed-encrypted copy of the vault.
    // Client will: decryptVaultWithSeed(encryptedVault, vaultIV, seedPhrase)
    // then generate a new key pair, re-encrypt, and call /api/vault/save.
    return NextResponse.json({
      success: true,
      encryptedVault: user.seed_encrypted_vault,
      vaultIV: user.seed_vault_iv,
      recoveryKey: seedPhrase.trim(), // client uses this as the seed arg to decryptVaultWithSeed
    });

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