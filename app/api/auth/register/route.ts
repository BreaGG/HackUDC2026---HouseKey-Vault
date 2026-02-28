// app/api/auth/register/route.ts
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase-server";

const Schema = z.object({
  publicKey:          z.string().min(50).max(500),
  publicKeyHash:      z.string().length(64),
  encryptedVault:     z.string().min(10),
  vaultIV:            z.string().min(10),
  // Recovery fields
  seedHash:           z.string().length(64),
  seedEncryptedVault: z.string().min(10),
  seedVaultIV:        z.string().min(10),
  // Duress / decoy vault (optional — user may skip duress setup)
  // The server stores this alongside the real vault but cannot distinguish them.
  duressEncryptedVault: z.string().min(10).optional(),
  duressVaultIV:        z.string().min(10).optional(),
});

export async function POST(req: NextRequest) {
  try {
    const supabaseAdmin = getSupabaseAdmin();
    const parsed = Schema.safeParse(await req.json());
    if (!parsed.success) return NextResponse.json({ error: "Invalid request" }, { status: 400 });

    const {
      publicKey, publicKeyHash,
      encryptedVault, vaultIV,
      seedHash, seedEncryptedVault, seedVaultIV,
      duressEncryptedVault, duressVaultIV,
    } = parsed.data;

    const { data: existing } = await supabaseAdmin
      .from("users")
      .select("id")
      .eq("public_key_hash", publicKeyHash)
      .single();

    if (existing) return NextResponse.json({ error: "Vault already exists." }, { status: 409 });

    const { data, error } = await supabaseAdmin
      .from("users")
      .insert({
        public_key:           publicKey,
        public_key_hash:      publicKeyHash,
        encrypted_vault:      encryptedVault,
        vault_iv:             vaultIV,
        seed_hash:            seedHash,
        seed_encrypted_vault: seedEncryptedVault,
        seed_vault_iv:        seedVaultIV,
        // Duress columns — add to Supabase:
        //   duress_encrypted_vault TEXT
        //   duress_vault_iv        TEXT
        // Both nullable — users who skip duress setup have NULL here.
        // The server never reads these; they are only returned on /api/auth/verify
        // for the client to select which one to decrypt locally.
        duress_encrypted_vault: duressEncryptedVault ?? null,
        duress_vault_iv:        duressVaultIV ?? null,
      })
      .select("id")
      .single();

    if (error) throw error;
    return NextResponse.json({ success: true, userId: data.id }, { status: 201 });
  } catch (err) {
    console.error("[register]", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}