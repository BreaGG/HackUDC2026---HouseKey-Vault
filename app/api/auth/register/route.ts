import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase-server";

const Schema = z.object({
  publicKey: z.string().min(50).max(500),
  publicKeyHash: z.string().length(64),
  encryptedVault: z.string().min(10),
  vaultIV: z.string().min(10),
});

export async function POST(req: NextRequest) {
  try {
    const supabaseAdmin = getSupabaseAdmin();
    const parsed = Schema.safeParse(await req.json());
    if (!parsed.success) return NextResponse.json({ error: "Invalid request" }, { status: 400 });

    const { publicKey, publicKeyHash, encryptedVault, vaultIV } = parsed.data;

    const { data: existing } = await supabaseAdmin
      .from("users")
      .select("id")
      .eq("public_key_hash", publicKeyHash)
      .single();

    if (existing) return NextResponse.json({ error: "Vault already exists." }, { status: 409 });

    const { data, error } = await supabaseAdmin
      .from("users")
      .insert({ public_key: publicKey, public_key_hash: publicKeyHash, encrypted_vault: encryptedVault, vault_iv: vaultIV })
      .select("id")
      .single();

    if (error) throw error;
    return NextResponse.json({ success: true, userId: data.id }, { status: 201 });
  } catch (err) {
    console.error("[register]", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}