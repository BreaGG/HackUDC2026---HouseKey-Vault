import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase-server";

export async function POST(req: NextRequest) {
  try {
    const supabaseAdmin = getSupabaseAdmin();
    const token = req.cookies.get("hkv_session")?.value;
    if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: session } = await supabaseAdmin
      .from("sessions").select("*").eq("token", token).single();
    if (!session || new Date(session.expires_at) < new Date())
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { encryptedVault, vaultIV } = z.object({
      encryptedVault: z.string(), vaultIV: z.string()
    }).parse(await req.json());

    await supabaseAdmin.from("users")
      .update({ encrypted_vault: encryptedVault, vault_iv: vaultIV, updated_at: new Date().toISOString() })
      .eq("id", session.user_id);

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("[vault/save]", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}