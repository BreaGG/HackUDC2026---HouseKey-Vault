import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase-server";
import { generateNonce } from "@/lib/crypto-server";

export async function POST(req: NextRequest) {
  try {
    const supabaseAdmin = getSupabaseAdmin();
    const { publicKeyHash } = z.object({ publicKeyHash: z.string().length(64) }).parse(await req.json());

    const { data: user } = await supabaseAdmin
      .from("users").select("id").eq("public_key_hash", publicKeyHash).single();
    if (!user) return NextResponse.json({ error: "Authentication failed." }, { status: 404 });

    const { data: lockout } = await supabaseAdmin
      .from("lockouts").select("*").eq("user_id", user.id).single();
    if (lockout?.locked_until && new Date(lockout.locked_until) > new Date()) {
      const remaining = Math.ceil((new Date(lockout.locked_until).getTime() - Date.now()) / 1000);
      return NextResponse.json({ error: "LOCKED", remaining }, { status: 429 });
    }

    await supabaseAdmin.from("challenges")
      .update({ used: true }).eq("pub_key_hash", publicKeyHash).eq("used", false);

    const nonce = generateNonce();
    await supabaseAdmin.from("challenges").insert({
      nonce,
      pub_key_hash: publicKeyHash,
      expires_at: new Date(Date.now() + 120000).toISOString(),
    });

    return NextResponse.json({ nonce });
  } catch (err) {
    console.error("[challenge]", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}