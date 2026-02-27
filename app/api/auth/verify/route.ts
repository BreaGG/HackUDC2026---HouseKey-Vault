import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase-server";
import { verifyECDSASignature, generateSessionToken } from "@/lib/crypto-server";

const LOCKOUT_THRESHOLD = 3;
const LOCKOUT_MS = 5 * 60 * 1000;

export async function POST(req: NextRequest) {
  try {
    const supabaseAdmin = getSupabaseAdmin();
    const { publicKey, publicKeyHash, signature, nonce } = z.object({
      publicKey: z.string(), publicKeyHash: z.string().length(64),
      signature: z.string(), nonce: z.string().length(64),
    }).parse(await req.json());

    const { data: user } = await supabaseAdmin
      .from("users").select("*").eq("public_key_hash", publicKeyHash).single();
    if (!user) return NextResponse.json({ error: "Authentication failed." }, { status: 401 });

    const { data: lockout } = await supabaseAdmin
      .from("lockouts").select("*").eq("user_id", user.id).single();
    if (lockout?.locked_until && new Date(lockout.locked_until) > new Date()) {
      const remaining = Math.ceil((new Date(lockout.locked_until).getTime() - Date.now()) / 1000);
      return NextResponse.json({ error: "LOCKED", remaining }, { status: 429 });
    }

    const { data: challenge } = await supabaseAdmin
      .from("challenges").select("*").eq("nonce", nonce).single();
    if (!challenge || challenge.used || challenge.pub_key_hash !== publicKeyHash || new Date(challenge.expires_at) < new Date()) {
      await recordFail(supabaseAdmin, user.id, lockout);
      return NextResponse.json({ error: "Invalid or expired challenge." }, { status: 401 });
    }

    await supabaseAdmin.from("challenges").update({ used: true }).eq("nonce", nonce);

    if (user.public_key !== publicKey) {
      await recordFail(supabaseAdmin, user.id, lockout);
      return NextResponse.json({ error: "Authentication failed." }, { status: 401 });
    }

    const valid = await verifyECDSASignature(publicKey, nonce, signature);
    if (!valid) {
      const updated = await recordFail(supabaseAdmin, user.id, lockout);
      if (updated?.locked_until) return NextResponse.json({ error: "LOCKED", remaining: LOCKOUT_MS / 1000 }, { status: 429 });
      const failsLeft = LOCKOUT_THRESHOLD - (updated?.fail_count ?? 0);
      return NextResponse.json({ error: "Authentication failed.", failsLeft }, { status: 401 });
    }

    await supabaseAdmin.from("lockouts").upsert({ user_id: user.id, fail_count: 0, locked_until: null });

    const token = generateSessionToken();
    await supabaseAdmin.from("sessions").insert({
      user_id: user.id, token,
      expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    });

    const res = NextResponse.json({ success: true, encryptedVault: user.encrypted_vault, vaultIV: user.vault_iv });
    res.cookies.set("hkv_session", token, {
      httpOnly: true, secure: process.env.NODE_ENV === "production",
      sameSite: "strict", maxAge: 900, path: "/",
    });
    return res;
  } catch (err) {
    console.error("[verify]", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}

async function recordFail(supabaseAdmin: any, userId: string, existing: any) {
  const newCount = (existing?.fail_count ?? 0) + 1;
  const lock = newCount >= LOCKOUT_THRESHOLD;
  const { data } = await supabaseAdmin.from("lockouts").upsert({
    user_id: userId,
    fail_count: newCount,
    locked_until: lock ? new Date(Date.now() + LOCKOUT_MS).toISOString() : null,
    last_attempt: new Date().toISOString(),
  }).select().single();
  return data;
}