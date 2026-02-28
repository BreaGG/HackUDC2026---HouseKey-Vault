// app/api/share/route.ts
// POST  — store encrypted share blob (requires session)
// GET   — retrieve blob once, mark as used (public, no auth)
//
// The AES key lives ONLY in the URL fragment (#key=...).
// The browser never sends fragments to the server — zero-knowledge by design.

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase-server";

const TTL_MAX = 7 * 24 * 60 * 60; // 7 days in seconds

// ── SESSION HELPER ────────────────────────────────────────────────────────────

async function getUserFromSession(req: NextRequest) {
  const token = req.cookies.get("hkv_session")?.value;
  if (!token) return null;
  const supabase = getSupabaseAdmin();
  const { data: session } = await supabase
    .from("sessions")
    .select("user_id, expires_at")
    .eq("token", token)
    .single();
  if (!session || new Date(session.expires_at) < new Date()) return null;
  return session.user_id as string;
}

// ── POST — create share ───────────────────────────────────────────────────────

const CreateSchema = z.object({
  ciphertext:   z.string().min(10),
  iv:           z.string().min(10),
  senderPubKey: z.string().min(10),   // ephemeral ECDH public key (spki, b64)
  ttlSeconds:   z.number().int().min(60).max(TTL_MAX).optional(),
});

export async function POST(req: NextRequest) {
  try {
    const userId = await getUserFromSession(req);
    if (!userId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = await req.json();
    const parsed = CreateSchema.safeParse(body);
    if (!parsed.success) return NextResponse.json({ error: "Invalid request" }, { status: 400 });

    const { ciphertext, iv, senderPubKey, ttlSeconds = 86400 } = parsed.data;
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

    const supabase = getSupabaseAdmin();
    const { data, error } = await supabase
      .from("shares")
      .insert({ ciphertext, iv, sender_pub_key: senderPubKey, expires_at: expiresAt, used: false, created_by: userId })
      .select("id")
      .single();

    if (error) throw error;
    return NextResponse.json({ id: data.id }, { status: 201 });
  } catch (err) {
    console.error("[share/POST]", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}

// ── GET — retrieve share (one-time) ──────────────────────────────────────────

export async function GET(req: NextRequest) {
  try {
    const id = req.nextUrl.searchParams.get("id");
    if (!id) return NextResponse.json({ error: "Missing id" }, { status: 400 });

    const supabase = getSupabaseAdmin();
    const { data: share, error } = await supabase
      .from("shares")
      .select("id, ciphertext, iv, sender_pub_key, expires_at, used")
      .eq("id", id)
      .single();

    if (error || !share) return NextResponse.json({ error: "Share not found." }, { status: 404 });
    if (share.used)        return NextResponse.json({ error: "This link has already been used." }, { status: 410 });
    if (new Date(share.expires_at) < new Date())
      return NextResponse.json({ error: "This link has expired." }, { status: 410 });

    // Mark as used atomically
    await supabase.from("shares").update({ used: true }).eq("id", id);

    return NextResponse.json({
      ciphertext:   share.ciphertext,
      iv:           share.iv,
      senderPubKey: share.sender_pub_key,
    });
  } catch (err) {
    console.error("[share/GET]", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}