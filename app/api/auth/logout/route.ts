import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase-server";

export async function POST(req: NextRequest) {
  try {
    const supabaseAdmin = getSupabaseAdmin();
    const token = req.cookies.get("hkv_session")?.value;
    if (token) await supabaseAdmin.from("sessions").delete().eq("token", token);
    const res = NextResponse.json({ success: true });
    res.cookies.set("hkv_session", "", { maxAge: 0, path: "/" });
    return res;
  } catch (err) {
    console.error("[logout]", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}