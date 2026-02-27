import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase-server";

const CHARSET = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  symbols: "!@#$%^&*-_+=?",
};

export async function POST(req: NextRequest) {
  const token = req.cookies.get("hkv_session")?.value;
  if (!token) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  try {
    const supabaseAdmin = getSupabaseAdmin();
    const { data: session } = await supabaseAdmin
      .from("sessions").select("*").eq("token", token).single();
    if (!session || new Date(session.expires_at) < new Date())
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const { length = 20, symbols = true, numbers = true, uppercase = true } =
      await req.json().catch(() => ({}));

    let chars = CHARSET.lower;
    if (uppercase) chars += CHARSET.upper;
    if (numbers)   chars += CHARSET.numbers;
    if (symbols)   chars += CHARSET.symbols;

    const randomOrgKey = process.env.RANDOM_ORG_API_KEY;

    let randomBytes: number[];

    if (randomOrgKey) {
      // Use Random.org true hardware randomness
      const response = await fetch("https://api.random.org/json-rpc/4/invoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "generateIntegers",
          params: {
            apiKey: randomOrgKey,
            n: length * 2, // extra to handle rejection sampling
            min: 0,
            max: 255,
            replacement: true,
          },
          id: 1,
        }),
      });

      const data = await response.json();
      if (data.error) throw new Error(data.error.message);
      randomBytes = data.result.random.data;
    } else {
      // Fallback: crypto.getRandomValues on server
      const buf = new Uint8Array(length * 2);
      crypto.getRandomValues(buf);
      randomBytes = Array.from(buf);
    }

    // Rejection sampling — no modulo bias
    let result = "";
    const maxValid = Math.floor(256 / chars.length) * chars.length;
    for (let i = 0; i < randomBytes.length && result.length < length; i++) {
      if (randomBytes[i] < maxValid) result += chars[randomBytes[i] % chars.length];
    }

    if (result.length < length) {
      // pad if needed (rare)
      result = result.padEnd(length, chars[0]);
    }

    return NextResponse.json({
      password: result,
      source: randomOrgKey ? "random.org" : "crypto",
    });
  } catch (err: any) {
    console.error("[random-password]", err);
    return NextResponse.json({ error: "Generation failed" }, { status: 500 });
  }
}