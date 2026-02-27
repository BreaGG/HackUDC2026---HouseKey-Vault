import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const prefix = req.nextUrl.searchParams.get("prefix");
  if (!prefix || prefix.length !== 5) return NextResponse.json({ error: "Invalid" }, { status: 400 });

  try {
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: {
        "User-Agent": "HouseKeyVault/1.0",
        ...(process.env.HIBP_API_KEY ? { "hibp-api-key": process.env.HIBP_API_KEY } : {}),
      },
    });
    const text = await res.text();
    return new NextResponse(text, { headers: { "Content-Type": "text/plain", "Cache-Control": "public, max-age=3600" } });
  } catch {
    return NextResponse.json({ error: "HIBP unavailable" }, { status: 503 });
  }
}