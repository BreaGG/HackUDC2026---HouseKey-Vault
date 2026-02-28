// app/api/hibp/route.ts
// k-Anonymity proxy for Have I Been Pwned.
// Only the first 5 hex chars of the SHA-1 hash ever leave the client —
// the full hash is computed in the browser and never sent here.
//
// Rate limiting: sliding window, in-process Map.
//   • 30 requests / 60 seconds per IP
//   • Global cap: 200 requests / 60 seconds (protects HIBP quota)
//   • Entries auto-expire — no memory leak.
//
// In production replace the in-process Map with Redis / Upstash if you
// need multi-instance deployments. The interface is identical.

import { NextRequest, NextResponse } from "next/server";

// ── Rate limit store ──────────────────────────────────────────────────────────

interface Window {
  timestamps: number[]; // epoch-ms of each request in the current window
}

const PER_IP_LIMIT   = 30;   // max requests per IP per window
const GLOBAL_LIMIT   = 200;  // max requests across all IPs per window
const WINDOW_MS      = 60_000; // 60 seconds

const ipWindows  = new Map<string, Window>();
const globalWin: Window = { timestamps: [] };

/** Prune timestamps older than WINDOW_MS and return current count. */
function prune(win: Window): number {
  const cutoff = Date.now() - WINDOW_MS;
  win.timestamps = win.timestamps.filter(t => t > cutoff);
  return win.timestamps.length;
}

/** Returns true if the request is allowed, false if rate-limited. */
function checkLimit(ip: string): { allowed: boolean; retryAfter: number } {
  // Global check
  const globalCount = prune(globalWin);
  if (globalCount >= GLOBAL_LIMIT) {
    const oldest = globalWin.timestamps[0];
    return { allowed: false, retryAfter: Math.ceil((oldest + WINDOW_MS - Date.now()) / 1000) };
  }

  // Per-IP check
  if (!ipWindows.has(ip)) ipWindows.set(ip, { timestamps: [] });
  const win = ipWindows.get(ip)!;
  const count = prune(win);

  if (count >= PER_IP_LIMIT) {
    const oldest = win.timestamps[0];
    return { allowed: false, retryAfter: Math.ceil((oldest + WINDOW_MS - Date.now()) / 1000) };
  }

  // Allow — record the request
  const now = Date.now();
  win.timestamps.push(now);
  globalWin.timestamps.push(now);

  // Evict IPs with empty windows to prevent unbounded Map growth
  if (ipWindows.size > 10_000) {
    for (const [key, w] of ipWindows) {
      if (prune(w) === 0) ipWindows.delete(key);
    }
  }

  return { allowed: true, retryAfter: 0 };
}

// ── Handler ───────────────────────────────────────────────────────────────────

export async function GET(req: NextRequest) {
  // Extract prefix from query param
  const prefix = req.nextUrl.searchParams.get("prefix");

  if (!prefix || !/^[0-9A-Fa-f]{5}$/.test(prefix)) {
    return NextResponse.json({ error: "Invalid prefix" }, { status: 400 });
  }

  // Determine client IP (works on Vercel and most reverse-proxies)
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    req.headers.get("x-real-ip") ??
    "unknown";

  const { allowed, retryAfter } = checkLimit(ip);

  if (!allowed) {
    return NextResponse.json(
      { error: "Too many breach checks. Please slow down." },
      {
        status: 429,
        headers: {
          "Retry-After": String(retryAfter),
          "X-RateLimit-Limit": String(PER_IP_LIMIT),
          "X-RateLimit-Window": "60",
        },
      }
    );
  }

  // Forward to HIBP — server → HIBP so the user's IP never touches HIBP directly
  try {
    const hibpRes = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix.toUpperCase()}`,
      {
        headers: {
          // HIBP requires a user-agent; identify as your app
          "User-Agent": "HouseKeyVault/1.0 (hackudc-2026)",
          // Add-Padding prevents traffic analysis of result size
          "Add-Padding": "true",
        },
        // Abort if HIBP is slow — don't block the user
        signal: AbortSignal.timeout(5_000),
      }
    );

    if (!hibpRes.ok) {
      return NextResponse.json(
        { error: "HIBP upstream error" },
        { status: 502 }
      );
    }

    const body = await hibpRes.text();

    return new NextResponse(body, {
      status: 200,
      headers: {
        "Content-Type": "text/plain",
        // Cache for 1 hour — prefix results are stable within the hour
        // and this avoids hammering HIBP for repeated checks of the same passwords
        "Cache-Control": "private, max-age=3600",
        "X-RateLimit-Limit":     String(PER_IP_LIMIT),
        "X-RateLimit-Remaining": String(PER_IP_LIMIT - (ipWindows.get(ip)?.timestamps.length ?? 1)),
        "X-RateLimit-Window":    "60",
      },
    });
  } catch (err: any) {
    if (err.name === "TimeoutError" || err.name === "AbortError") {
      return NextResponse.json({ error: "HIBP request timed out" }, { status: 504 });
    }
    return NextResponse.json({ error: "Failed to reach HIBP" }, { status: 502 });
  }
}