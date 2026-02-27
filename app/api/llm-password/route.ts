// app/api/llm-password/route.ts
// Uses HuggingFace Inference API (free tier compatible)
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

const Schema = z.object({
  theme: z.string().max(100).optional(),
  style: z.enum(["passphrase", "creative", "technical", "poetic"]),
  count: z.number().min(1).max(5).default(3),
});

// Models that work on HF free tier text-generation endpoint
const MODELS = [
  "mistralai/Mixtral-8x7B-Instruct-v0.1",
  "HuggingFaceH4/zephyr-7b-beta",
  "tiiuae/falcon-7b-instruct",
];

function buildPrompt(style: string, theme?: string): string {
  const themeClause = theme ? ` The theme is: "${theme}".` : "";
  const base = `Generate exactly 3 secure passwords.${themeClause}
Rules: 16-32 chars, mix uppercase+lowercase+numbers+symbols, memorable but unpredictable.
Return ONLY a JSON array like: ["Password1!", "Str0ng#Key", "S3cur3@Pass"]
Style: ${style}
JSON array:`;
  return base;
}

async function tryModel(model: string, prompt: string, apiKey: string): Promise<string | null> {
  try {
    const res = await fetch(`https://api-inference.huggingface.co/models/${model}`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        inputs: prompt,
        parameters: {
          max_new_tokens: 150,
          temperature: 0.8,
          return_full_text: false,
          stop: ["\n\n", "```"],
        },
        options: { wait_for_model: true },
      }),
    });

    if (!res.ok) return null;
    const data = await res.json();
    return data[0]?.generated_text ?? null;
  } catch {
    return null;
  }
}

function extractPasswords(text: string): string[] {
  // Try JSON array first
  const jsonMatch = text.match(/\[[\s\S]*?\]/);
  if (jsonMatch) {
    try {
      const parsed = JSON.parse(jsonMatch[0]);
      if (Array.isArray(parsed)) {
        return parsed.filter((p): p is string => typeof p === "string" && p.length >= 12 && p.length <= 64);
      }
    } catch {}
  }

  // Fallback: extract quoted strings
  const quoted = text.match(/"([^"]{12,64})"/g);
  if (quoted?.length) {
    return quoted.map(s => s.replace(/"/g, "")).slice(0, 3);
  }

  // Last resort: lines that look like passwords (12+ chars with mixed content)
  const lines = text.split("\n")
    .map(l => l.trim().replace(/^[\d\.\-\*\s"']+|["'\s]+$/g, ""))
    .filter(l => l.length >= 12 && l.length <= 64 && /[A-Z]/.test(l) && /[0-9!@#$%^&*]/.test(l));

  return lines.slice(0, 3);
}

export async function POST(req: NextRequest) {
  const hfKey = process.env.HUGGINGFACE_API_KEY;
  if (!hfKey) return NextResponse.json({ error: "LLM service not configured" }, { status: 503 });

  try {
    const body = Schema.parse(await req.json());
    const prompt = buildPrompt(body.style, body.theme);

    let generated: string | null = null;
    let usedModel = "";

    for (const model of MODELS) {
      generated = await tryModel(model, prompt, hfKey);
      if (generated) { usedModel = model; break; }
    }

    if (!generated) {
      return NextResponse.json({ error: "All models unavailable, try again in a moment" }, { status: 503 });
    }

    const passwords = extractPasswords(generated);

    if (passwords.length === 0) {
      console.error("[llm-password] Could not extract passwords from:", generated);
      return NextResponse.json({ error: "Could not parse model response" }, { status: 500 });
    }

    return NextResponse.json({ passwords: passwords.slice(0, body.count), model: usedModel });
  } catch (err: any) {
    console.error("[llm-password]", err);
    return NextResponse.json({ error: err.message ?? "Generation failed" }, { status: 500 });
  }
}