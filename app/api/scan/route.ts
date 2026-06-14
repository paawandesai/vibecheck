import { NextResponse } from "next/server";
import { recordEvent, saveReport } from "@/lib/store/reportStore";
import { runScan } from "@/lib/scanner/runScan";
import { scanConfig } from "@/lib/env";
import { normalizeScannerUrl } from "@/lib/scanner/safeFetch";
import { requesterFingerprint } from "@/lib/scanner/runScan";
import { consumeScanRateLimit } from "@/lib/store/rateLimitStore";

export const runtime = "nodejs";
export const maxDuration = 60;

function requesterFrom(request: Request) {
  return {
    ip: request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null,
    userAgent: request.headers.get("user-agent")
  };
}

export async function POST(request: Request) {
  if (scanConfig.scanningDisabled) {
    return NextResponse.json({ error: "Scanning is temporarily disabled." }, { status: 503 });
  }

  let body: { url?: string; authorizedSupabaseProbe?: boolean };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  if (!body.url || typeof body.url !== "string") {
    return NextResponse.json({ error: "A deployed app URL is required." }, { status: 400 });
  }

  try {
    const target = normalizeScannerUrl(body.url);
    const requester = requesterFrom(request);
    const fingerprint = requesterFingerprint(requester);
    let rateLimit;
    try {
      rateLimit = await consumeScanRateLimit({
        requesterFingerprint: fingerprint,
        targetOrigin: target.origin
      });
    } catch {
      return NextResponse.json(
        { error: "Rate limiting is not configured correctly." },
        { status: 503 }
      );
    }

    if (!rateLimit.allowed) {
      const response = NextResponse.json(
        { error: rateLimit.reason ?? "Rate limit exceeded." },
        { status: rateLimit.reason?.includes("requires Supabase") ? 503 : 429 }
      );
      if (rateLimit.retryAfterSeconds) {
        response.headers.set("Retry-After", String(rateLimit.retryAfterSeconds));
      }
      return response;
    }

    await recordEvent("scan_started");

    const report = await runScan({
      targetUrl: target.toString(),
      authorizedSupabaseProbe: body.authorizedSupabaseProbe === true,
      requester
    });
    await saveReport(report);
    await recordEvent("scan_completed", report.id);

    return NextResponse.json({
      reportId: report.id,
      reportUrl: `/r/${report.id}`,
      report
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
