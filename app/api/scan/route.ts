import { NextResponse } from "next/server";
import { recordEvent, saveReport } from "@/lib/store/reportStore";
import { runScan, requesterFingerprint } from "@/lib/scanner/runScan";
import { scanConfig } from "@/lib/env";
import { normalizeScannerUrl } from "@/lib/scanner/safeFetch";
import { consumeScanRateLimit } from "@/lib/store/rateLimitStore";
import { pendoTrack } from "@/lib/pendo";

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

  const requester = requesterFrom(request);
  const authorizedSupabaseProbe = body.authorizedSupabaseProbe === true;
  let target: URL;

  try {
    target = normalizeScannerUrl(body.url);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid URL provided.";
    await pendoTrack(
      "scan_failed",
      {
        targetOrigin: "invalid",
        errorMessage: message.substring(0, 200),
        authorizedSupabaseProbe
      },
      { ip: requester.ip, userAgent: requester.userAgent }
    );
    return NextResponse.json({ error: message }, { status: 400 });
  }

  try {
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
      await pendoTrack(
        "scan_rate_limited",
        {
          targetOrigin: target.origin,
          reason: rateLimit.reason ?? "Rate limit exceeded.",
          authorizedSupabaseProbe
        },
        { ip: requester.ip, userAgent: requester.userAgent }
      );

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
    await pendoTrack(
      "scan_started",
      {
        targetOrigin: target.origin,
        authorizedSupabaseProbe
      },
      { ip: requester.ip, userAgent: requester.userAgent }
    );

    const report = await runScan({
      targetUrl: target.toString(),
      authorizedSupabaseProbe,
      requester
    });
    await saveReport(report);
    await recordEvent("scan_completed", report.id);

    await pendoTrack(
      "scan_completed",
      {
        reportId: report.id,
        targetOrigin: report.targetOrigin,
        state: report.state,
        grade: report.grade,
        score: report.score,
        findingCount: report.aggregate.findingCount,
        highestSeverity: report.aggregate.highestSeverity,
        hasClientSecretFinding: report.aggregate.hasClientSecretFinding,
        hasSourceMapFinding: report.aggregate.hasSourceMapFinding,
        hasSupabaseRiskFinding: report.aggregate.hasSupabaseRiskFinding,
        hasInfrastructureFinding: report.aggregate.hasInfrastructureFinding,
        hasCorsFinding: report.aggregate.hasCorsFinding,
        hasSecurityHeaderFinding: report.aggregate.hasSecurityHeaderFinding,
        hasPublicApiFinding: report.aggregate.hasPublicApiFinding,
        hasClientDataExposureFinding: report.aggregate.hasClientDataExposureFinding,
        hasDebugSchemaFinding: report.aggregate.hasDebugSchemaFinding,
        hasFirebaseConfigFinding: report.aggregate.hasFirebaseConfigFinding,
        requestCount: report.scanner.requestCount,
        checksRun: report.scanner.checksRun.join(","),
        authorizedSupabaseProbe
      },
      { ip: requester.ip, userAgent: requester.userAgent }
    );

    return NextResponse.json({
      reportId: report.id,
      reportUrl: `/r/${report.id}`,
      absoluteReportUrl: new URL(`/r/${report.id}`, scanConfig.appUrl).toString(),
      report
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed.";

    await pendoTrack(
      "scan_failed",
      {
        targetOrigin: target.origin,
        errorMessage: message.substring(0, 200),
        authorizedSupabaseProbe
      },
      { ip: requester.ip, userAgent: requester.userAgent }
    );

    return NextResponse.json({ error: message }, { status: 400 });
  }
}
