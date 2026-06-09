import { NextResponse } from "next/server";
import { recordEvent, saveReport } from "@/lib/store/reportStore";
import { runScan } from "@/lib/scanner/runScan";
import { scanConfig } from "@/lib/env";
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

  await recordEvent("scan_started");

  let targetOrigin: string;
  try {
    targetOrigin = new URL(body.url).origin;
  } catch {
    return NextResponse.json({ error: "Invalid URL provided." }, { status: 400 });
  }
  const authorizedSupabaseProbe = body.authorizedSupabaseProbe === true;
  const requester = requesterFrom(request);

  await pendoTrack(
    "scan_started",
    {
      targetOrigin,
      authorizedSupabaseProbe,
    },
    { ip: requester.ip, userAgent: requester.userAgent }
  );

  try {
    const report = await runScan({
      targetUrl: body.url,
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
        grade: report.grade,
        score: report.score,
        findingCount: report.aggregate.findingCount,
        highestSeverity: report.aggregate.highestSeverity,
        hasClientSecretFinding: report.aggregate.hasClientSecretFinding,
        hasSourceMapFinding: report.aggregate.hasSourceMapFinding,
        hasSupabaseRiskFinding: report.aggregate.hasSupabaseRiskFinding,
        requestCount: report.scanner.requestCount,
        checksRun: report.scanner.checksRun.join(","),
        authorizedSupabaseProbe,
      },
      { ip: requester.ip, userAgent: requester.userAgent }
    );

    return NextResponse.json({
      reportId: report.id,
      reportUrl: `/r/${report.id}`,
      report
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed.";

    await pendoTrack(
      "scan_failed",
      {
        targetOrigin,
        errorMessage: message.substring(0, 200),
        authorizedSupabaseProbe,
      },
      { ip: requester.ip, userAgent: requester.userAgent }
    );

    return NextResponse.json({ error: message }, { status: 400 });
  }
}
