import { NextResponse } from "next/server";
import { recordEvent, saveReport } from "@/lib/store/reportStore";
import { runScan } from "@/lib/scanner/runScan";
import { scanConfig } from "@/lib/env";

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

  try {
    const report = await runScan({
      targetUrl: body.url,
      authorizedSupabaseProbe: body.authorizedSupabaseProbe === true,
      requester: requesterFrom(request)
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
