import { NextResponse } from "next/server";
import { hashEmail } from "@/lib/scanner/redaction";
import {
  deleteWaitlistEntry,
  getReport,
  recordEvent,
  saveWaitlistEntry
} from "@/lib/store/reportStore";
import { pendoTrack } from "@/lib/pendo";
import { normalizeEmail, normalizeOptionalReportId } from "@/lib/validation";
import { requesterFingerprint } from "@/lib/scanner/runScan";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as { email?: string; reportId?: string };
  const email = normalizeEmail(body.email);
  if (!email) {
    return NextResponse.json({ error: "A valid email is required." }, { status: 400 });
  }
  const reportId = normalizeOptionalReportId(body.reportId);
  if (!reportId.ok) {
    return NextResponse.json({ error: reportId.error }, { status: 400 });
  }

  await saveWaitlistEntry({
    email,
    emailHash: hashEmail(email),
    reportId: reportId.reportId,
    createdAt: new Date().toISOString()
  });
  await recordEvent("waitlist_submitted", reportId.reportId);

  const requester = {
    ip: request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null,
    userAgent: request.headers.get("user-agent")
  };
  const fingerprint = requesterFingerprint(requester);

  const referringReport = reportId.reportId ? await getReport(reportId.reportId) : null;
  await pendoTrack(
    "waitlist_submitted",
    {
      ...(reportId.reportId ? { reportId: reportId.reportId } : {}),
      ...(referringReport ? { referringState: referringReport.state } : {}),
      ...(referringReport ? { referringGrade: referringReport.grade } : {}),
      ...(referringReport ? { referringScore: referringReport.score } : {})
    },
    { ip: requester.ip, userAgent: requester.userAgent, visitorId: fingerprint }
  );

  return NextResponse.json({ ok: true });
}

export async function DELETE(request: Request) {
  const body = (await request.json().catch(() => ({}))) as { email?: string };
  const email = normalizeEmail(body.email);
  if (!email) {
    return NextResponse.json({ error: "A valid email is required." }, { status: 400 });
  }

  await deleteWaitlistEntry(hashEmail(email));
  return NextResponse.json({ ok: true });
}
