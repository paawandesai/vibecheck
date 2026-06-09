import { NextResponse } from "next/server";
import { hashEmail } from "@/lib/scanner/redaction";
import { getReport, recordEvent, saveWaitlistEntry } from "@/lib/store/reportStore";
import { pendoTrack } from "@/lib/pendo";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as { email?: string; reportId?: string };
  if (!body.email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email)) {
    return NextResponse.json({ error: "A valid email is required." }, { status: 400 });
  }

  await saveWaitlistEntry({
    emailHash: hashEmail(body.email),
    reportId: body.reportId,
    createdAt: new Date().toISOString()
  });
  await recordEvent("waitlist_submitted", body.reportId);

  const referringReport = body.reportId ? await getReport(body.reportId) : null;
  await pendoTrack("waitlist_submitted", {
    ...(body.reportId ? { reportId: body.reportId } : {}),
    ...(referringReport ? { referringGrade: referringReport.grade } : {}),
    ...(referringReport ? { referringScore: referringReport.score } : {}),
  });

  return NextResponse.json({ ok: true });
}
