import { NextResponse } from "next/server";
import { hashEmail } from "@/lib/scanner/redaction";
import { recordEvent, saveWaitlistEntry } from "@/lib/store/reportStore";

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

  return NextResponse.json({ ok: true });
}
