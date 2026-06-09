import { NextResponse } from "next/server";
import type { EventName } from "@/lib/types";
import { recordEvent } from "@/lib/store/reportStore";

export const runtime = "nodejs";

const allowedEvents: EventName[] = [
  "scan_started",
  "scan_completed",
  "report_viewed",
  "share_clicked",
  "waitlist_submitted",
  "stripe_clicked"
];

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as { name?: EventName; reportId?: string };
  if (!body.name || !allowedEvents.includes(body.name)) {
    return NextResponse.json({ error: "Unsupported event." }, { status: 400 });
  }
  await recordEvent(body.name, body.reportId);
  return NextResponse.json({ ok: true });
}
