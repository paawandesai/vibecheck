import { NextResponse } from "next/server";
import { getReport } from "@/lib/store/reportStore";
import { isUuid } from "@/lib/validation";

export const runtime = "nodejs";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!isUuid(id)) {
    return NextResponse.json({ error: "Report ID must be a valid UUID." }, { status: 400 });
  }
  const report = await getReport(id);
  if (!report) {
    return NextResponse.json({ error: "Report not found." }, { status: 404 });
  }
  return NextResponse.json({ report });
}
