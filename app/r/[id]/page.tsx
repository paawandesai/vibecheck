import { notFound } from "next/navigation";
import { ReportView } from "@/components/ReportView";
import { getReport, recordEvent } from "@/lib/store/reportStore";
import { pendoTrack } from "@/lib/pendo";

export const dynamic = "force-dynamic";

export default async function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const report = await getReport(id);
  if (!report) notFound();

  await recordEvent("report_viewed", report.id);

  await pendoTrack("report_viewed", {
    reportId: report.id,
    grade: report.grade,
    score: report.score,
    findingCount: report.aggregate.findingCount,
    targetOrigin: report.targetOrigin,
    highestSeverity: report.aggregate.highestSeverity,
  });

  return (
    <main className="report-band">
      <ReportView report={report} />
    </main>
  );
}
