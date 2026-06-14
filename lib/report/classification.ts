import type { Finding, ReportState, RunbookCode, ScanReport, ScanStatus } from "@/lib/types";
import { normalizeFindingForDisplay } from "@/lib/report/findingModel";

const publicSurfaceLocations = new Set([
  "client_bundle",
  "public_web_path",
  "referenced_api",
  "response_header",
  "supabase_rest",
  "supabase_storage",
  "public_repo_head",
  "public_repo_history"
]);

export interface ReportClassification {
  status: ScanStatus;
  state: ReportState;
  stateReason: string;
  stateSummary: string;
  primaryRunbookCode?: RunbookCode;
}

export function classifyReport(input: {
  status: ScanStatus;
  findings: Finding[];
  incompleteReason?: string;
}): ReportClassification {
  const findings = input.findings.map(normalizeFindingForDisplay);

  if (input.status === "incomplete") {
    return {
      status: "incomplete",
      state: "incomplete",
      stateReason: input.incompleteReason ?? "The scan did not finish.",
      stateSummary:
        "VibeCheck could not finish the public-surface scan, so this report does not make a safety claim."
    };
  }

  const critical = findings.find((finding) => finding.tier === "critical");
  if (critical) {
    return {
      status: "complete",
      state: "incident",
      stateReason: `Critical finding: ${critical.title}`,
      stateSummary:
        "A privileged secret or critical public exposure was found. Treat this as an incident and rotate affected keys.",
      primaryRunbookCode: critical.runbookCode
    };
  }

  const publicByDesign = findings.find(
    (finding) =>
      finding.tier === "public_by_design" && publicSurfaceLocations.has(finding.location)
  );
  if (publicByDesign) {
    return {
      status: "complete",
      state: "fixable",
      stateReason: `Needs a self-check: ${publicByDesign.title}`,
      stateSummary:
        "VibeCheck found a public-by-design surface that needs a permission self-check before you trust it.",
      primaryRunbookCode: publicByDesign.runbookCode
    };
  }

  const unknown = findings.find((finding) => finding.tier === "unknown");
  if (unknown) {
    return {
      status: "complete",
      state: "fixable",
      stateReason: `Review item: ${unknown.title}`,
      stateSummary:
        "VibeCheck found a public surface worth tightening. The fix is usually configuration or access-control cleanup.",
      primaryRunbookCode: unknown.runbookCode
    };
  }

  return {
    status: "complete",
    state: "clean",
    stateReason: "no_findings",
    stateSummary:
      "No issues were found on the enabled public-surface checks. This is not a full penetration test."
  };
}

export function normalizeReportForDisplay(report: ScanReport): ScanReport {
  const findings = report.findings.map(normalizeFindingForDisplay);
  const classification = classifyReport({
    status: report.status ?? "complete",
    findings,
    incompleteReason: report.stateReason
  });

  return {
    ...report,
    ...classification,
    findings
  };
}
