import type {
  Confidence,
  DisplayScanReport,
  EvidenceItem,
  Finding,
  FindingDisplayGroup,
  ReportState,
  RunbookCode,
  ScanReport,
  ScanStatus
} from "@/lib/types";
import { normalizeFindingForDisplay } from "@/lib/report/findingModel";
import { severityRank } from "@/lib/report/scoring";

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
        "A privileged secret or critical public exposure was found. Treat this as an incident and lock down affected access.",
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

const confidenceRank: Record<Confidence, number> = {
  confirmed: 4,
  likely: 3,
  informational: 2,
  not_applicable: 1
};

function bundleTitle(finding: Finding, count: number) {
  const suffix = count > 1 ? ` (${count} items)` : "";
  if (finding.type === "security_header") return `Browser security headers${suffix}`;
  if (finding.type === "source_map") return `Public source maps exposed${suffix}`;
  if (finding.type === "cors" || finding.type === "public_api") return `API endpoint exposure${suffix}`;
  if (finding.type === "client_secret") return `Credential exposure incident${suffix}`;
  if (finding.runbookCode === "RLS_LOCKDOWN_INCIDENT") return `Supabase anonymous-read incident${suffix}`;
  if (finding.type === "supabase_rls") return `Supabase access-control review${suffix}`;
  if (finding.type === "exposed_infrastructure") return `Public infrastructure exposure${suffix}`;
  return `${finding.title}${suffix}`;
}

function evidenceKey(item: EvidenceItem) {
  return `${item.label}|${item.value}|${item.fingerprint ?? ""}`;
}

function maxSeverity(findings: Finding[]) {
  return findings.reduce(
    (max, finding) => (severityRank[finding.severity] > severityRank[max] ? finding.severity : max),
    findings[0].severity
  );
}

function maxConfidence(findings: Finding[]) {
  return findings.reduce(
    (max, finding) => (confidenceRank[finding.confidence] > confidenceRank[max] ? finding.confidence : max),
    findings[0].confidence
  );
}

function representativeFinding(findings: Finding[]) {
  return [...findings].sort((a, b) => {
    const severityDelta = severityRank[b.severity] - severityRank[a.severity];
    if (severityDelta) return severityDelta;
    return confidenceRank[b.confidence] - confidenceRank[a.confidence];
  })[0];
}

export function bundleFindingsForDisplay(findings: Finding[]): FindingDisplayGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const bundleKey = `${finding.runbookCode}|${finding.type}|${finding.location}`;
    groups.set(bundleKey, [...(groups.get(bundleKey) ?? []), finding]);
  }

  return [...groups.entries()].map(([bundleKey, members]) => {
    const representative = representativeFinding(members);
    const evidence = new Map<string, EvidenceItem>();
    for (const member of members) {
      for (const item of member.evidence) evidence.set(evidenceKey(item), item);
    }

    return {
      bundleKey,
      title: bundleTitle(representative, members.length),
      severity: maxSeverity(members),
      confidence: maxConfidence(members),
      representative,
      members,
      evidence: [...evidence.values()],
      remediations: representative.remediations
    };
  });
}

export function normalizeReportForDisplay(report: ScanReport): DisplayScanReport {
  const findings = report.findings.map(normalizeFindingForDisplay);
  const classification = classifyReport({
    status: report.status ?? "complete",
    findings,
    incompleteReason: report.stateReason
  });

  const displayGroups = bundleFindingsForDisplay(findings);

  return {
    ...report,
    ...classification,
    findings,
    displayGroups,
    displayGroupCount: displayGroups.length
  };
}
