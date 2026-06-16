import type { Finding, Severity } from "@/lib/types";

export const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const severityWeight: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0
};

export function highestSeverity(findings: Pick<Finding, "severity">[]) {
  return findings.reduce<Severity | "none">((highest, finding) => {
    if (highest === "none") return finding.severity;
    return severityRank[finding.severity] > severityRank[highest] ? finding.severity : highest;
  }, "none");
}

export function gradeFromScore(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

export function scoreReport(findings: Pick<Finding, "severity">[]) {
  const rawScore = findings.reduce((score, finding) => score - severityWeight[finding.severity], 100);
  const clamped = Math.max(0, Math.min(100, rawScore));
  const hasCritical = findings.some((finding) => finding.severity === "critical");
  const score = hasCritical ? Math.min(clamped, 35) : clamped;

  return {
    grade: hasCritical ? ("F" as const) : gradeFromScore(score),
    score
  };
}
