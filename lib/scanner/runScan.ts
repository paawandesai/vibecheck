import crypto from "node:crypto";
import type { AuthorizationArtifact, Finding, ScanReport, Severity } from "@/lib/types";
import { scanConfig } from "@/lib/env";
import { collectPublicAssets } from "@/lib/scanner/assets";
import { analyzeSecrets } from "@/lib/scanner/secrets";
import { checkSourceMaps } from "@/lib/scanner/sourceMaps";
import { checkSupabaseExposure } from "@/lib/scanner/supabase";
import { checkInfrastructure } from "@/lib/scanner/infra";
import { normalizeScannerUrl, ScanBudget } from "@/lib/scanner/safeFetch";
import { safeUrlForStorage } from "@/lib/scanner/redaction";

export const AUTH_CHECKBOX_TEXT_VERSION = "supabase-ownership-v1";

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

function highestSeverity(findings: Finding[]) {
  return findings.reduce<Severity | "none">((highest, finding) => {
    if (highest === "none") return finding.severity;
    return severityRank[finding.severity] > severityRank[highest] ? finding.severity : highest;
  }, "none");
}

function scoreReport(findings: Finding[]) {
  const highest = highestSeverity(findings);
  if (highest === "critical") return { grade: "F" as const, score: 35 };
  if (highest === "high") return { grade: "D" as const, score: 55 };
  if (highest === "medium") return { grade: "C" as const, score: 72 };
  if (highest === "low") return { grade: "B" as const, score: 86 };
  return { grade: "A" as const, score: 96 };
}

export function requesterFingerprint(input: { ip?: string | null; userAgent?: string | null }) {
  return crypto
    .createHash("sha256")
    .update(`${scanConfig.authFingerprintSalt}:${input.ip ?? "unknown"}:${input.userAgent ?? "unknown"}`)
    .digest("hex");
}

export async function runScan(input: {
  targetUrl: string;
  authorizedSupabaseProbe: boolean;
  requester?: { ip?: string | null; userAgent?: string | null };
}) {
  if (scanConfig.scanningDisabled) {
    throw new Error("Scanning is temporarily disabled");
  }

  const scanId = crypto.randomUUID();
  const target = normalizeScannerUrl(input.targetUrl);
  const targetOrigin = target.origin;
  const checksRun = ["client_bundle_secrets", "exposed_source_maps", "exposed_infrastructure"];
  const checksSkipped: string[] = [];
  const budget = new ScanBudget(24);

  const assets = await collectPublicAssets(target.toString(), budget);
  const { findings: secretFindings, supabaseContext } = analyzeSecrets(assets);
  const sourceMapFindings = await checkSourceMaps(assets, budget);
  const infraFindings = await checkInfrastructure(targetOrigin, budget);

  let authorization: AuthorizationArtifact | undefined;
  let supabaseFindings: Finding[] = [];
  if (input.authorizedSupabaseProbe && !scanConfig.supabaseProbeDisabled) {
    checksRun.push("supabase_rls_authorized_probe");
    authorization = {
      scanId,
      targetOrigin,
      timestamp: new Date().toISOString(),
      checkboxTextVersion: AUTH_CHECKBOX_TEXT_VERSION,
      requesterFingerprint: requesterFingerprint(input.requester ?? {})
    };
    supabaseFindings = await checkSupabaseExposure(supabaseContext, budget);
  } else {
    checksSkipped.push(
      input.authorizedSupabaseProbe ? "supabase_probe_disabled_by_operator" : "supabase_probe_requires_authorization"
    );
  }

  const findings = [...secretFindings, ...sourceMapFindings, ...supabaseFindings, ...infraFindings].sort(
    (a, b) => severityRank[b.severity] - severityRank[a.severity]
  );
  const score = scoreReport(findings);
  const highest = highestSeverity(findings);

  const report: ScanReport = {
    id: scanId,
    targetOrigin,
    targetUrlRedacted: safeUrlForStorage(target),
    createdAt: new Date().toISOString(),
    grade: score.grade,
    score: score.score,
    scanner: {
      version: "0.1.0",
      mode: "read_only",
      requestCount: budget.count(),
      checksRun,
      checksSkipped
    },
    findings,
    authorization,
    aggregate: {
      hasClientSecretFinding: findings.some((finding) => finding.type === "client_secret"),
      hasSourceMapFinding: findings.some((finding) => finding.type === "source_map"),
      hasSupabaseRiskFinding: findings.some((finding) => finding.type === "supabase_rls"),
      findingCount: findings.length,
      highestSeverity: highest
    }
  };

  return report;
}
