import crypto from "node:crypto";
import type {
  AuthorizationArtifact,
  Finding,
  PublicAsset,
  ScanReport,
  ScanStatus,
  Severity,
  SupabaseContext
} from "@/lib/types";
import { scanConfig } from "@/lib/env";
import { collectPublicAssets } from "@/lib/scanner/assets";
import { CHECK_BUDGETS, type CheckId, isCheckEnabled, parseDisabledChecks } from "@/lib/scanner/checks";
import { checkCorsExposure } from "@/lib/scanner/cors";
import { analyzeSecrets } from "@/lib/scanner/secrets";
import { checkPublicApiSurface } from "@/lib/scanner/publicApi";
import { checkSecurityHeaders } from "@/lib/scanner/securityHeaders";
import { checkSourceMaps } from "@/lib/scanner/sourceMaps";
import { checkSupabaseExposure, supabaseAnonSelfCheckFinding } from "@/lib/scanner/supabase";
import { checkInfrastructure } from "@/lib/scanner/infra";
import { normalizeScannerUrl, safeFetch, ScanBudget } from "@/lib/scanner/safeFetch";
import { safeUrlForStorage } from "@/lib/scanner/redaction";
import { classifyReport } from "@/lib/report/classification";

export const AUTH_CHECKBOX_TEXT_VERSION = "supabase-ownership-v1";
const TOTAL_REQUEST_BUDGET = 35;

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
  const disabled = parseDisabledChecks(scanConfig.disabledChecks);
  const checksRun: string[] = [];
  const checksSkipped: string[] = [];
  const checksDisabled = disabled.disabled;
  const checkerBudgets: Record<string, { max: number; used: number }> = {};
  const budget = new ScanBudget(TOTAL_REQUEST_BUDGET);
  const findings: Finding[] = [];
  let status: ScanStatus = "complete";
  let incompleteReason: string | undefined;
  let assets: PublicAsset[] = [];
  let supabaseContext: SupabaseContext = { serviceRoleKeyFingerprints: [] };
  let authorization: AuthorizationArtifact | undefined;

  async function runWithBudget<T>(checkId: keyof typeof CHECK_BUDGETS, fn: (scoped: ScanBudget) => Promise<T>) {
    const scoped = budget.scope(checkId, CHECK_BUDGETS[checkId]);
    try {
      return await fn(scoped);
    } finally {
      checkerBudgets[checkId] = {
        max: CHECK_BUDGETS[checkId],
        used: scoped.count()
      };
    }
  }

  function enabled(checkId: CheckId) {
    return isCheckEnabled(checksDisabled, checkId);
  }

  try {
    const needsAssets =
      enabled("client_bundle_secrets") ||
      enabled("exposed_source_maps") ||
      enabled("cors") ||
      enabled("public_api_surface") ||
      (input.authorizedSupabaseProbe && enabled("supabase_rls_authorized_probe"));

    assets = needsAssets
      ? await runWithBudget("asset_collection", (scoped) => collectPublicAssets(target.toString(), scoped))
      : [];
    const analysis = analyzeSecrets(assets);
    supabaseContext = analysis.supabaseContext;

    if (enabled("security_headers")) {
      checksRun.push("security_headers");
      const headerAsset = await runWithBudget("security_headers", async (scoped) => {
        const response = await safeFetch(target.toString(), scoped, {
          method: "HEAD",
          maxBytes: 0,
          timeoutMs: 8000
        });
        return {
          url: safeUrlForStorage(response.url),
          type: "html" as const,
          body: "",
          truncated: false,
          status: response.status,
          headers: Object.fromEntries(response.headers.entries())
        };
      });
      findings.push(...checkSecurityHeaders(headerAsset, targetOrigin));
    }

    if (enabled("client_bundle_secrets")) {
      checksRun.push("client_bundle_secrets");
      checkerBudgets.client_bundle_secrets = {
        max: CHECK_BUDGETS.client_bundle_secrets,
        used: checkerBudgets.asset_collection?.used ?? 0
      };
      findings.push(...analysis.findings);
    }

    if (enabled("exposed_source_maps")) {
      checksRun.push("exposed_source_maps");
      findings.push(
        ...(await runWithBudget("exposed_source_maps", (scoped) => checkSourceMaps(assets, scoped)))
      );
    }

    if (enabled("exposed_infrastructure")) {
      checksRun.push("exposed_infrastructure");
      findings.push(
        ...(await runWithBudget("exposed_infrastructure", (scoped) =>
          checkInfrastructure(targetOrigin, scoped)
        ))
      );
    }

    if (enabled("cors")) {
      checksRun.push("cors");
      findings.push(
        ...(await runWithBudget("cors", (scoped) => checkCorsExposure(assets, targetOrigin, scoped)))
      );
    }

    if (enabled("public_api_surface")) {
      checksRun.push("public_api_surface");
      findings.push(
        ...(await runWithBudget("public_api_surface", (scoped) =>
          checkPublicApiSurface(assets, targetOrigin, scoped)
        ))
      );
    }

    let authorizedSupabaseProbeRan = false;
    if (
      input.authorizedSupabaseProbe &&
      !scanConfig.supabaseProbeDisabled &&
      enabled("supabase_rls_authorized_probe")
    ) {
      checksRun.push("supabase_rls_authorized_probe");
      authorizedSupabaseProbeRan = true;
      authorization = {
        scanId,
        targetOrigin,
        timestamp: new Date().toISOString(),
        checkboxTextVersion: AUTH_CHECKBOX_TEXT_VERSION,
        requesterFingerprint: requesterFingerprint(input.requester ?? {})
      };
      findings.push(
        ...(await runWithBudget("supabase_rls_authorized_probe", (scoped) =>
          checkSupabaseExposure(supabaseContext, scoped)
        ))
      );
    } else {
      if (!enabled("supabase_rls_authorized_probe")) {
        // Disabled checks are represented in checksDisabled rather than checksSkipped.
      } else {
        checksSkipped.push(
          input.authorizedSupabaseProbe ? "supabase_probe_disabled_by_operator" : "supabase_probe_requires_authorization"
        );
      }
    }

    if (!authorizedSupabaseProbeRan && enabled("client_bundle_secrets")) {
      const selfCheck = supabaseAnonSelfCheckFinding(supabaseContext);
      if (selfCheck) findings.push(selfCheck);
    }
  } catch (err) {
    status = "incomplete";
    incompleteReason = err instanceof Error ? err.message : "The scanner stopped before finishing.";
    checksSkipped.push("scan_incomplete");
  }

  const sortedFindings = findings.sort(
    (a, b) => severityRank[b.severity] - severityRank[a.severity]
  );
  const score = scoreReport(sortedFindings);
  const highest = highestSeverity(sortedFindings);
  const classification = classifyReport({ status, findings: sortedFindings, incompleteReason });

  const report: ScanReport = {
    id: scanId,
    targetOrigin,
    targetUrlRedacted: safeUrlForStorage(target),
    createdAt: new Date().toISOString(),
    ...classification,
    grade: score.grade,
    score: score.score,
    scanner: {
      version: "0.1.0",
      mode: "read_only",
      requestCount: budget.count(),
      requestBudget: TOTAL_REQUEST_BUDGET,
      checksRun,
      checksSkipped,
      checksDisabled,
      unknownDisabledChecks: disabled.unknown,
      checkerBudgets
    },
    findings: sortedFindings,
    authorization,
    aggregate: {
      hasClientSecretFinding: sortedFindings.some((finding) => finding.type === "client_secret"),
      hasSourceMapFinding: sortedFindings.some((finding) => finding.type === "source_map"),
      hasSupabaseRiskFinding: sortedFindings.some((finding) => finding.type === "supabase_rls"),
      hasInfrastructureFinding: sortedFindings.some((finding) => finding.type === "exposed_infrastructure"),
      hasCorsFinding: sortedFindings.some((finding) => finding.type === "cors"),
      hasSecurityHeaderFinding: sortedFindings.some((finding) => finding.type === "security_header"),
      hasPublicApiFinding: sortedFindings.some((finding) => finding.type === "public_api"),
      findingCount: sortedFindings.length,
      highestSeverity: highest
    }
  };

  return report;
}
