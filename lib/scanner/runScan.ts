import crypto from "node:crypto";
import type {
  AuthorizationArtifact,
  CheckStatusItem,
  Finding,
  PublicAsset,
  ScanReport,
  ScanStatus,
  StackProfile,
  SupabaseContext
} from "@/lib/types";
import { scanConfig } from "@/lib/env";
import { collectPublicAssets } from "@/lib/scanner/assets";
import { CHECK_BUDGETS, type CheckId, isCheckEnabled, parseDisabledChecks } from "@/lib/scanner/checks";
import { checkCorsExposure } from "@/lib/scanner/cors";
import { analyzeSecrets } from "@/lib/scanner/secrets";
import { checkClientDataExposure } from "@/lib/scanner/clientDataExposure";
import { checkDebugSchemas } from "@/lib/scanner/debugSchemas";
import { checkFirebaseConfig } from "@/lib/scanner/firebase";
import { checkPublicApiSurface } from "@/lib/scanner/publicApi";
import { checkSecurityHeaders } from "@/lib/scanner/securityHeaders";
import { checkSourceMaps } from "@/lib/scanner/sourceMaps";
import { checkSupabaseExposure, supabaseAnonSelfCheckFinding } from "@/lib/scanner/supabase";
import { checkInfrastructure } from "@/lib/scanner/infra";
import { normalizeScannerUrl, safeFetch, ScanBudget } from "@/lib/scanner/safeFetch";
import { safeUrlForStorage } from "@/lib/scanner/redaction";
import { classifyReport } from "@/lib/report/classification";
import { highestSeverity, scoreReport, severityRank } from "@/lib/report/scoring";
import { detectStack } from "@/lib/scanner/stack";

export const AUTH_CHECKBOX_TEXT_VERSION = "supabase-ownership-v1";
const TOTAL_REQUEST_BUDGET = 38;

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
  const checkStatuses: Record<string, CheckStatusItem> = {};
  const budget = new ScanBudget(TOTAL_REQUEST_BUDGET);
  const findings: Finding[] = [];
  let status: ScanStatus = "complete";
  let incompleteReason: string | undefined;
  let assets: PublicAsset[] = [];
  let supabaseContext: SupabaseContext = { serviceRoleKeyFingerprints: [] };
  let authorization: AuthorizationArtifact | undefined;
  let stack: StackProfile | undefined;

  for (const checkId of checksDisabled) {
    checkStatuses[checkId] = {
      status: "disabled",
      requestsUsed: 0,
      maxRequests: CHECK_BUDGETS[checkId],
      reason: "Disabled by DISABLED_CHECKS"
    };
  }

  function markSkipped(checkId: string, reason: string) {
    checkStatuses[checkId] = {
      status: "skipped",
      requestsUsed: 0,
      maxRequests: checkId in CHECK_BUDGETS ? CHECK_BUDGETS[checkId as CheckId] : undefined,
      reason
    };
  }

  function markCompleted(checkId: CheckId, requestsUsed: number) {
    checkStatuses[checkId] = {
      status: "completed",
      requestsUsed,
      maxRequests: CHECK_BUDGETS[checkId]
    };
  }

  function recordCheckerBudget(checkId: CheckId, scoped: ScanBudget) {
    const used = scoped.count();
    checkerBudgets[checkId] = {
      max: CHECK_BUDGETS[checkId],
      used
    };
    return used;
  }

  async function runWithBudget<T>(checkId: CheckId, fn: (scoped: ScanBudget) => Promise<T>) {
    const scoped = budget.scope(checkId, CHECK_BUDGETS[checkId]);
    try {
      const result = await fn(scoped);
      markCompleted(checkId, recordCheckerBudget(checkId, scoped));
      return result;
    } catch (err) {
      const reason = err instanceof Error ? err.message : "Check did not finish.";
      const used = recordCheckerBudget(checkId, scoped);
      checkStatuses[checkId] = {
        status: "incomplete",
        requestsUsed: used,
        maxRequests: CHECK_BUDGETS[checkId],
        reason
      };
      throw err;
    }
  }

  function enabled(checkId: CheckId) {
    return isCheckEnabled(checksDisabled, checkId);
  }

  try {
    const needsAssets =
      enabled("client_bundle_secrets") ||
      enabled("client_data_exposure") ||
      enabled("firebase_config") ||
      enabled("exposed_source_maps") ||
      enabled("cors") ||
      enabled("public_api_surface") ||
      (input.authorizedSupabaseProbe && enabled("supabase_rls_authorized_probe"));

    if (needsAssets) {
      assets = await runWithBudget("asset_collection", (scoped) =>
        collectPublicAssets(target.toString(), scoped)
      );
    } else {
      assets = [];
      markSkipped("asset_collection", "No enabled check needed page assets.");
    }
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
      stack = detectStack({ targetOrigin, headerAsset, assets });
      findings.push(...checkSecurityHeaders(headerAsset, targetOrigin, stack));
    } else {
      stack = detectStack({ targetOrigin, assets });
    }

    if (enabled("client_bundle_secrets")) {
      checksRun.push("client_bundle_secrets");
      checkerBudgets.client_bundle_secrets = {
        max: CHECK_BUDGETS.client_bundle_secrets,
        used: checkerBudgets.asset_collection?.used ?? 0
      };
      markCompleted("client_bundle_secrets", checkerBudgets.asset_collection?.used ?? 0);
      findings.push(...analysis.findings);
    }

    if (enabled("client_data_exposure")) {
      checksRun.push("client_data_exposure");
      checkerBudgets.client_data_exposure = {
        max: CHECK_BUDGETS.client_data_exposure,
        used: checkerBudgets.asset_collection?.used ?? 0
      };
      markCompleted("client_data_exposure", checkerBudgets.asset_collection?.used ?? 0);
      findings.push(...checkClientDataExposure(assets));
    }

    if (enabled("firebase_config")) {
      checksRun.push("firebase_config");
      checkerBudgets.firebase_config = {
        max: CHECK_BUDGETS.firebase_config,
        used: checkerBudgets.asset_collection?.used ?? 0
      };
      markCompleted("firebase_config", checkerBudgets.asset_collection?.used ?? 0);
      findings.push(...checkFirebaseConfig(assets));
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

    if (enabled("debug_schema_surface")) {
      checksRun.push("debug_schema_surface");
      findings.push(
        ...(await runWithBudget("debug_schema_surface", (scoped) =>
          checkDebugSchemas(targetOrigin, scoped)
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
        const skipReason = input.authorizedSupabaseProbe
          ? "Supabase probe disabled by operator configuration."
          : "Supabase probe requires the ownership checkbox.";
        checksSkipped.push(
          input.authorizedSupabaseProbe ? "supabase_probe_disabled_by_operator" : "supabase_probe_requires_authorization"
        );
        markSkipped("supabase_rls_authorized_probe", skipReason);
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
    markSkipped("scan_incomplete", incompleteReason);
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
      checkerBudgets,
      checkStatuses,
      stack
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
      hasClientDataExposureFinding: sortedFindings.some((finding) => finding.type === "client_data_exposure"),
      hasDebugSchemaFinding: sortedFindings.some((finding) => finding.type === "debug_schema"),
      hasFirebaseConfigFinding: sortedFindings.some((finding) => finding.type === "firebase_config"),
      findingCount: sortedFindings.length,
      highestSeverity: highest
    }
  };

  return report;
}
