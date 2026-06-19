import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { buildAllFixesPrompt, buildFindingGroupPrompt, buildSingleFixPrompt, ReportView } from "@/components/ReportView";
import { classifyReport, normalizeReportForDisplay } from "@/lib/report/classification";
import { createFinding } from "@/lib/report/findingModel";
import type { CheckStatusItem, Finding, ScanReport, ScanStatus } from "@/lib/types";

function baseFinding(overrides: Partial<Finding>): Finding {
  return createFinding({
    id: overrides.id ?? "finding-1",
    type: overrides.type ?? "security_header",
    title: overrides.title ?? "Missing Content Security Policy",
    severity: overrides.severity ?? "medium",
    confidence: overrides.confidence ?? "confirmed",
    reasonCode: overrides.reasonCode ?? "missing_content_security_policy",
    tier: overrides.tier ?? "unknown",
    location: overrides.location ?? "response_header",
    rlsInference: overrides.rlsInference ?? "not_applicable",
    runbookCode: overrides.runbookCode ?? "HEADER_HARDEN",
    summary: overrides.summary ?? "The public page does not send a Content-Security-Policy header.",
    explanation: overrides.explanation ?? "A CSP helps reduce the blast radius of browser-side bugs.",
    limitation: overrides.limitation ?? "Headers only.",
    evidence: overrides.evidence ?? [{ label: "URL", value: "https://example.com" }],
    remediations: overrides.remediations
  });
}

function report(findings: Finding[], status: ScanStatus = "complete"): ScanReport {
  const classification = classifyReport({ status, findings, incompleteReason: "request budget exceeded" });
  const checkStatuses: Record<string, CheckStatusItem> =
    status === "incomplete"
      ? {
          security_headers: {
            status: "completed" as const,
            requestsUsed: 1,
            maxRequests: 1
          },
          cors: {
            status: "incomplete" as const,
            requestsUsed: 5,
            maxRequests: 5,
            reason: "request budget exceeded"
          }
        }
      : {
          security_headers: {
            status: "completed" as const,
            requestsUsed: 1,
            maxRequests: 1
          },
          supabase_rls_authorized_probe: {
            status: "skipped" as const,
            requestsUsed: 0,
            maxRequests: 5,
            reason: "Supabase probe requires the ownership checkbox."
          }
        };

  return {
    id: "00000000-0000-4000-8000-000000000000",
    targetOrigin: "https://example.com",
    targetUrlRedacted: "https://example.com/",
    createdAt: "2026-06-14T00:00:00.000Z",
    ...classification,
    grade: findings.some((finding) => finding.tier === "critical") ? "F" : "C",
    score: findings.length ? 72 : 96,
    scanner: {
      version: "0.1.0",
      mode: "read_only",
      requestCount: 8,
      requestBudget: 38,
      checksRun: ["security_headers"],
      checksSkipped: ["supabase_probe_requires_authorization"],
      checksDisabled: [],
      unknownDisabledChecks: [],
      checkerBudgets: {},
      checkStatuses
    },
    findings,
    aggregate: {
      hasClientSecretFinding: findings.some((finding) => finding.type === "client_secret"),
      hasSourceMapFinding: findings.some((finding) => finding.type === "source_map"),
      hasSupabaseRiskFinding: findings.some((finding) => finding.type === "supabase_rls"),
      hasInfrastructureFinding: findings.some((finding) => finding.type === "exposed_infrastructure"),
      hasCorsFinding: findings.some((finding) => finding.type === "cors"),
      hasSecurityHeaderFinding: findings.some((finding) => finding.type === "security_header"),
      hasPublicApiFinding: findings.some((finding) => finding.type === "public_api"),
      hasClientDataExposureFinding: findings.some((finding) => finding.type === "client_data_exposure"),
      hasDebugSchemaFinding: findings.some((finding) => finding.type === "debug_schema"),
      hasFirebaseConfigFinding: findings.some((finding) => finding.type === "firebase_config"),
      findingCount: findings.length,
      highestSeverity: findings[0]?.severity ?? "none"
    }
  };
}

function render(input: ScanReport) {
  return renderToStaticMarkup(React.createElement(ReportView, { report: input }));
}

test("clean report renders green progressive disclosure", () => {
  const html = render(report([]));
  assert.match(html, /Clean on visible surfaces/);
  assert.match(html, /What we checked/);
  assert.match(html, /What we could not see/);
});

test("fixable report renders remediation checklist and copy buttons", () => {
  const html = render(report([baseFinding({})]));
  assert.match(html, /Fixable/);
  assert.match(html, /Hygiene score C · 72\/100/);
  assert.match(html, /1 finding · 1 group/);
  assert.match(html, /AI-ready remediation brief/);
  assert.match(html, /Copy all fixes for AI agent/);
  assert.match(html, /Copy fix/);
  assert.match(html, /Copy-paste fix prompt/);
  assert.match(html, /Copy agent prompt/);
  assert.match(html, /Send this to any AI coding agent/);
  assert.doesNotMatch(html, /Bolt/);
  assert.doesNotMatch(html, /Cursor/);
  assert.doesNotMatch(html, /Lovable/);
  assert.doesNotMatch(html, /Replit/);
  assert.match(html, /CDN, reverse proxy, or hosting edge/);
  assert.doesNotMatch(html, /vercel\.json/);
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /unsafe-inline/);
});

test("all-fixes prompt includes report context and remediation snippets", () => {
  const generated = buildAllFixesPrompt(report([baseFinding({})]));

  assert.match(generated, /You are an AI coding agent working in the target application's repository/);
  assert.match(generated, /Target: https:\/\/example\.com/);
  assert.match(generated, /Report state: Fixable \(fixable\)/);
  assert.match(generated, /Missing Content Security Policy/);
  assert.match(generated, /Evidence:/);
  assert.match(generated, /Recommended fixes:/);
  assert.match(generated, /Content-Security-Policy/);
  assert.match(generated, /Do not exploit, mutate, brute force, bypass auth, or probe private systems/);
});

test("single-fix prompt includes context around the copied snippet", () => {
  const normalized = normalizeReportForDisplay(report([baseFinding({})]));
  const group = normalized.displayGroups[0];
  const remediation = group.remediations[0];
  const generated = buildSingleFixPrompt(normalized, group, remediation);

  assert.match(generated, /Apply this single VibeCheck remediation/);
  assert.match(generated, /Target: https:\/\/example\.com/);
  assert.match(generated, /Finding group: Browser security headers/);
  assert.match(generated, /Representative finding: Missing Content Security Policy/);
  assert.match(generated, /Evidence:/);
  assert.match(generated, /URL: https:\/\/example\.com/);
  assert.match(generated, /Scanner limitation: Headers only/);
  assert.match(generated, /Target location: CDN, reverse proxy, or hosting edge/);
  assert.match(generated, /Content-Security-Policy/);
  assert.match(generated, /Adapt the snippet to the repo's framework/);
});

test("finding-group prompt is generic and agent-ready", () => {
  const normalized = normalizeReportForDisplay(report([baseFinding({})]));
  const generated = buildFindingGroupPrompt(normalized, normalized.displayGroups[0]);

  assert.match(generated, /You are an AI coding agent working in the target application's repository/);
  assert.match(generated, /Fix this VibeCheck finding group/);
  assert.match(generated, /Target: https:\/\/example\.com/);
  assert.match(generated, /Evidence:/);
  assert.match(generated, /Recommended fixes:/);
  assert.match(generated, /tool-neutral|production-safe|smallest safe changes/);
  assert.doesNotMatch(generated, /Bolt|Cursor|Lovable|Replit/);
});

test("header-only report renders one grouped card with raw finding count", () => {
  const findings = [
    baseFinding({ id: "header-csp", title: "Missing Content Security Policy", reasonCode: "missing_content_security_policy" }),
    baseFinding({ id: "header-hsts", title: "Missing HSTS header", reasonCode: "missing_hsts", severity: "low" }),
    baseFinding({ id: "header-nosniff", title: "Missing X-Content-Type-Options nosniff", reasonCode: "missing_nosniff", severity: "low" }),
    baseFinding({ id: "header-frame", title: "Missing frame embedding protection", reasonCode: "missing_frame_protection", severity: "low" }),
    baseFinding({ id: "header-referrer", title: "Missing or weak Referrer-Policy", reasonCode: "weak_referrer_policy", severity: "low" })
  ];
  const html = render(report(findings));

  assert.match(html, /5 findings · 1 group/);
  assert.match(html, /Browser security headers \(5 items\)/);
  assert.equal(html.match(/Copy fix/g)?.length, 1);
  assert.match(html, /Missing HSTS header/);
  assert.match(html, /Missing or weak Referrer-Policy/);
});

test("incident report renders procedural runbook before evidence", () => {
  const html = render(
    report([
      baseFinding({
        type: "client_secret",
        title: "Service role key appears in a public client asset",
        severity: "critical",
        reasonCode: "supabase_service_role_key_in_client_bundle",
        tier: "critical",
        location: "client_bundle",
        runbookCode: "INCIDENT_ROTATE"
      })
    ])
  );
  assert.match(html, /Incident runbook/);
  assert.match(html, /Stop the bleeding/);
  assert.match(html, /If active abuse is suspected/);
  assert.match(html, /Assess blast radius/);
  assert.match(html, /Remediate/);
  assert.match(html, /grep -RInE/);
});

test("Supabase incident report renders emergency fork and RLS lockdown SQL", () => {
  const html = render(
    report([
      baseFinding({
        type: "supabase_rls",
        title: "Anonymous read confirmed on likely private Supabase table \"profiles\"",
        severity: "critical",
        reasonCode: "supabase_anon_read_probe_allowed",
        tier: "critical",
        location: "supabase_rest",
        rlsInference: "confirmed_open",
        runbookCode: "RLS_LOCKDOWN_INCIDENT",
        evidence: [{ label: "Read-only probe", value: "HEAD /rest/v1/profiles?select=* returned 200" }]
      })
    ])
  );

  assert.match(html, /If active abuse is suspected/);
  assert.match(html, /alter table public\.&lt;TABLE_NAME&gt; enable row level security/);
  assert.match(html, /Supabase Logs/);
});

test("incomplete report renders neutral no-safety-claim copy", () => {
  const html = render(report([], "incomplete"));
  assert.match(html, /Incomplete/);
  assert.match(html, /Do not treat this as clean/);
  assert.match(html, /request budget exceeded/);
  assert.match(html, /cors incomplete/);
});
