import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ReportView } from "@/components/ReportView";
import { classifyReport } from "@/lib/report/classification";
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
      requestBudget: 35,
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
  assert.match(html, /Copy fix/);
  assert.match(html, /next.config.js/);
  assert.match(html, /vercel.json/);
  assert.match(html, /async headers\(\)/);
  assert.match(html, /Content-Security-Policy/);
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
