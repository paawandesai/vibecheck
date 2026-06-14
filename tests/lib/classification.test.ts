import assert from "node:assert/strict";
import test from "node:test";
import { classifyReport } from "@/lib/report/classification";
import { createFinding } from "@/lib/report/findingModel";
import { checkInfrastructure } from "@/lib/scanner/infra";
import { analyzeSecrets } from "@/lib/scanner/secrets";
import { checkSourceMaps } from "@/lib/scanner/sourceMaps";
import { checkSupabaseExposure } from "@/lib/scanner/supabase";
import { ScanBudget } from "@/lib/scanner/safeFetch";
import type {
  Confidence,
  Finding,
  FindingLocation,
  FindingTier,
  RlsInference,
  RunbookCode,
  Severity
} from "@/lib/types";
import { infraExposedFetch } from "../fixtures/infraTargets";
import { leakyAssets } from "../fixtures/assets";
import { publicResolver, supabaseContext, supabaseReadableFetch } from "../fixtures/supabaseTargets";

function finding(input: {
  tier: FindingTier;
  location: FindingLocation;
  rlsInference?: RlsInference;
  runbookCode: RunbookCode;
  severity?: Severity;
  confidence?: Confidence;
  reasonCode?: string;
}): Finding {
  return createFinding({
    id: `${input.tier}-${input.location}-${input.runbookCode}`,
    type: input.runbookCode === "RLS_SELF_CHECK" ? "supabase_rls" : "client_secret",
    title: `${input.runbookCode} finding`,
    severity: input.severity ?? (input.tier === "critical" ? "critical" : "medium"),
    confidence: input.confidence ?? "confirmed",
    reasonCode: input.reasonCode ?? input.runbookCode.toLowerCase(),
    tier: input.tier,
    location: input.location,
    rlsInference: input.rlsInference ?? "not_applicable",
    runbookCode: input.runbookCode,
    summary: "summary",
    explanation: "explanation",
    limitation: "limitation",
    evidence: [{ label: "Asset", value: "https://example.com/app.js" }]
  });
}

test("classification precedence makes incomplete beat critical", () => {
  const result = classifyReport({
    status: "incomplete",
    incompleteReason: "scan request budget exceeded",
    findings: [
      finding({
        tier: "critical",
        location: "client_bundle",
        runbookCode: "INCIDENT_ROTATE"
      })
    ]
  });

  assert.equal(result.state, "incomplete");
  assert.equal(result.primaryRunbookCode, undefined);
  assert.match(result.stateReason, /budget exceeded/);
});

test("classification matrix routes finding tier, location, and RLS inference", () => {
  const cases: Array<{
    name: string;
    tier: FindingTier;
    location: FindingLocation;
    rlsInference?: RlsInference;
    runbookCode: RunbookCode;
    expectedState: "clean" | "fixable" | "incident";
    expectedRunbook?: RunbookCode;
  }> = [
    {
      name: "public anon key in client bundle",
      tier: "public_by_design",
      location: "client_bundle",
      rlsInference: "unverifiable",
      runbookCode: "RLS_SELF_CHECK",
      expectedState: "fixable",
      expectedRunbook: "RLS_SELF_CHECK"
    },
    {
      name: "public anon key in public repo head",
      tier: "public_by_design",
      location: "public_repo_head",
      rlsInference: "unverifiable",
      runbookCode: "RLS_SELF_CHECK",
      expectedState: "fixable",
      expectedRunbook: "RLS_SELF_CHECK"
    },
    {
      name: "public anon key in private repo",
      tier: "public_by_design",
      location: "private_repo",
      rlsInference: "unverifiable",
      runbookCode: "INFO_ONLY",
      expectedState: "clean"
    },
    {
      name: "critical in client bundle",
      tier: "critical",
      location: "client_bundle",
      runbookCode: "INCIDENT_ROTATE",
      expectedState: "incident",
      expectedRunbook: "INCIDENT_ROTATE"
    },
    {
      name: "critical in public repo head",
      tier: "critical",
      location: "public_repo_head",
      runbookCode: "INCIDENT_ROTATE",
      expectedState: "incident",
      expectedRunbook: "INCIDENT_ROTATE"
    },
    {
      name: "critical in public repo history",
      tier: "critical",
      location: "public_repo_history",
      runbookCode: "INCIDENT_ROTATE_HISTORICAL",
      expectedState: "incident",
      expectedRunbook: "INCIDENT_ROTATE_HISTORICAL"
    },
    {
      name: "critical committed env",
      tier: "critical",
      location: "committed_env",
      runbookCode: "INCIDENT_ROTATE",
      expectedState: "incident",
      expectedRunbook: "INCIDENT_ROTATE"
    },
    {
      name: "unknown public surface",
      tier: "unknown",
      location: "public_web_path",
      runbookCode: "MANUAL_TRIAGE",
      expectedState: "fixable",
      expectedRunbook: "MANUAL_TRIAGE"
    },
    {
      name: "unknown private repo",
      tier: "unknown",
      location: "private_repo",
      runbookCode: "MANUAL_TRIAGE",
      expectedState: "fixable",
      expectedRunbook: "MANUAL_TRIAGE"
    }
  ];

  for (const item of cases) {
    const result = classifyReport({
      status: "complete",
      findings: [
        finding({
          tier: item.tier,
          location: item.location,
          rlsInference: item.rlsInference,
          runbookCode: item.runbookCode
        })
      ]
    });

    assert.equal(result.state, item.expectedState, item.name);
    assert.equal(result.primaryRunbookCode, item.expectedRunbook, item.name);
  }
});

test("new findings require structured remediation data", () => {
  const result = finding({
    tier: "unknown",
    location: "referenced_api",
    runbookCode: "API_AUTH_REVIEW"
  });

  assert.ok(result.remediations.length > 0);
  assert.ok(result.remediations.every((item) => item.snippet.trim()));
  assert.ok(result.remediations.every((item) => item.targetLocation.trim()));
});

test("current checker outputs route to the expected report states", async () => {
  const sourceMapFetch: typeof fetch = async () =>
    new Response(JSON.stringify({ version: 3, sources: ["app.ts"], mappings: "" }), {
      status: 200
    });
  const sourceMapFindings = await checkSourceMaps(
    [
      {
        url: "https://example.com/app.js",
        type: "script",
        body: "console.log('x');\n//# sourceMappingURL=app.js.map",
        truncated: false
      }
    ],
    new ScanBudget(1),
    { fetchImpl: sourceMapFetch, resolveHostname: publicResolver }
  );
  const infra = infraExposedFetch();
  const infraFindings = await checkInfrastructure("https://example.com", new ScanBudget(12), {
    fetchImpl: infra.fetchImpl,
    resolveHostname: publicResolver
  });
  const supabase = supabaseReadableFetch();
  const supabaseFindings = await checkSupabaseExposure(supabaseContext, new ScanBudget(5), {
    fetchImpl: supabase.fetchImpl,
    resolveHostname: publicResolver
  });

  const cases = [
    { name: "leaked key", findings: analyzeSecrets(leakyAssets).findings, state: "incident" },
    { name: "public source map", findings: sourceMapFindings, state: "fixable" },
    { name: "exposed infra critical", findings: infraFindings, state: "incident" },
    { name: "Supabase anon read", findings: supabaseFindings, state: "fixable" },
    { name: "no findings", findings: [] as Finding[], state: "clean" }
  ] as const;

  for (const item of cases) {
    const result = classifyReport({ status: "complete", findings: item.findings });
    assert.equal(result.state, item.state, item.name);
  }
});
