import assert from "node:assert/strict";
import test from "node:test";
import { bundleFindingsForDisplay, classifyReport } from "@/lib/report/classification";
import { createFinding } from "@/lib/report/findingModel";
import { remediationsFor } from "@/lib/report/remediations";
import { scoreReport } from "@/lib/report/scoring";
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
  Severity,
  StackProfile
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
	  type?: Finding["type"];
	}): Finding {
	  return createFinding({
	    id: `${input.tier}-${input.location}-${input.runbookCode}`,
	    type: input.type ?? (input.runbookCode === "RLS_SELF_CHECK" || input.runbookCode === "RLS_LOCKDOWN_INCIDENT"
	      ? "supabase_rls"
	      : "client_secret"),
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
      name: "confirmed open private Supabase read",
      tier: "critical",
      location: "supabase_rest",
      rlsInference: "confirmed_open",
      runbookCode: "RLS_LOCKDOWN_INCIDENT",
      expectedState: "incident",
      expectedRunbook: "RLS_LOCKDOWN_INCIDENT"
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
  assert.ok(result.remediations.every((item) => item.beginnerContext.trim()));
});

test("weighted scoring uses all raw findings and caps incidents to F", () => {
  const fourFindings = Array.from({ length: 4 }, (_, index) =>
    finding({
      tier: "unknown",
      location: "response_header",
      runbookCode: "HEADER_HARDEN",
      severity: "low",
      reasonCode: `missing_header_${index}`,
      type: "security_header"
    })
  );
  const fiveFindings = [
    ...fourFindings,
    finding({
      tier: "unknown",
      location: "response_header",
      runbookCode: "HEADER_HARDEN",
      severity: "low",
      reasonCode: "missing_header_4",
      type: "security_header"
    })
  ];
  const incident = [
    finding({
      tier: "critical",
      location: "client_bundle",
      runbookCode: "INCIDENT_ROTATE",
      severity: "critical"
    })
  ];

  assert.notEqual(scoreReport(fourFindings).score, scoreReport(fiveFindings).score);
  assert.deepEqual(scoreReport(incident), { grade: "F", score: 35 });
});

test("display bundling groups related raw findings without changing members", () => {
  const findings = [
    finding({
      tier: "unknown",
      location: "response_header",
      runbookCode: "HEADER_HARDEN",
      severity: "medium",
      reasonCode: "missing_content_security_policy",
      type: "security_header"
    }),
    finding({
      tier: "unknown",
      location: "response_header",
      runbookCode: "HEADER_HARDEN",
      severity: "low",
      reasonCode: "missing_hsts",
      type: "security_header"
    }),
    createFinding({
      id: "source-map-1",
      type: "source_map",
      title: "Public source map",
      severity: "medium",
      confidence: "confirmed",
      reasonCode: "public_source_map_confirmed",
      tier: "unknown",
      location: "public_web_path",
      rlsInference: "not_applicable",
      runbookCode: "SOURCE_MAP_DISABLE",
      summary: "summary",
      explanation: "explanation",
      limitation: "limitation",
      evidence: [{ label: "Source map URL", value: "https://example.com/app.js.map" }]
    }),
    createFinding({
      id: "cors-1",
      type: "cors",
      title: "Permissive CORS",
      severity: "high",
      confidence: "confirmed",
      reasonCode: "credentialed_permissive_cors",
      tier: "unknown",
      location: "referenced_api",
      rlsInference: "not_applicable",
      runbookCode: "CORS_TIGHTEN",
      summary: "summary",
      explanation: "explanation",
      limitation: "limitation",
      evidence: [{ label: "Endpoint", value: "https://example.com/api/me" }]
    }),
    createFinding({
      id: "secret-1",
      type: "client_secret",
      title: "Secret in bundle",
      severity: "critical",
      confidence: "confirmed",
      reasonCode: "openai_key_in_client_bundle",
      tier: "critical",
      location: "client_bundle",
      rlsInference: "not_applicable",
      runbookCode: "INCIDENT_ROTATE",
      summary: "summary",
      explanation: "explanation",
      limitation: "limitation",
      evidence: [{ label: "Asset", value: "https://example.com/app.js" }]
    })
  ];

  const groups = bundleFindingsForDisplay(findings);
  assert.equal(groups.length, 4);
  assert.equal(groups.find((group) => group.title.includes("Browser security headers"))?.members.length, 2);
  assert.ok(groups.some((group) => group.title.includes("Public source maps exposed")));
  assert.ok(groups.some((group) => group.title.includes("API endpoint exposure")));
  assert.ok(groups.some((group) => group.title.includes("Credential exposure incident")));
});

test("stack-aware header remediations keep Vercel config scoped to Vercel", () => {
  const vercelNext: StackProfile = {
    host: "vercel",
    framework: "next",
    backend: "unknown",
    confidence: "confirmed",
    signals: ["x-vercel-id header", "Next.js asset marker"]
  };
  const netlify: StackProfile = {
    host: "netlify",
    framework: "react",
    backend: "unknown",
    confidence: "confirmed",
    signals: ["x-nf-request-id header"]
  };
  const django: StackProfile = {
    host: "kilo",
    framework: "unknown",
    backend: "django",
    confidence: "likely",
    signals: ["kiloapps.io hostname", "Django/backend header or CSRF marker"]
  };
  const unknown: StackProfile = {
    host: "unknown",
    framework: "unknown",
    backend: "unknown",
    confidence: "unknown",
    signals: []
  };

  assert.deepEqual(
    remediationsFor("HEADER_HARDEN", "security_header", vercelNext).map((item) => item.targetLocation),
    ["next.config.js", "vercel.json"]
  );
  assert.ok(remediationsFor("HEADER_HARDEN", "security_header", netlify).some((item) => item.targetLocation === "netlify.toml"));
  assert.ok(remediationsFor("HEADER_HARDEN", "security_header", django).some((item) => item.targetLocation.includes("Django")));
  for (const profile of [netlify, django, unknown]) {
    assert.ok(
      remediationsFor("HEADER_HARDEN", "security_header", profile).every((item) => item.targetLocation !== "vercel.json")
    );
  }
  assert.ok(
    remediationsFor("HEADER_HARDEN", "security_header", unknown).every((item) =>
      item.beginnerContext.includes("unsafe-inline")
    )
  );
  assert.ok(!JSON.stringify(remediationsFor("HEADER_HARDEN", "security_header", vercelNext)).includes("preload"));
});

test("header-only findings route to Fixable instead of Clean", () => {
  const result = classifyReport({
    status: "complete",
    findings: [
      createFinding({
        id: "header-only",
        type: "security_header",
        title: "Missing Content Security Policy",
        severity: "medium",
        confidence: "confirmed",
        reasonCode: "missing_content_security_policy",
        tier: "unknown",
        location: "response_header",
        rlsInference: "not_applicable",
        runbookCode: "HEADER_HARDEN",
        summary: "summary",
        explanation: "explanation",
        limitation: "limitation",
        evidence: [{ label: "URL", value: "https://example.com" }]
      })
    ]
  });

  assert.equal(result.state, "fixable");
});

test("new passive detector findings route to expected states", () => {
  const fixableHydration = createFinding({
    id: "hydration-fixable",
    type: "client_data_exposure",
    title: "Large client hydration payload contains private-looking fields",
    severity: "medium",
    confidence: "likely",
    reasonCode: "next_data_private_shape_in_client_payload",
    tier: "unknown",
    location: "client_bundle",
    rlsInference: "not_applicable",
    runbookCode: "CLIENT_DATA_MINIMIZE",
    summary: "summary",
    explanation: "explanation",
    limitation: "limitation",
    evidence: [{ label: "Asset", value: "https://example.com/" }]
  });
  const incidentHydration = createFinding({
    ...fixableHydration,
    id: "hydration-incident",
    title: "Sensitive-looking records are serialized to the client",
    severity: "critical",
    confidence: "confirmed",
    reasonCode: "next_data_sensitive_record_dump",
    tier: "critical"
  });
  const debugSchema = createFinding({
    id: "debug-schema",
    type: "debug_schema",
    title: "Public OpenAPI or Swagger schema is exposed",
    severity: "medium",
    confidence: "likely",
    reasonCode: "public_openapi_schema",
    tier: "unknown",
    location: "public_web_path",
    rlsInference: "not_applicable",
    runbookCode: "DEBUG_SCHEMA_RESTRICT",
    summary: "summary",
    explanation: "explanation",
    limitation: "limitation",
    evidence: [{ label: "Schema path", value: "https://example.com/openapi.json" }]
  });
  const firebase = createFinding({
    id: "firebase",
    type: "firebase_config",
    title: "Firebase browser config detected; audit Security Rules",
    severity: "medium",
    confidence: "likely",
    reasonCode: "firebase_config_in_client_bundle",
    tier: "public_by_design",
    location: "client_bundle",
    rlsInference: "unverifiable",
    runbookCode: "FIREBASE_RULES_SELF_CHECK",
    summary: "summary",
    explanation: "explanation",
    limitation: "limitation",
    evidence: [{ label: "Asset", value: "https://example.com/app.js" }]
  });

  assert.equal(classifyReport({ status: "complete", findings: [fixableHydration] }).state, "fixable");
  assert.equal(classifyReport({ status: "complete", findings: [incidentHydration] }).state, "incident");
  assert.equal(classifyReport({ status: "complete", findings: [debugSchema] }).state, "fixable");
  assert.equal(classifyReport({ status: "complete", findings: [firebase] }).state, "fixable");
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
    { name: "Supabase anon read", findings: supabaseFindings, state: "incident" },
    { name: "no findings", findings: [] as Finding[], state: "clean" }
  ] as const;

  for (const item of cases) {
    const result = classifyReport({ status: "complete", findings: item.findings });
    assert.equal(result.state, item.state, item.name);
  }
});
