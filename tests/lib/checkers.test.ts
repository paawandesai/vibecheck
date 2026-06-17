import assert from "node:assert/strict";
import test from "node:test";
import { analyzeSecrets } from "@/lib/scanner/secrets";
import { checkClientDataExposure } from "@/lib/scanner/clientDataExposure";
import { checkDebugSchemas } from "@/lib/scanner/debugSchemas";
import { checkFirebaseConfig } from "@/lib/scanner/firebase";
import { checkSupabaseExposure, supabaseAnonSelfCheckFinding } from "@/lib/scanner/supabase";
import { classifyReport } from "@/lib/report/classification";
import { escapeEvidence } from "@/lib/scanner/redaction";
import { ScanBudget } from "@/lib/scanner/safeFetch";
import { checkSourceMaps, findSourceMapReferences } from "@/lib/scanner/sourceMaps";
import {
  cleanAssets,
  leakyAssets,
  supabaseAnonJwt,
  supabaseServiceRoleJwt,
  xssAsset
} from "../fixtures/assets";
import {
  publicResolver,
  supabaseContext,
  supabaseProtectedFetch,
  supabaseReadableFetch
} from "../fixtures/supabaseTargets";

test("clean fixture has no client secret findings", () => {
  const result = analyzeSecrets(cleanAssets);
  assert.equal(result.findings.length, 0);
});

test("leaky fixture produces redacted high-confidence findings without raw secret storage", () => {
  const result = analyzeSecrets(leakyAssets);
  assert.equal(result.findings.length, 7);
  assert.ok(result.findings.every((finding) => finding.confidence === "confirmed"));

  const serialized = JSON.stringify(result.findings);
  assert.ok(!serialized.includes("sk_live_1234567890abcdefghijkl"));
  assert.ok(!serialized.includes(supabaseServiceRoleJwt));
});

test("Supabase anon keys are collected for gated probes, not reported as secrets", () => {
  const result = analyzeSecrets([
    {
      url: "https://demo.example/app.js",
      type: "script",
      body: `const supabaseUrl = "https://demo.supabase.co"; const anon = "${supabaseAnonJwt}";`,
      truncated: false
    }
  ]);
  assert.equal(result.findings.length, 0);
});

test("AI-era secret expansion routes modern provider keys to incident without raw storage", () => {
  const samples = [
    {
      reasonCode: "deepseek_key_in_client_bundle",
      value: "sk-deepseek1234567890abcdefghijklmnopqrstuvwxyz"
    },
    {
      reasonCode: "openrouter_key_in_client_bundle",
      value: "sk-or-v1-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
    },
    {
      reasonCode: "pinecone_key_in_client_bundle",
      value: "pcsk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
    },
    {
      reasonCode: "langsmith_key_in_client_bundle",
      value: "lsv2_pt_abcdefghijklmnopqrstuvwxyzABCDE12345"
    },
    {
      reasonCode: "langfuse_secret_key_in_client_bundle",
      value: "sk-lf-abcdefghijklmnopqrstuvwxyzABCDE12345"
    },
    {
      reasonCode: "stripe_clerk_secret_key_in_client_bundle",
      value: "sk_test_1234567890abcdefghijklmnopqrstu"
    }
  ];
  const body = [
    `const deepseekKey = "${samples[0].value}";`,
    ...samples.slice(1).map((sample) => `const value = "${sample.value}";`)
  ].join("\n");

  const result = analyzeSecrets([
    {
      url: "https://demo.example/app.js",
      type: "script",
      body,
      truncated: false
    }
  ]);
  const reasonCodes = new Set(result.findings.map((finding) => finding.reasonCode));

  for (const sample of samples) {
    assert.ok(reasonCodes.has(sample.reasonCode), `${sample.reasonCode} should be detected`);
  }
  assert.ok(result.findings.every((finding) => finding.severity === "critical"));
  assert.equal(classifyReport({ status: "complete", findings: result.findings }).state, "incident");

  const serialized = JSON.stringify(result.findings);
  for (const sample of samples) {
    assert.ok(!serialized.includes(sample.value), `${sample.value} should not be stored raw`);
  }
});

test("client hydration detector ignores benign Next data", () => {
  const findings = checkClientDataExposure([
    {
      url: "https://demo.example/",
      type: "html",
      body: `<script id="__NEXT_DATA__" type="application/json">${JSON.stringify({
        props: { pageProps: { title: "Hello" } },
        page: "/"
      })}</script>`,
      truncated: false
    }
  ]);

  assert.equal(findings.length, 0);
});

test("client hydration detector flags fixable private-looking payloads without storing PII", () => {
  const privateEmail = "founder@example.com";
  const findings = checkClientDataExposure([
    {
      url: "https://demo.example/",
      type: "html",
      body: `<script id="__NEXT_DATA__" type="application/json">${JSON.stringify({
        props: {
          pageProps: {
            account: { email: privateEmail, role: "owner" },
            filler: "x".repeat(2500)
          }
        }
      })}</script>`,
      truncated: false
    }
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, "client_data_exposure");
  assert.equal(findings[0].severity, "medium");
  assert.equal(classifyReport({ status: "complete", findings }).state, "fixable");
  assert.ok(!JSON.stringify(findings).includes(privateEmail));
});

test("client hydration detector escalates repeated sensitive records to incident", () => {
  const users = Array.from({ length: 3 }, (_, index) => ({
    id: index + 1,
    email: `customer-${index}@example.com`,
    role: index === 0 ? "admin" : "member",
    phone: `+1555123000${index}`
  }));
  const findings = checkClientDataExposure([
    {
      url: "https://demo.example/",
      type: "html",
      body: `<script id="__NEXT_DATA__" type="application/json">${JSON.stringify({
        props: { pageProps: { users } }
      })}</script>`,
      truncated: false
    }
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.equal(findings[0].tier, "critical");
  assert.equal(classifyReport({ status: "complete", findings }).state, "incident");
  assert.ok(!JSON.stringify(findings).includes("customer-0@example.com"));
});

test("RSC payload detector flags large private-looking payloads", () => {
  const findings = checkClientDataExposure([
    {
      url: "https://demo.example/",
      type: "html",
      body: `<script>self.__next_f.push([1,"{\\"email\\":\\"owner@example.com\\",\\"role\\":\\"owner\\",\\"notes\\":\\"${"x".repeat(2500)}\\"}"])</script>`,
      truncated: false
    }
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].reasonCode, "rsc_private_shape_in_client_payload");
  assert.ok(!JSON.stringify(findings).includes("owner@example.com"));
});

test("source map references are detected without storing source map contents", () => {
  const refs = findSourceMapReferences([
    {
      url: "https://demo.example/app.js",
      type: "script",
      body: "console.log('x');\n//# sourceMappingURL=app.js.map",
      truncated: false
    }
  ]);

  assert.deepEqual(refs, [
    {
      assetUrl: "https://demo.example/app.js",
      mapUrl: "https://demo.example/app.js.map"
    }
  ]);
});

test("debug schema checker uses GET-only predictable paths and stores only metadata", async () => {
  const calls: Array<{ url: string; method: string }> = [];
  const schema = {
    openapi: "3.0.0",
    paths: {
      "/api/users": {
        get: {
          responses: { 200: { description: "ok" } }
        }
      }
    },
    components: {
      schemas: {
        User: {
          properties: {
            email: { type: "string" }
          }
        }
      }
    }
  };
  const fetchImpl: typeof fetch = async (input, init) => {
    calls.push({ url: input.toString(), method: init?.method ?? "GET" });
    if (input.toString().endsWith("/openapi.json")) {
      return new Response(JSON.stringify(schema), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response("not found", { status: 404 });
  };

  const findings = await checkDebugSchemas("https://demo.example", new ScanBudget(3), {
    fetchImpl,
    resolveHostname: publicResolver
  });

  assert.equal(calls.length, 3);
  assert.ok(calls.every((call) => call.method === "GET"));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, "debug_schema");
  assert.equal(classifyReport({ status: "complete", findings }).state, "fixable");
  assert.ok(!JSON.stringify(findings).includes("User"));
  assert.ok(!JSON.stringify(findings).includes("email"));
});

test("debug schema checker detects public GraphQL explorer markers", async () => {
  const fetchImpl: typeof fetch = async (input) => {
    if (input.toString().endsWith("/api/graphql")) {
      return new Response("<html>GraphiQL Apollo Sandbox __schema queryType</html>", {
        status: 200,
        headers: { "content-type": "text/html" }
      });
    }
    return new Response("not found", { status: 404 });
  };

  const findings = await checkDebugSchemas("https://demo.example", new ScanBudget(3), {
    fetchImpl,
    resolveHostname: publicResolver
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].reasonCode, "public_graphql_schema");
});

test("Firebase config detector routes to rules self-check without storing config values", () => {
  const apiKey = "AIzaSy123456789012345678901234567890123";
  const findings = checkFirebaseConfig([
    {
      url: "https://demo.example/app.js",
      type: "script",
      body: `
        import { initializeApp } from "firebase/app";
        initializeApp({
          apiKey: "${apiKey}",
          authDomain: "demo.firebaseapp.com",
          projectId: "demo-private-project",
          storageBucket: "demo-private-project.appspot.com"
        });
      `,
      truncated: false
    }
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, "firebase_config");
  assert.equal(findings[0].runbookCode, "FIREBASE_RULES_SELF_CHECK");
  assert.equal(classifyReport({ status: "complete", findings }).state, "fixable");
  assert.ok(!JSON.stringify(findings).includes(apiKey));
  assert.ok(!JSON.stringify(findings).includes("demo-private-project"));
});

test("source map checker continues past inaccessible earlier map references", async () => {
  const assets = Array.from({ length: 5 }, (_, index) => ({
    url: `https://demo.example/chunk-${index}.js`,
    type: "script" as const,
    body: `console.log(${index});\n//# sourceMappingURL=chunk-${index}.js.map`,
    truncated: false
  }));
  assets.push({
    url: "https://demo.example/app.js",
    type: "script",
    body: "console.log('app');\n//# sourceMappingURL=/api/source-map",
    truncated: false
  });

  const fetchImpl: typeof fetch = async (input) => {
    const url = input.toString();
    if (url.endsWith("/api/source-map")) {
      return new Response(JSON.stringify({ version: 3, sources: ["app.ts"], mappings: "" }), {
        status: 200
      });
    }

    return new Response("not found", { status: 404 });
  };

  const findings = await checkSourceMaps(assets, new ScanBudget(8), {
    fetchImpl,
    resolveHostname: publicResolver
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].reasonCode, "public_source_map_confirmed");
  assert.ok(!JSON.stringify(findings).includes("app.ts"));
});

test("hostile evidence strings are escaped for report rendering", () => {
  const escaped = escapeEvidence(xssAsset.body);
  assert.ok(!escaped.includes("<script>"));
  assert.ok(escaped.includes("&lt;script&gt;"));
});

test("Supabase protected fixture produces no anonymous-read finding", async () => {
  const { calls, fetchImpl } = supabaseProtectedFetch();
  const findings = await checkSupabaseExposure(supabaseContext, new ScanBudget(5), {
    fetchImpl,
    resolveHostname: publicResolver
  });

  assert.equal(findings.length, 0);
  assert.ok(calls.every((call) => !call.url.includes("select=*") || call.method === "HEAD"));
});

test("Supabase readable fixture uses HEAD probes and reports anonymous read precisely", async () => {
  const { calls, fetchImpl } = supabaseReadableFetch();
  const findings = await checkSupabaseExposure(supabaseContext, new ScanBudget(5), {
    fetchImpl,
    resolveHostname: publicResolver
  });

  const readFinding = findings.find(
    (finding) => finding.reasonCode === "supabase_anon_read_probe_allowed"
  );
  assert.ok(readFinding);
  assert.equal(readFinding.severity, "critical");
  assert.equal(readFinding.tier, "critical");
  assert.equal(readFinding.rlsInference, "confirmed_open");
  assert.equal(readFinding.runbookCode, "RLS_LOCKDOWN_INCIDENT");
  assert.equal(readFinding.confidence, "confirmed");
  assert.match(readFinding.title, /Anonymous read probe allowed/);
  assert.ok(calls.every((call) => !call.url.includes("select=*") || call.method === "HEAD"));
  assert.ok(!JSON.stringify(findings).includes("secret-row@example.com"));
});

test("Supabase non-sensitive anonymous read stays fixable high review", async () => {
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = input.toString();
    const method = init?.method ?? "GET";
    if (url.endsWith("/rest/v1/")) {
      return new Response(JSON.stringify({ paths: { "/todos": {} } }), { status: 200 });
    }
    if (url.includes("/rest/v1/todos") && method === "HEAD") {
      return new Response(null, { status: 200, headers: { "content-range": "0-0/1" } });
    }
    return new Response(null, { status: 401 });
  };
  const findings = await checkSupabaseExposure(supabaseContext, new ScanBudget(5), {
    fetchImpl,
    resolveHostname: publicResolver
  });
  const readFinding = findings.find((finding) => finding.reasonCode === "supabase_anon_read_probe_allowed");

  assert.ok(readFinding);
  assert.equal(readFinding.severity, "high");
  assert.equal(readFinding.tier, "public_by_design");
  assert.equal(readFinding.runbookCode, "RLS_SELF_CHECK");
  assert.equal(classifyReport({ status: "complete", findings }).state, "fixable");
});

test("Supabase unverifiable anon key self-check stays fixable", () => {
  const finding = supabaseAnonSelfCheckFinding(supabaseContext);

  assert.ok(finding);
  assert.equal(finding.severity, "medium");
  assert.equal(finding.runbookCode, "RLS_SELF_CHECK");
  assert.equal(classifyReport({ status: "complete", findings: [finding] }).state, "fixable");
});
