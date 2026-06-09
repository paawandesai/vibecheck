import assert from "node:assert/strict";
import test from "node:test";
import { analyzeSecrets } from "@/lib/scanner/secrets";
import { checkSupabaseExposure } from "@/lib/scanner/supabase";
import { escapeEvidence } from "@/lib/scanner/redaction";
import { ScanBudget } from "@/lib/scanner/safeFetch";
import { findSourceMapReferences } from "@/lib/scanner/sourceMaps";
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
  assert.equal(result.findings.length, 2);
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
  assert.equal(readFinding.confidence, "confirmed");
  assert.match(readFinding.title, /Anonymous read appears possible/);
  assert.ok(calls.every((call) => !call.url.includes("select=*") || call.method === "HEAD"));
  assert.ok(!JSON.stringify(findings).includes("secret-row@example.com"));
});
