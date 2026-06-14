import assert from "node:assert/strict";
import test from "node:test";
import { checkCorsExposure } from "@/lib/scanner/cors";
import { checkPublicApiSurface } from "@/lib/scanner/publicApi";
import { checkSecurityHeaders } from "@/lib/scanner/securityHeaders";
import { analyzeSecrets } from "@/lib/scanner/secrets";
import { checkSupabaseExposure } from "@/lib/scanner/supabase";
import { runScan } from "@/lib/scanner/runScan";
import { ScanBudget } from "@/lib/scanner/safeFetch";
import { scanConfig } from "@/lib/env";
import { consumeScanRateLimit } from "@/lib/store/rateLimitStore";
import { isUuid, normalizeEmail, normalizeOptionalReportId } from "@/lib/validation";
import { publicResolver, supabaseContext } from "../fixtures/supabaseTargets";

const ORIGIN = "https://example.com";

test("security header checker reports missing protections from header metadata", () => {
  const findings = checkSecurityHeaders(
    {
      url: ORIGIN,
      type: "html",
      body: "",
      truncated: false,
      headers: {}
    },
    ORIGIN
  );

  assert.ok(findings.some((finding) => finding.reasonCode === "missing_content_security_policy"));
  assert.ok(findings.some((finding) => finding.type === "security_header"));
});

test("CORS checker only probes referenced API paths and records header metadata", async () => {
  const calls: Array<{ url: string; method: string }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    calls.push({ url: input.toString(), method: init?.method ?? "GET" });
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "https://vibecheck.invalid",
        "access-control-allow-credentials": "true"
      }
    });
  };

  const findings = await checkCorsExposure(
    [
      {
        url: ORIGIN,
        type: "html",
        body: '<script>fetch("/api/profile")</script>',
        truncated: false
      }
    ],
    ORIGIN,
    new ScanBudget(5),
    { fetchImpl, resolveHostname: publicResolver }
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "OPTIONS");
  assert.equal(calls[0].url, `${ORIGIN}/api/profile`);
  assert.equal(findings[0].reasonCode, "credentialed_permissive_cors");
});

test("public API checker stores only endpoint and shape metadata", async () => {
  const fetchImpl: typeof fetch = async () =>
    new Response(JSON.stringify({ email: "secret@example.com", role: "admin" }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });

  const findings = await checkPublicApiSurface(
    [
      {
        url: ORIGIN,
        type: "script",
        body: 'fetch("/api/me")',
        truncated: false
      }
    ],
    ORIGIN,
    new ScanBudget(8),
    { fetchImpl, resolveHostname: publicResolver }
  );

  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, "public_api");
  assert.ok(!JSON.stringify(findings).includes("secret@example.com"));
});

test("secret expansion flags private keys but ignores public certificates", () => {
  const privateKey = `-----BEGIN PRIVATE KEY-----
abc123abc123abc123abc123abc123
-----END PRIVATE KEY-----`;
  const cert = `-----BEGIN CERTIFICATE-----
abc123abc123abc123abc123abc123
-----END CERTIFICATE-----`;
  const result = analyzeSecrets([
    {
      url: ORIGIN,
      type: "script",
      body: `${privateKey}\n${cert}`,
      truncated: false
    }
  ]);

  assert.ok(
    result.findings.some((finding) => finding.reasonCode === "private_key_block_in_client_bundle")
  );
  assert.ok(!result.findings.some((finding) => finding.reasonCode.includes("certificate")));
});

test("Supabase deep probe reports bucket listing without storing bucket names", async () => {
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = input.toString();
    if (url.endsWith("/rest/v1/")) return new Response(null, { status: 401 });
    if (init?.method === "HEAD") return new Response(null, { status: 401 });
    if (url.endsWith("/storage/v1/bucket")) {
      return new Response(JSON.stringify([{ id: "private-documents", name: "private-documents" }]), {
        status: 200
      });
    }
    return new Response(null, { status: 404 });
  };

  const findings = await checkSupabaseExposure(supabaseContext, new ScanBudget(5), {
    fetchImpl,
    resolveHostname: publicResolver
  });

  assert.ok(
    findings.some((finding) => finding.reasonCode === "supabase_storage_buckets_listable")
  );
  assert.ok(!JSON.stringify(findings).includes("private-documents"));
});

test("runScan records disabled and unknown checks", async () => {
  const previousDisabled = scanConfig.disabledChecks;
  const previousFetch = globalThis.fetch;
  scanConfig.disabledChecks = "security_headers,cors,unknown_check";
  globalThis.fetch = async () => new Response("<html><main>safe</main></html>", { status: 404 });

  try {
    const report = await runScan({
      targetUrl: ORIGIN,
      authorizedSupabaseProbe: false,
      requester: { ip: "203.0.113.9", userAgent: "test" }
    });
    assert.ok(report.scanner.checksDisabled.includes("security_headers"));
    assert.ok(report.scanner.checksDisabled.includes("cors"));
    assert.ok(report.scanner.unknownDisabledChecks.includes("unknown_check"));
    assert.equal(report.scanner.requestBudget, 35);
  } finally {
    scanConfig.disabledChecks = previousDisabled;
    globalThis.fetch = previousFetch;
  }
});

test("validation normalizes expected IDs and emails", () => {
  assert.equal(isUuid("00000000-0000-4000-8000-000000000000"), true);
  assert.equal(normalizeOptionalReportId("not-a-uuid").ok, false);
  assert.equal(normalizeEmail(" Person@Example.COM "), "person@example.com");
});

test("development rate limiter blocks the sixth hourly requester scan", async () => {
  const key = `test-${Date.now()}-${Math.random()}`;
  const targetOrigin = `https://target-${Date.now()}.example`;

  for (let index = 0; index < 5; index += 1) {
    const allowed = await consumeScanRateLimit({ requesterFingerprint: key, targetOrigin });
    assert.equal(allowed.allowed, true);
  }

  const blocked = await consumeScanRateLimit({ requesterFingerprint: key, targetOrigin });
  assert.equal(blocked.allowed, false);
  assert.match(blocked.reason ?? "", /requester_hour/);
  assert.equal(blocked.retryAfterSeconds, 3600);
});
