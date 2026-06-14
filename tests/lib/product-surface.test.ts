import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import nextConfig from "@/next.config";
import { CHECK_BUDGETS } from "@/lib/scanner/checks";
import { consumeScanRateLimit } from "@/lib/store/rateLimitStore";
import { isSupabaseStoreConfigured } from "@/lib/store/supabaseStore";

test("marketing pages are indexable while reports and APIs send noindex headers", async () => {
  assert.ok(nextConfig.headers);
  const headers = await nextConfig.headers();
  const allRoutes = headers.find((entry) => entry.source === "/:path*");
  const reportRoutes = headers.find((entry) => entry.source === "/r/:path*");
  const apiRoutes = headers.find((entry) => entry.source === "/api/:path*");

  assert.ok(allRoutes);
  assert.ok(reportRoutes);
  assert.ok(apiRoutes);
  assert.ok(!allRoutes.headers.some((header) => header.key.toLowerCase() === "x-robots-tag"));
  assert.equal(
    reportRoutes.headers.find((header) => header.key.toLowerCase() === "x-robots-tag")?.value,
    "noindex, nofollow"
  );
  assert.equal(
    apiRoutes.headers.find((header) => header.key.toLowerCase() === "x-robots-tag")?.value,
    "noindex, nofollow"
  );
});

test("Stripe founding-member CTA is not rendered by the report component", () => {
  const source = readFileSync("components/ReportView.tsx", "utf8");
  assert.ok(!source.includes("Founding member"));
  assert.ok(!source.includes("stripeLink"));
});

test("deep checker request caps are explicit", () => {
  assert.equal(CHECK_BUDGETS.security_headers, 1);
  assert.equal(CHECK_BUDGETS.cors, 5);
  assert.equal(CHECK_BUDGETS.exposed_infrastructure, 12);
  assert.equal(CHECK_BUDGETS.public_api_surface, 8);
  assert.equal(CHECK_BUDGETS.supabase_rls_authorized_probe, 5);
});

test(
  "production rate limiting fails closed without Supabase storage",
  { skip: isSupabaseStoreConfigured() },
  async () => {
    const previousNodeEnv = process.env.NODE_ENV;
    (process.env as Record<string, string | undefined>).NODE_ENV = "production";
    try {
      const result = await consumeScanRateLimit({
        requesterFingerprint: `prod-test-${Date.now()}`,
        targetOrigin: "https://example.com"
      });
      assert.equal(result.allowed, false);
      assert.match(result.reason ?? "", /requires Supabase/);
    } finally {
      (process.env as Record<string, string | undefined>).NODE_ENV = previousNodeEnv;
    }
  }
);
