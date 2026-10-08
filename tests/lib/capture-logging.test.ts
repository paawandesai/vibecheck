import assert from "node:assert/strict";
import test from "node:test";
import { POST as eventsPost } from "@/app/api/events/route";
import { POST as scanPost } from "@/app/api/scan/route";
import {
  getAggregateSnapshot,
  getInMemoryScanRunsForTesting,
  recordScanRun
} from "@/lib/store/reportStore";
import { isSupabaseStoreConfigured, scanRunToSupabaseRow } from "@/lib/store/supabaseStore";
import type { ScanRunLog } from "@/lib/types";

function scanRun(overrides: Partial<ScanRunLog> = {}): ScanRunLog {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    targetOrigin: "https://example.com",
    targetUrlRedacted: "https://example.com/",
    status: "completed",
    reportId: "00000000-0000-4000-8000-000000000000",
    requesterFingerprint: "requester-fingerprint",
    authorizedSupabaseProbe: false,
    grade: "A",
    score: 98,
    findingCount: 0,
    highestSeverity: "none",
    requestCount: 4,
    checksRun: ["security_headers"],
    createdAt: "2026-06-26T00:00:00.000Z",
    completedAt: "2026-06-26T00:00:01.000Z",
    ...overrides
  };
}

function scanRequest(body: unknown) {
  return new Request("http://localhost/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "capture-test" },
    body: typeof body === "string" ? body : JSON.stringify(body)
  });
}

function eventRequest(body: unknown) {
  return new Request("http://localhost/api/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

test("scan-run Supabase row preserves terminal metadata without raw content", () => {
  const row = scanRunToSupabaseRow(
    scanRun({
      status: "failed",
      reportId: undefined,
      errorMessage: "DNS lookup failed",
      grade: undefined,
      score: undefined,
      findingCount: undefined,
      highestSeverity: undefined,
      requestCount: undefined,
      checksRun: []
    })
  );

  assert.deepEqual(row, {
    id: "00000000-0000-4000-8000-000000000001",
    target_origin: "https://example.com",
    target_url_redacted: "https://example.com/",
    status: "failed",
    report_id: null,
    requester_fingerprint: "requester-fingerprint",
    authorized_supabase_probe: false,
    error_message: "DNS lookup failed",
    grade: null,
    score: null,
    finding_count: null,
    highest_severity: null,
    request_count: null,
    checks_run: [],
    created_at: "2026-06-26T00:00:00.000Z",
    completed_at: "2026-06-26T00:00:01.000Z"
  });
});

test(
  "scan runs record to the in-memory fallback when Supabase is not configured",
  { skip: isSupabaseStoreConfigured() },
  async () => {
    const before = getAggregateSnapshot().scanRunCount;
    await recordScanRun(scanRun({ id: "00000000-0000-4000-8000-000000000002" }));
    const runs = getInMemoryScanRunsForTesting();

    assert.equal(getAggregateSnapshot().scanRunCount, before + 1);
    assert.equal(runs.at(-1)?.id, "00000000-0000-4000-8000-000000000002");
    assert.equal(runs.at(-1)?.status, "completed");
  }
);

test(
  "scan route records invalid URL attempts as terminal scan runs",
  { skip: isSupabaseStoreConfigured() },
  async () => {
    const before = getInMemoryScanRunsForTesting().length;
    const response = await scanPost(scanRequest({ url: "ftp://example.com" }));
    const body = (await response.json()) as { error?: string };
    const runs = getInMemoryScanRunsForTesting();
    const latest = runs.at(-1);

    assert.equal(response.status, 400);
    assert.match(body.error ?? "", /Only http and https/);
    assert.equal(runs.length, before + 1);
    assert.equal(latest?.status, "invalid_url");
    assert.equal(latest?.targetOrigin, undefined);
    assert.equal(latest?.checksRun.length, 0);
  }
);

test(
  "scan route records production rate-limit denials as terminal scan runs",
  { skip: isSupabaseStoreConfigured() },
  async () => {
    const previousNodeEnv = process.env.NODE_ENV;
    (process.env as Record<string, string | undefined>).NODE_ENV = "production";
    try {
      const before = getInMemoryScanRunsForTesting().length;
      const response = await scanPost(scanRequest({ url: "https://example.com" }));
      const body = (await response.json()) as { error?: string };
      const runs = getInMemoryScanRunsForTesting();
      const latest = runs.at(-1);

      assert.equal(response.status, 503);
      assert.match(body.error ?? "", /Production rate limiting requires Supabase storage/);
      assert.equal(runs.length, before + 1);
      assert.equal(latest?.status, "rate_limited");
      assert.equal(latest?.targetOrigin, "https://example.com");
      assert.equal(latest?.targetUrlRedacted, "https://example.com/");
    } finally {
      (process.env as Record<string, string | undefined>).NODE_ENV = previousNodeEnv;
    }
  }
);

test(
  "events route accepts founding-member click capture",
  { skip: isSupabaseStoreConfigured() },
  async () => {
    const response = await eventsPost(
      eventRequest({
        name: "founding_member_clicked",
        reportId: "00000000-0000-4000-8000-000000000000"
      })
    );
    const body = (await response.json()) as { ok?: boolean };

    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
  }
);
