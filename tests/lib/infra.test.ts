import assert from "node:assert/strict";
import test from "node:test";
import { checkInfrastructure } from "@/lib/scanner/infra";
import { ScanBudget } from "@/lib/scanner/safeFetch";
import { publicResolver } from "../fixtures/supabaseTargets";
import {
  infraCleanFetch,
  infraExpandedFetch,
  infraExposedFetch,
  infraSoft404Fetch
} from "../fixtures/infraTargets";

const ORIGIN = "https://example.com";

function opts(fetchImpl: typeof fetch) {
  return { fetchImpl, resolveHostname: publicResolver };
}

test("exposed .env and .git/config produce confirmed critical findings", async () => {
  const { calls, fetchImpl } = infraExposedFetch();
  const findings = await checkInfrastructure(ORIGIN, new ScanBudget(12), opts(fetchImpl));

  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.reasonCode).sort(),
    ["exposed_env_file", "exposed_git_directory"]
  );
  assert.ok(findings.every((finding) => finding.severity === "critical"));
  assert.ok(findings.every((finding) => finding.confidence === "confirmed"));
  assert.ok(calls.every((call) => call.method === "GET"));
});

test("only one environment exposure finding is reported per origin", async () => {
  const { fetchImpl } = infraExposedFetch();
  const findings = await checkInfrastructure(ORIGIN, new ScanBudget(12), opts(fetchImpl));
  assert.equal(findings.filter((finding) => finding.reasonCode === "exposed_env_file").length, 1);
});

test("expanded infra probes detect source-control and deployment metadata", async () => {
  const { calls, fetchImpl } = infraExpandedFetch();
  const findings = await checkInfrastructure(ORIGIN, new ScanBudget(12), opts(fetchImpl));

  assert.equal(calls.length, 12);
  assert.ok(calls.every((call) => call.method === "GET"));
  assert.deepEqual(
    findings.map((finding) => finding.reasonCode).sort(),
    [
      "exposed_config_file",
      "exposed_config_file",
      "exposed_config_file",
      "exposed_config_file",
      "exposed_ds_store",
      "exposed_git_directory",
      "exposed_svn_metadata"
    ]
  );
  assert.ok(
    findings.some(
      (finding) => finding.reasonCode === "exposed_git_directory" && finding.severity === "critical"
    )
  );
  assert.ok(
    findings.some(
      (finding) => finding.reasonCode === "exposed_svn_metadata" && finding.severity === "high"
    )
  );
  assert.ok(
    findings.some(
      (finding) => finding.reasonCode === "exposed_config_file" && finding.severity === "medium"
    )
  );
});

test("clean target with only 404s produces no findings", async () => {
  const { fetchImpl } = infraCleanFetch();
  const findings = await checkInfrastructure(ORIGIN, new ScanBudget(12), opts(fetchImpl));
  assert.equal(findings.length, 0);
});

test("soft-404 HTML pages do not trigger infra findings", async () => {
  const { fetchImpl } = infraSoft404Fetch();
  const findings = await checkInfrastructure(ORIGIN, new ScanBudget(12), opts(fetchImpl));
  assert.equal(findings.length, 0);
});

test("findings record only the path, never the response body", async () => {
  const { fetchImpl } = infraExposedFetch();
  const findings = await checkInfrastructure(ORIGIN, new ScanBudget(12), opts(fetchImpl));

  const serialized = JSON.stringify(findings);
  assert.ok(!serialized.includes("STRIPE_SECRET_KEY"));
  assert.ok(!serialized.includes("repositoryformatversion"));
});

test("expanded infra findings do not store exposed file contents", async () => {
  const { fetchImpl } = infraExpandedFetch();
  const findings = await checkInfrastructure(ORIGIN, new ScanBudget(12), opts(fetchImpl));

  const serialized = JSON.stringify(findings);
  assert.ok(!serialized.includes("refs/heads/main"));
  assert.ok(!serialized.includes("DS_STORE_BINARY_SHAPE_PLACEHOLDER"));
  assert.ok(!serialized.includes('"rewrites"'));
  assert.ok(!serialized.includes("[build]"));
});
