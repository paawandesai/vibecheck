// Throwaway self-test runner: scans the owned VibeCheck test targets and prints a
// pass/fail table. Usage: npx tsx --env-file=.env.local scripts/scan-targets.ts [urls-file]
import { readFileSync } from "node:fs";
import { runScan } from "@/lib/scanner/runScan";

const DEFAULT_URLS_FILE =
  "/Users/paawandesai/Documents/Personal/vibecheck_test_targets/deployed_urls.txt";

type Expect = { label: string; ok: (types: Set<string>, reasons: Set<string>) => boolean };

const EXPECTED: Record<string, Expect> = {
  "leaked-key-demo": {
    label: "secrets -> client_secret",
    ok: (types) => types.has("client_secret")
  },
  "sourcemap-demo": {
    label: "source maps -> source_map",
    ok: (types) => types.has("source_map")
  },
  "open-rls-demo": {
    label: "RLS exposure -> supabase_rls",
    ok: (types) => types.has("supabase_rls")
  },
  "exposed-infra-demo": {
    label: ".env/.git -> exposed_env_file or exposed_git_directory",
    ok: (_types, reasons) =>
      reasons.has("exposed_env_file") || reasons.has("exposed_git_directory")
  }
};

const urlsFile = process.argv[2] ?? DEFAULT_URLS_FILE;

async function main() {
  const targets = readFileSync(urlsFile, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [app, url] = line.trim().split(/\s+/);
      return { app, url };
    });

  const rows: Array<{ app: string; expected: string; actual: string; pass: boolean }> = [];

  for (const { app, url } of targets) {
    const expect = EXPECTED[app];
    process.stderr.write(`\n=== Scanning ${app} (${url}) ===\n`);
    try {
      const report = await runScan({
        targetUrl: url,
        authorizedSupabaseProbe: true,
        requester: { ip: null, userAgent: "vibecheck-selftest" }
      });
      const types = new Set(report.findings.map((f) => f.type));
      const reasons = new Set(report.findings.map((f) => f.reasonCode));
      for (const f of report.findings) {
        process.stderr.write(`  - ${f.type} / ${f.reasonCode} / ${f.severity}\n`);
      }
      if (report.findings.length === 0) process.stderr.write("  (no findings)\n");
      const actual =
        report.findings.map((f) => `${f.type}:${f.reasonCode}`).join("; ") || "(none)";
      rows.push({
        app,
        expected: expect?.label ?? "(unmapped)",
        actual,
        pass: expect ? expect.ok(types, reasons) : false
      });
    } catch (err) {
      process.stderr.write(`  ERROR: ${(err as Error).message}\n`);
      rows.push({
        app,
        expected: expect?.label ?? "(unmapped)",
        actual: `ERROR: ${(err as Error).message}`,
        pass: false
      });
    }
  }

  console.log("\n| app | expected finding | actual finding | pass/fail |");
  console.log("| --- | --- | --- | --- |");
  for (const r of rows) {
    console.log(`| ${r.app} | ${r.expected} | ${r.actual} | ${r.pass ? "PASS" : "FAIL"} |`);
  }
}

void main();
