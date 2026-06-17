import { existsSync, readFileSync } from "node:fs";

const DEFAULT_APP_URL = "https://vibecheck-pi-blue.vercel.app";
const DEFAULT_TARGETS_FILE =
  "/Users/paawandesai/Documents/Personal/vibecheck_test_targets/deployed_urls.txt";

type SmokeRow = {
  step: string;
  result: "PASS" | "FAIL" | "SKIP";
  detail: string;
};

type Finding = {
  type: string;
  severity: string;
  reasonCode: string;
};

type ScanReport = {
  id: string;
  state: string;
  grade: string;
  score: number;
  targetOrigin: string;
  findings: Finding[];
};

type ScanResponse = {
  reportId: string;
  reportUrl: string;
  absoluteReportUrl?: string;
  report: ScanReport;
};

type RecallSpec = {
  detector: string;
  envName: string;
  fixtureLabel: string;
  findingType: string;
  expectedState?: string;
};

const appUrl = normalizeBaseUrl(process.env.VIBECHECK_APP_URL || DEFAULT_APP_URL);

const recallSpecs: RecallSpec[] = [
  {
    detector: "client_data_exposure",
    envName: "OWNED_CLIENT_DATA_TARGET",
    fixtureLabel: "client-data-demo",
    findingType: "client_data_exposure"
  },
  {
    detector: "firebase_config",
    envName: "OWNED_FIREBASE_TARGET",
    fixtureLabel: "firebase-demo",
    findingType: "firebase_config",
    expectedState: "fixable"
  },
  {
    detector: "debug_schema_surface",
    envName: "OWNED_DEBUG_SCHEMA_TARGET",
    fixtureLabel: "debug-schema-demo",
    findingType: "debug_schema",
    expectedState: "fixable"
  }
];

function normalizeBaseUrl(value: string) {
  const url = new URL(value);
  return url.origin;
}

function targetMap() {
  if (!existsSync(DEFAULT_TARGETS_FILE)) return new Map<string, string>();
  return new Map(
    readFileSync(DEFAULT_TARGETS_FILE, "utf8")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [label, url] = line.split(/\s+/);
        return [label, url] as const;
      })
  );
}

function defaultScanTarget() {
  const targets = targetMap();
  return (
    process.env.SMOKE_SCAN_TARGET ||
    targets.get("leaked-key-demo") ||
    "https://leaked-key-demo.vercel.app"
  );
}

function recallTarget(spec: RecallSpec) {
  return process.env[spec.envName] || targetMap().get(spec.fixtureLabel) || "";
}

function endpoint(path: string) {
  return new URL(path, appUrl).toString();
}

function cleanCell(value: string) {
  return value.replaceAll("|", "\\|").replace(/\s+/g, " ").trim();
}

function printTable(headers: string[], rows: string[][]) {
  console.log(`| ${headers.join(" | ")} |`);
  console.log(`| ${headers.map(() => "---").join(" | ")} |`);
  for (const row of rows) {
    console.log(`| ${row.map(cleanCell).join(" | ")} |`);
  }
}

async function readJson(response: Response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { text };
  }
}

async function postScan(targetUrl: string) {
  const response = await fetch(endpoint("/api/scan"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: targetUrl, authorizedSupabaseProbe: false })
  });
  const body = await readJson(response);
  return { response, body };
}

function scanBody(body: Record<string, unknown>) {
  return body as unknown as ScanResponse;
}

async function main() {
  const smokeRows: SmokeRow[] = [];
  let failed = false;
  let scanResult: ScanResponse | null = null;

  try {
    const response = await fetch(appUrl);
    const body = await response.text();
    const ok = response.ok && body.includes("VibeCheck");
    smokeRows.push({
      step: "homepage loads",
      result: ok ? "PASS" : "FAIL",
      detail: `${response.status} ${ok ? "VibeCheck copy found" : "expected homepage copy missing"}`
    });
    failed ||= !ok;
  } catch (error) {
    smokeRows.push({
      step: "homepage loads",
      result: "FAIL",
      detail: error instanceof Error ? error.message : String(error)
    });
    failed = true;
  }

  for (const blockedTarget of ["http://localhost:3000", "http://192.168.0.1"]) {
    try {
      const { response, body } = await postScan(blockedTarget);
      const message = typeof body.error === "string" ? body.error : "";
      const ok = response.status === 400 && /blocked|unsafe|localhost|private/i.test(message);
      smokeRows.push({
        step: `${blockedTarget} blocked`,
        result: ok ? "PASS" : "FAIL",
        detail: `${response.status} ${message || "no error message"}`
      });
      failed ||= !ok;
    } catch (error) {
      smokeRows.push({
        step: `${blockedTarget} blocked`,
        result: "FAIL",
        detail: error instanceof Error ? error.message : String(error)
      });
      failed = true;
    }
  }

  const ownedTarget = defaultScanTarget();
  try {
    const { response, body } = await postScan(ownedTarget);
    const typed = scanBody(body);
    const ok = response.ok && Boolean(typed.reportId) && Boolean(typed.report);
    if (ok) scanResult = typed;
    smokeRows.push({
      step: "owned demo scan returns report",
      result: ok ? "PASS" : "FAIL",
      detail: ok
        ? `${ownedTarget} -> ${typed.report.state} ${typed.report.grade}/${typed.report.score} (${typed.report.findings.length} findings)`
        : `${response.status} ${typeof body.error === "string" ? body.error : "missing report"}`
    });
    failed ||= !ok;
  } catch (error) {
    smokeRows.push({
      step: "owned demo scan returns report",
      result: "FAIL",
      detail: error instanceof Error ? error.message : String(error)
    });
    failed = true;
  }

  if (scanResult) {
    const reportUrl =
      scanResult.absoluteReportUrl || new URL(scanResult.reportUrl, appUrl).toString();
    try {
      const response = await fetch(reportUrl);
      const body = await response.text();
      const ok =
        response.ok &&
        body.includes("Scanned with VibeCheck") &&
        body.includes(scanResult.report.targetOrigin);
      smokeRows.push({
        step: "report/share page renders",
        result: ok ? "PASS" : "FAIL",
        detail: `${response.status} ${reportUrl}`
      });
      failed ||= !ok;
    } catch (error) {
      smokeRows.push({
        step: "report/share page renders",
        result: "FAIL",
        detail: error instanceof Error ? error.message : String(error)
      });
      failed = true;
    }

    try {
      const email = `submission-smoke+${Date.now()}@example.com`;
      const response = await fetch(endpoint("/api/waitlist"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, reportId: scanResult.reportId })
      });
      const body = await readJson(response);
      const ok = response.ok && body.ok === true;
      smokeRows.push({
        step: "waitlist submit persists",
        result: ok ? "PASS" : "FAIL",
        detail: ok ? `${email} accepted` : `${response.status} ${JSON.stringify(body)}`
      });
      failed ||= !ok;
    } catch (error) {
      smokeRows.push({
        step: "waitlist submit persists",
        result: "FAIL",
        detail: error instanceof Error ? error.message : String(error)
      });
      failed = true;
    }
  } else {
    smokeRows.push({
      step: "report/share page renders",
      result: "SKIP",
      detail: "owned scan did not return a report"
    });
    smokeRows.push({
      step: "waitlist submit persists",
      result: "SKIP",
      detail: "owned scan did not return a report id"
    });
  }

  const recallRows: string[][] = [];
  for (const spec of recallSpecs) {
    const target = recallTarget(spec);
    if (!target) {
      recallRows.push([
        spec.detector,
        `set ${spec.envName}`,
        "SKIP",
        "not run",
        "no planted owned target configured"
      ]);
      continue;
    }

    try {
      const { response, body } = await postScan(target);
      const typed = scanBody(body);
      const detected = response.ok && typed.report.findings.some((finding) => finding.type === spec.findingType);
      const stateOk = !spec.expectedState || typed.report.state === spec.expectedState;
      const ok = detected && stateOk;
      recallRows.push([
        spec.detector,
        target,
        detected ? "yes" : "no",
        response.ok ? typed.report.state : "request failed",
        ok
          ? "PASS"
          : `${response.status} ${
              !detected ? `missing ${spec.findingType}` : `expected state ${spec.expectedState}`
            }`
      ]);
      failed ||= !ok;
    } catch (error) {
      recallRows.push([
        spec.detector,
        target,
        "no",
        "request failed",
        error instanceof Error ? error.message : String(error)
      ]);
      failed = true;
    }
  }

  console.log(`\nSubmission smoke target: ${appUrl}`);
  console.log(`Owned scan target: ${ownedTarget}\n`);
  printTable(
    ["step", "result", "detail"],
    smokeRows.map((row) => [row.step, row.result, row.detail])
  );

  console.log("\nDetector recall table");
  printTable(["detector", "owned target", "detected?", "state", "result"], recallRows);

  if (failed) {
    process.exitCode = 1;
  }
}

void main();
