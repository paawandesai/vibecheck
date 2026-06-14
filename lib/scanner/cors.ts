import type { Finding, PublicAsset } from "@/lib/types";
import { discoverReferencedApiPaths } from "@/lib/scanner/apiPaths";
import { createFinding } from "@/lib/report/findingModel";
import { escapeEvidence, fingerprint, safeUrlForStorage } from "@/lib/scanner/redaction";
import { safeFetch, type SafeFetchOptions, type ScanBudget } from "@/lib/scanner/safeFetch";

const PROBE_ORIGIN = "https://vibecheck.invalid";

export async function checkCorsExposure(
  assets: PublicAsset[],
  targetOrigin: string,
  budget: ScanBudget,
  safeFetchOptions: Pick<SafeFetchOptions, "fetchImpl" | "resolveHostname"> = {}
) {
  const findings: Finding[] = [];
  const paths = discoverReferencedApiPaths(assets, targetOrigin, 5);

  for (const path of paths) {
    try {
      const res = await safeFetch(path, budget, {
        method: "OPTIONS",
        headers: {
          Origin: PROBE_ORIGIN,
          "Access-Control-Request-Method": "GET"
        },
        timeoutMs: 7000,
        maxBytes: 0,
        ...safeFetchOptions
      });
      const allowOrigin = res.headers.get("access-control-allow-origin") ?? "";
      const allowCredentials = res.headers.get("access-control-allow-credentials") ?? "";
      const reflected = allowOrigin === PROBE_ORIGIN;
      const wildcard = allowOrigin === "*";
      const credentialed = allowCredentials.toLowerCase() === "true";
      if (!reflected && !wildcard) continue;

      findings.push(createFinding({
        id: `cors_${fingerprint(path)}`,
        type: "cors",
        title: credentialed ? "Credentialed permissive CORS detected" : "Permissive CORS detected",
        severity: credentialed ? "high" : "medium",
        confidence: "confirmed",
        reasonCode: credentialed ? "credentialed_permissive_cors" : "permissive_cors",
        tier: "unknown",
        location: "referenced_api",
        rlsInference: "not_applicable",
        runbookCode: "CORS_TIGHTEN",
        summary: "A referenced API endpoint accepts a hostile cross-origin browser request.",
        explanation:
          "Overly broad CORS can let attacker-controlled websites read API responses from users' browsers, especially when credentials are allowed.",
        limitation:
          "VibeCheck sent a bounded preflight request only. It did not submit data, brute force endpoints, or bypass authentication.",
        evidence: [
          {
            label: "Endpoint",
            value: escapeEvidence(safeUrlForStorage(path)),
            fingerprint: fingerprint(path),
            metadata: {
              allowOrigin,
              credentialed
            }
          }
        ]
      }));
    } catch (err) {
      if ((err as Error).message.includes("budget exceeded")) throw err;
      continue;
    }
  }

  return findings;
}
