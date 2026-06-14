import type { Finding, PublicAsset } from "@/lib/types";
import { discoverReferencedApiPaths } from "@/lib/scanner/apiPaths";
import { fixPromptsFor } from "@/lib/scanner/fixPrompts";
import { escapeEvidence, fingerprint, safeUrlForStorage } from "@/lib/scanner/redaction";
import { safeFetch, type SafeFetchOptions, type ScanBudget } from "@/lib/scanner/safeFetch";

const SENSITIVE_KEY_PATTERNS = [
  /email/i,
  /token/i,
  /secret/i,
  /password/i,
  /role/i,
  /admin/i,
  /private/i,
  /session/i
];

function jsonShapeFlags(text: string) {
  try {
    const parsed = JSON.parse(text) as unknown;
    const sample = Array.isArray(parsed) ? parsed[0] : parsed;
    if (!sample || typeof sample !== "object") return null;
    const keys = Object.keys(sample as Record<string, unknown>);
    const sensitive = keys.some((key) => SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(key)));
    return {
      topLevelKeyCount: keys.length,
      hasSensitiveKeyShape: sensitive,
      isArray: Array.isArray(parsed)
    };
  } catch {
    return null;
  }
}

export async function checkPublicApiSurface(
  assets: PublicAsset[],
  targetOrigin: string,
  budget: ScanBudget,
  safeFetchOptions: Pick<SafeFetchOptions, "fetchImpl" | "resolveHostname"> = {}
) {
  const findings: Finding[] = [];
  const paths = discoverReferencedApiPaths(assets, targetOrigin, 8);

  for (const path of paths) {
    try {
      const res = await safeFetch(path, budget, {
        method: "GET",
        headers: {
          Accept: "application/json"
        },
        timeoutMs: 8000,
        maxBytes: 60_000,
        allowTruncate: true,
        ...safeFetchOptions
      });
      const contentType = res.headers.get("content-type") ?? "";
      if (!res.ok || !contentType.includes("json")) continue;
      const shape = jsonShapeFlags(res.text);
      if (!shape?.hasSensitiveKeyShape) continue;

      findings.push({
        id: `public_api_${fingerprint(path)}`,
        type: "public_api",
        title: "Referenced API route returns sensitive-looking JSON anonymously",
        severity: "medium",
        confidence: "likely",
        reasonCode: "anonymous_public_api_sensitive_shape",
        summary: "A same-origin API route referenced by the app returned JSON with private-looking fields.",
        explanation:
          "API routes used by frontend apps can still require authorization or server-side filtering before returning user, token, role, or private fields.",
        limitation:
          "VibeCheck stored only endpoint metadata and shape flags. It did not store the API response body.",
        evidence: [
          {
            label: "Endpoint",
            value: escapeEvidence(safeUrlForStorage(res.url)),
            fingerprint: fingerprint(path),
            metadata: {
              status: res.status,
              contentType,
              topLevelKeyCount: shape.topLevelKeyCount,
              isArray: shape.isArray
            }
          }
        ],
        fixPrompts: fixPromptsFor("public_api")
      });
    } catch (err) {
      if ((err as Error).message.includes("budget exceeded")) throw err;
      continue;
    }
  }

  return findings;
}
