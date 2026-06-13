import type { Finding } from "@/lib/types";
import { safeFetch, type SafeFetchOptions, type ScanBudget } from "@/lib/scanner/safeFetch";
import { escapeEvidence } from "@/lib/scanner/redaction";
import { fixPromptsFor } from "@/lib/scanner/fixPrompts";

const INFRA_PATHS = ["/.env", "/.env.local", "/.git/config"];

function exposedPathEvidence(targetUrl: string) {
  return [
    {
      label: "Exposed path",
      value: escapeEvidence(targetUrl)
    }
  ];
}

export async function checkInfrastructure(
  targetOrigin: string,
  budget: ScanBudget,
  safeFetchOptions: Pick<SafeFetchOptions, "fetchImpl" | "resolveHostname"> = {}
): Promise<Finding[]> {
  const findings: Finding[] = [];
  let foundEnvExposure = false;

  for (const path of INFRA_PATHS) {
    try {
      const targetUrl = new URL(path, targetOrigin).toString();
      const res = await safeFetch(targetUrl, budget, { ...safeFetchOptions });

      if (res.status >= 300 && res.status < 400) continue;
      if (!res.ok) continue;

      const body = res.text;
      if (
        !foundEnvExposure &&
        path.includes(".env") &&
        body.includes("=") &&
        !body.trim().startsWith("<")
      ) {
        foundEnvExposure = true;
        findings.push({
          id: `infra_env_exposure_${Buffer.from(path).toString("base64url")}`,
          type: "client_secret",
          title: `Exposed environment file detected at ${path}`,
          severity: "critical",
          confidence: "confirmed",
          reasonCode: "exposed_env_file",
          summary: "A publicly accessible .env file was found at the web root.",
          explanation:
            "Environment files often contain server-side secrets. Exposing them to the public internet can compromise backend infrastructure.",
          limitation:
            "VibeCheck only verified the presence and shape of the file. It did not store the contents.",
          evidence: exposedPathEvidence(targetUrl),
          fixPrompts: fixPromptsFor("client_secret")
        });
      }

      if (path.includes(".git/config") && body.includes("[core]") && !body.trim().startsWith("<")) {
        findings.push({
          id: `infra_git_exposure_${Buffer.from(path).toString("base64url")}`,
          type: "client_secret",
          title: "Exposed .git directory detected",
          severity: "critical",
          confidence: "confirmed",
          reasonCode: "exposed_git_directory",
          summary: "A publicly accessible .git/config file was found.",
          explanation:
            "An exposed .git directory can let attackers recover source code history, including hardcoded secrets in past commits.",
          limitation:
            "VibeCheck only verified the presence of the config file. It did not download the repository.",
          evidence: exposedPathEvidence(targetUrl),
          fixPrompts: fixPromptsFor("client_secret")
        });
      }
    } catch {
      continue;
    }
  }

  return findings;
}
