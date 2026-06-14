import type { Finding } from "@/lib/types";
import { safeFetch, type SafeFetchOptions, type ScanBudget } from "@/lib/scanner/safeFetch";
import { escapeEvidence } from "@/lib/scanner/redaction";
import { fixPromptsFor } from "@/lib/scanner/fixPrompts";

const INFRA_PATHS = [
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.env.development",
  "/.git/config",
  "/.git/HEAD",
  "/.svn/entries",
  "/.DS_Store",
  "/config.json",
  "/firebase.json",
  "/vercel.json",
  "/netlify.toml"
];

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
          type: "exposed_infrastructure",
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
          fixPrompts: fixPromptsFor("exposed_infrastructure")
        });
      }

      if (path.includes(".git/config") && body.includes("[core]") && !body.trim().startsWith("<")) {
        findings.push({
          id: `infra_git_exposure_${Buffer.from(path).toString("base64url")}`,
          type: "exposed_infrastructure",
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
          fixPrompts: fixPromptsFor("exposed_infrastructure")
        });
      }
      if (path.endsWith("/.git/HEAD") && body.includes("ref: refs/") && !body.trim().startsWith("<")) {
        findings.push({
          id: `infra_git_head_exposure_${Buffer.from(path).toString("base64url")}`,
          type: "exposed_infrastructure",
          title: "Exposed .git metadata detected",
          severity: "critical",
          confidence: "confirmed",
          reasonCode: "exposed_git_directory",
          summary: "A publicly accessible .git/HEAD file was found.",
          explanation:
            "Exposed .git metadata can indicate that source control internals are publicly reachable.",
          limitation:
            "VibeCheck only verified the presence of metadata. It did not download repository contents.",
          evidence: exposedPathEvidence(targetUrl),
          fixPrompts: fixPromptsFor("exposed_infrastructure")
        });
      }
      if (path.includes(".svn") && body.includes("dir") && !body.trim().startsWith("<")) {
        findings.push({
          id: `infra_svn_exposure_${Buffer.from(path).toString("base64url")}`,
          type: "exposed_infrastructure",
          title: "Exposed SVN metadata detected",
          severity: "high",
          confidence: "confirmed",
          reasonCode: "exposed_svn_metadata",
          summary: "A publicly accessible SVN metadata file was found.",
          explanation:
            "Source control metadata can reveal repository structure and historical implementation details.",
          limitation: "VibeCheck verified only the metadata path and shape.",
          evidence: exposedPathEvidence(targetUrl),
          fixPrompts: fixPromptsFor("exposed_infrastructure")
        });
      }
      if (path === "/.DS_Store" && body.length > 20 && !body.trim().startsWith("<")) {
        findings.push({
          id: "infra_ds_store_exposure",
          type: "exposed_infrastructure",
          title: "Exposed .DS_Store file detected",
          severity: "medium",
          confidence: "likely",
          reasonCode: "exposed_ds_store",
          summary: "A publicly accessible .DS_Store file was found.",
          explanation:
            "Directory metadata can reveal file names and deployment structure that should not be public.",
          limitation: "VibeCheck did not store the file contents.",
          evidence: exposedPathEvidence(targetUrl),
          fixPrompts: fixPromptsFor("exposed_infrastructure")
        });
      }
      if (
        ["/config.json", "/firebase.json", "/vercel.json", "/netlify.toml"].includes(path) &&
        (body.includes("{") || body.includes("[build]")) &&
        !body.trim().startsWith("<")
      ) {
        findings.push({
          id: `infra_config_exposure_${Buffer.from(path).toString("base64url")}`,
          type: "exposed_infrastructure",
          title: `Public deployment/config file detected at ${path}`,
          severity: "medium",
          confidence: "likely",
          reasonCode: "exposed_config_file",
          summary: "A deployment or configuration file appears publicly accessible.",
          explanation:
            "Public config files can reveal project structure, routes, functions, or deployment details that help attackers target the app.",
          limitation: "VibeCheck stored only the path and shape metadata, not the file body.",
          evidence: exposedPathEvidence(targetUrl),
          fixPrompts: fixPromptsFor("exposed_infrastructure")
        });
      }
    } catch (err) {
      if ((err as Error).message.includes("budget exceeded")) throw err;
      continue;
    }
  }

  return findings;
}
