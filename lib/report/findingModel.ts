import type {
  Finding,
  FindingLocation,
  FindingTier,
  Remediation,
  RlsInference,
  RunbookCode
} from "@/lib/types";
import { fixPromptsFor } from "@/lib/scanner/fixPrompts";
import { remediationsFor } from "@/lib/report/remediations";

type FindingInit = Omit<Finding, "remediations" | "fixPrompts"> & {
  remediations?: Remediation[];
  fixPrompts?: Finding["fixPrompts"];
};

export function createFinding(init: FindingInit): Finding {
  const remediations = init.remediations ?? remediationsFor(init.runbookCode, init.type);
  if (!remediations.length) {
    throw new Error(`Finding ${init.reasonCode} is missing remediation data`);
  }
  for (const remediation of remediations) {
    if (!remediation.snippet.trim() || !remediation.targetLocation.trim() || !remediation.beginnerContext.trim()) {
      throw new Error(`Finding ${init.reasonCode} has incomplete remediation data`);
    }
  }

  return {
    ...init,
    remediations,
    fixPrompts: init.fixPrompts ?? fixPromptsFor(init.type)
  };
}

function evidenceMentionsLikelyPrivateSupabaseTable(finding: Partial<Pick<Finding, "evidence">>) {
  return finding.evidence?.some((item) => /\/rest\/v1\/(?:profiles|users)\?/.test(item.value)) ?? false;
}

export function defaultFindingClassification(
  finding: Pick<Finding, "type" | "reasonCode" | "severity"> & Partial<Pick<Finding, "evidence">>
): {
  tier: FindingTier;
  location: FindingLocation;
  rlsInference: RlsInference;
  runbookCode: RunbookCode;
} {
  if (finding.type === "client_secret") {
    return {
      tier: "critical",
      location: "client_bundle",
      rlsInference: "not_applicable",
      runbookCode: "INCIDENT_ROTATE"
    };
  }

  if (finding.reasonCode === "exposed_env_file") {
    return {
      tier: "critical",
      location: "public_web_path",
      rlsInference: "not_applicable",
      runbookCode: "INCIDENT_ROTATE"
    };
  }

  if (finding.reasonCode === "exposed_git_directory") {
    return {
      tier: "critical",
      location: "public_repo_head",
      rlsInference: "not_applicable",
      runbookCode: "INCIDENT_ROTATE"
    };
  }

  if (finding.type === "supabase_rls") {
    const anonRead = finding.reasonCode === "supabase_anon_read_probe_allowed";
    if (anonRead && evidenceMentionsLikelyPrivateSupabaseTable(finding)) {
      return {
        tier: "critical",
        location: "supabase_rest",
        rlsInference: "confirmed_open",
        runbookCode: "RLS_LOCKDOWN_INCIDENT"
      };
    }

    return {
      tier: "public_by_design",
      location:
        finding.reasonCode === "supabase_storage_buckets_listable"
          ? "supabase_storage"
          : "supabase_rest",
      rlsInference: anonRead ? "anon_read_possible" : "unverifiable",
      runbookCode: "RLS_SELF_CHECK"
    };
  }

  if (finding.type === "source_map") {
    return {
      tier: "unknown",
      location: "public_web_path",
      rlsInference: "not_applicable",
      runbookCode: "SOURCE_MAP_DISABLE"
    };
  }

  if (finding.type === "security_header") {
    return {
      tier: "unknown",
      location: "response_header",
      rlsInference: "not_applicable",
      runbookCode: "HEADER_HARDEN"
    };
  }

  if (finding.type === "cors") {
    return {
      tier: "unknown",
      location: "referenced_api",
      rlsInference: "not_applicable",
      runbookCode: "CORS_TIGHTEN"
    };
  }

  if (finding.type === "public_api") {
    return {
      tier: "unknown",
      location: "referenced_api",
      rlsInference: "not_applicable",
      runbookCode: "API_AUTH_REVIEW"
    };
  }

  if (finding.type === "exposed_infrastructure") {
    return {
      tier: "unknown",
      location: "public_web_path",
      rlsInference: "not_applicable",
      runbookCode: "INFRA_REMOVE"
    };
  }

  return {
    tier: "unknown",
    location: "unknown",
    rlsInference: "not_applicable",
    runbookCode: "MANUAL_TRIAGE"
  };
}

export function normalizeFindingForDisplay(finding: Finding): Finding {
  const defaults = defaultFindingClassification(finding);
  const runbookCode = finding.runbookCode ?? defaults.runbookCode;
  const remediations = finding.remediations?.length
    ? finding.remediations
    : remediationsFor(runbookCode, finding.type);

  return {
    ...finding,
    tier: finding.tier ?? defaults.tier,
    location: finding.location ?? defaults.location,
    rlsInference: finding.rlsInference ?? defaults.rlsInference,
    runbookCode,
    remediations,
    fixPrompts: finding.fixPrompts ?? fixPromptsFor(finding.type)
  };
}
