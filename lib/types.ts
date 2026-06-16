export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "confirmed" | "likely" | "informational" | "not_applicable";
export type FindingType =
  | "client_secret"
  | "source_map"
  | "supabase_rls"
  | "security_header"
  | "cors"
  | "exposed_infrastructure"
  | "public_api";
export type Builder = "lovable" | "bolt" | "cursor" | "replit" | "supabase";
export type ScanStatus = "complete" | "incomplete";
export type ReportState = "clean" | "fixable" | "incident" | "incomplete";
export type FindingTier = "critical" | "public_by_design" | "unknown" | "informational";
export type FindingLocation =
  | "client_bundle"
  | "public_web_path"
  | "referenced_api"
  | "response_header"
  | "supabase_rest"
  | "supabase_storage"
  | "public_repo_head"
  | "public_repo_history"
  | "private_repo"
  | "committed_env"
  | "unknown";
export type RlsInference =
  | "unverifiable"
  | "anon_read_possible"
  | "confirmed_open"
  | "not_applicable";
export type RunbookCode =
  | "INFO_ONLY"
  | "RLS_SELF_CHECK"
  | "RLS_LOCKDOWN_INCIDENT"
  | "INCIDENT_ROTATE"
  | "INCIDENT_ROTATE_HISTORICAL"
  | "MANUAL_TRIAGE"
  | "SOURCE_MAP_DISABLE"
  | "INFRA_REMOVE"
  | "HEADER_HARDEN"
  | "CORS_TIGHTEN"
  | "API_AUTH_REVIEW";

export interface Remediation {
  type: "code" | "shell" | "sql" | "config" | "dashboard_instruction";
  snippet: string;
  targetLocation: string;
  beginnerContext: string;
}

export type StackHost = "vercel" | "netlify" | "kilo" | "cloudflare_pages" | "github_pages" | "unknown";
export type StackFramework = "next" | "react" | "static" | "unknown";
export type StackBackend = "django" | "node" | "unknown";
export type StackConfidence = "confirmed" | "likely" | "unknown";

export interface StackProfile {
  host: StackHost;
  framework: StackFramework;
  backend: StackBackend;
  confidence: StackConfidence;
  signals: string[];
}

export interface EvidenceItem {
  label: string;
  value: string;
  fingerprint?: string;
  metadata?: Record<string, string | number | boolean | null>;
}

export interface Finding {
  id: string;
  type: FindingType;
  title: string;
  severity: Severity;
  confidence: Confidence;
  reasonCode: string;
  tier: FindingTier;
  location: FindingLocation;
  rlsInference: RlsInference;
  runbookCode: RunbookCode;
  summary: string;
  explanation: string;
  limitation: string;
  evidence: EvidenceItem[];
  remediations: Remediation[];
  fixPrompts?: Record<Builder, string>;
}

export interface AuthorizationArtifact {
  scanId: string;
  targetOrigin: string;
  timestamp: string;
  checkboxTextVersion: string;
  requesterFingerprint: string;
}

export interface ScannerMetadata {
  version: string;
  mode: "read_only";
  requestCount: number;
  requestBudget: number;
  checksRun: string[];
  checksSkipped: string[];
  checksDisabled: string[];
  unknownDisabledChecks: string[];
  checkerBudgets: Record<string, { max: number; used: number }>;
  checkStatuses?: Record<string, CheckStatusItem>;
  stack?: StackProfile;
}

export type CheckRunStatus = "completed" | "skipped" | "disabled" | "incomplete";

export interface CheckStatusItem {
  status: CheckRunStatus;
  requestsUsed: number;
  maxRequests?: number;
  reason?: string;
}

export interface ScanReport {
  id: string;
  targetOrigin: string;
  targetUrlRedacted: string;
  createdAt: string;
  status: ScanStatus;
  state: ReportState;
  stateReason: string;
  stateSummary: string;
  primaryRunbookCode?: RunbookCode;
  grade: "A" | "B" | "C" | "D" | "F";
  score: number;
  scanner: ScannerMetadata;
  findings: Finding[];
  authorization?: AuthorizationArtifact;
  aggregate: {
    hasClientSecretFinding: boolean;
    hasSourceMapFinding: boolean;
    hasSupabaseRiskFinding: boolean;
    hasInfrastructureFinding: boolean;
    hasCorsFinding: boolean;
    hasSecurityHeaderFinding: boolean;
    hasPublicApiFinding: boolean;
    findingCount: number;
    highestSeverity: Severity | "none";
  };
}

export interface FindingDisplayGroup {
  bundleKey: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  representative: Finding;
  members: Finding[];
  evidence: EvidenceItem[];
  remediations: Remediation[];
}

export type DisplayScanReport = ScanReport & {
  displayGroups: FindingDisplayGroup[];
  displayGroupCount: number;
};

export type EventName =
  | "scan_started"
  | "scan_completed"
  | "report_viewed"
  | "share_clicked"
  | "waitlist_submitted"
  | "stripe_clicked";

export interface PublicAsset {
  url: string;
  type: "html" | "script" | "source_map";
  body: string;
  truncated: boolean;
  status?: number;
  headers?: Record<string, string>;
}

export interface SupabaseContext {
  url?: string;
  anonKey?: string;
  serviceRoleKeyFingerprints: string[];
}
