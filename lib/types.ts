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
  summary: string;
  explanation: string;
  limitation: string;
  evidence: EvidenceItem[];
  fixPrompts: Record<Builder, string>;
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
}

export interface ScanReport {
  id: string;
  targetOrigin: string;
  targetUrlRedacted: string;
  createdAt: string;
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
