import { createClient } from "@supabase/supabase-js";
import { scanConfig } from "@/lib/env";
import type { EventName, ScanReport } from "@/lib/types";

const supabase =
  scanConfig.supabaseUrl && scanConfig.supabaseServiceRoleKey
    ? createClient(scanConfig.supabaseUrl, scanConfig.supabaseServiceRoleKey, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      })
    : null;

export function isSupabaseStoreConfigured() {
  return Boolean(supabase);
}

export async function saveReportToSupabase(report: ScanReport) {
  if (!supabase) return false;

  const { error } = await supabase.from("reports").upsert({
    id: report.id,
    target_origin: report.targetOrigin,
    target_url_redacted: report.targetUrlRedacted,
    grade: report.grade,
    score: report.score,
    scanner: report.scanner,
    findings: report.findings,
    aggregate: report.aggregate,
    authorization_artifact: report.authorization ?? null,
    created_at: report.createdAt
  });

  if (error) throw new Error(`Could not save report: ${error.message}`);
  return true;
}

export async function getReportFromSupabase(id: string) {
  if (!supabase) return null;

  const { data, error } = await supabase
    .from("reports")
    .select(
      "id,target_origin,target_url_redacted,grade,score,scanner,findings,aggregate,authorization_artifact,created_at"
    )
    .eq("id", id)
    .maybeSingle();

  if (error) throw new Error(`Could not load report: ${error.message}`);
  if (!data) return null;

  return {
    id: data.id,
    targetOrigin: data.target_origin,
    targetUrlRedacted: data.target_url_redacted,
    createdAt: data.created_at,
    grade: data.grade,
    score: data.score,
    scanner: data.scanner,
    findings: data.findings,
    authorization: data.authorization_artifact ?? undefined,
    aggregate: data.aggregate
  } satisfies ScanReport;
}

export async function recordEventToSupabase(name: EventName, reportId?: string) {
  if (!supabase) return false;

  const { error } = await supabase.from("events").insert({
    name,
    report_id: reportId ?? null
  });

  if (error) throw new Error(`Could not record event: ${error.message}`);
  return true;
}

export async function saveWaitlistEntryToSupabase(entry: {
  email: string;
  emailHash: string;
  reportId?: string;
  createdAt: string;
}) {
  if (!supabase) return false;

  const { error } = await supabase.from("waitlist_entries").insert({
    email: entry.email,
    email_hash: entry.emailHash,
    report_id: entry.reportId ?? null,
    created_at: entry.createdAt
  });

  if (error) throw new Error(`Could not save waitlist entry: ${error.message}`);
  return true;
}

export async function deleteWaitlistEntryFromSupabase(emailHash: string) {
  if (!supabase) return false;

  const { error } = await supabase.from("waitlist_entries").delete().eq("email_hash", emailHash);

  if (error) throw new Error(`Could not delete waitlist entry: ${error.message}`);
  return true;
}

export async function rateLimitCountSince(scope: string, key: string, since: Date) {
  if (!supabase) throw new Error("Supabase rate limit storage is not configured");

  const { count, error } = await supabase
    .from("rate_limit_events")
    .select("id", { count: "exact", head: true })
    .eq("scope", scope)
    .eq("key", key)
    .gte("created_at", since.toISOString());

  if (error) throw new Error(`Could not read rate limit events: ${error.message}`);
  return count ?? 0;
}

export async function recordRateLimitHit(scope: string, key: string, now: Date) {
  if (!supabase) throw new Error("Supabase rate limit storage is not configured");

  const { error } = await supabase.from("rate_limit_events").insert({
    scope,
    key,
    created_at: now.toISOString()
  });

  if (error) throw new Error(`Could not record rate limit event: ${error.message}`);
}
