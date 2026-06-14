import type { Finding, SupabaseContext } from "@/lib/types";
import { fixPromptsFor } from "@/lib/scanner/fixPrompts";
import { escapeEvidence, fingerprint, safeUrlForStorage } from "@/lib/scanner/redaction";
import { safeFetch, type SafeFetchOptions, type ScanBudget } from "@/lib/scanner/safeFetch";

const LIKELY_TABLES = ["profiles", "users", "todos"];

function supabaseHeaders(anonKey: string) {
  return {
    apikey: anonKey,
    Authorization: `Bearer ${anonKey}`,
    Prefer: "count=exact",
    "Range-Unit": "items",
    Range: "0-0"
  };
}

function openApiTableNames(body: string) {
  try {
    const parsed = JSON.parse(body) as { paths?: Record<string, unknown>; definitions?: Record<string, unknown> };
    const fromPaths = Object.keys(parsed.paths ?? {})
      .map((path) => path.replace(/^\//, "").split("/")[0])
      .filter(Boolean);
    const fromDefinitions = Object.keys(parsed.definitions ?? {});
    return [...new Set([...fromPaths, ...fromDefinitions])];
  } catch {
    return [];
  }
}

export async function checkSupabaseExposure(
  context: SupabaseContext,
  budget: ScanBudget,
  safeFetchOptions: Pick<SafeFetchOptions, "fetchImpl" | "resolveHostname"> = {}
) {
  const findings: Finding[] = [];
  if (!context.url || !context.anonKey) return findings;

  const root = `${context.url}/rest/v1/`;
  const rootResponse = await safeFetch(root, budget, {
    headers: supabaseHeaders(context.anonKey),
    maxBytes: 180_000,
    allowTruncate: true,
    timeoutMs: 9000,
    ...safeFetchOptions
  });

  const discoveredTables = rootResponse.ok ? openApiTableNames(rootResponse.text) : [];
  if (rootResponse.ok && discoveredTables.length > 0) {
    findings.push({
      id: `supabase_schema_${fingerprint(context.url)}`,
      type: "supabase_rls",
      title: "Supabase schema surface appears enumerable",
      severity: "low",
      confidence: "likely",
      reasonCode: "supabase_postgrest_schema_enumerable",
      summary:
        "The Supabase PostgREST schema endpoint returned table-like metadata to the anonymous key.",
      explanation:
        "Schema enumeration is not the same as data exposure, but it can help attackers understand your data model. Review API exposure and RLS policies.",
      limitation:
        "This finding does not claim RLS is disabled. It only reports that schema-like metadata was available to the anonymous key.",
      evidence: [
        {
          label: "Endpoint",
          value: escapeEvidence(safeUrlForStorage(rootResponse.url)),
          fingerprint: fingerprint(rootResponse.url),
          metadata: {
            tableNameCount: discoveredTables.length
          }
        }
      ],
      fixPrompts: fixPromptsFor("supabase_rls")
    });
  }

  const probeTables = [...new Set([...LIKELY_TABLES, ...discoveredTables])].slice(0, 2);
  for (const table of probeTables) {
    const tableUrl = `${context.url}/rest/v1/${encodeURIComponent(table)}?select=*`;
    const probe = await safeFetch(tableUrl, budget, {
      method: "HEAD",
      headers: supabaseHeaders(context.anonKey),
      timeoutMs: 9000,
      maxBytes: 0,
      ...safeFetchOptions
    });

    if (probe.status === 200 || probe.status === 206) {
      const hasCountHeader = Boolean(probe.headers.get("content-range"));
      findings.push({
        id: `supabase_read_${table}_${fingerprint(tableUrl)}`,
        type: "supabase_rls",
        title: `Anonymous read appears possible on Supabase table "${table}"`,
        severity: table === "users" || table === "profiles" ? "high" : "medium",
        confidence: hasCountHeader ? "confirmed" : "likely",
        reasonCode: "supabase_anon_read_probe_allowed",
        summary:
          "A read-only, count-style probe was allowed with the public Supabase anonymous key.",
        explanation:
          "Anon/publishable keys are expected in frontend apps, but private tables must still be protected by RLS and least-privilege policies.",
        limitation:
          "VibeCheck used a HEAD request and did not request, store, or display database rows. This finding says anonymous read appears possible; it does not claim RLS is globally disabled.",
        evidence: [
          {
            label: "Read-only probe",
            value: escapeEvidence(`HEAD /rest/v1/${table}?select=* returned ${probe.status}`),
            fingerprint: fingerprint(tableUrl),
            metadata: {
              countHeaderPresent: hasCountHeader
            }
          }
        ],
        fixPrompts: fixPromptsFor("supabase_rls")
      });
    }
  }

  const storageUrl = `${context.url}/storage/v1/bucket`;
  const storage = await safeFetch(storageUrl, budget, {
    method: "GET",
    headers: supabaseHeaders(context.anonKey),
    maxBytes: 80_000,
    allowTruncate: true,
    timeoutMs: 9000,
    ...safeFetchOptions
  });

  if (storage.ok) {
    let bucketCount = 0;
    try {
      const parsed = JSON.parse(storage.text) as unknown;
      bucketCount = Array.isArray(parsed) ? parsed.length : 0;
    } catch {
      bucketCount = 0;
    }

    if (bucketCount > 0) {
      findings.push({
        id: `supabase_storage_${fingerprint(storageUrl)}`,
        type: "supabase_rls",
        title: "Supabase storage buckets appear listable with anon key",
        severity: "medium",
        confidence: "likely",
        reasonCode: "supabase_storage_buckets_listable",
        summary:
          "The Supabase Storage bucket listing endpoint responded to the public anonymous key.",
        explanation:
          "Public bucket metadata can reveal storage structure. Review bucket policies and keep private objects behind least-privilege access.",
        limitation:
          "VibeCheck did not list object contents or download files. It stored only endpoint metadata and a bucket count.",
        evidence: [
          {
            label: "Read-only storage probe",
            value: escapeEvidence("GET /storage/v1/bucket returned 200"),
            fingerprint: fingerprint(storageUrl),
            metadata: {
              bucketCount
            }
          }
        ],
        fixPrompts: fixPromptsFor("supabase_rls")
      });
    }
  }

  return findings;
}
