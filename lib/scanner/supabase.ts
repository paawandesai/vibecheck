import type { Finding, SupabaseContext } from "@/lib/types";
import { createFinding } from "@/lib/report/findingModel";
import { escapeEvidence, fingerprint, safeUrlForStorage } from "@/lib/scanner/redaction";
import { safeFetch, type SafeFetchOptions, type ScanBudget } from "@/lib/scanner/safeFetch";

const COMMON_PROBE_TABLES = ["profiles", "users"];
const SENSITIVE_TABLES = new Set([
  "profiles",
  "users",
  "orders",
  "payments",
  "customers",
  "subscriptions",
  "invoices",
  "accounts",
  "members"
]);

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

export function supabaseAnonSelfCheckFinding(context: SupabaseContext): Finding | null {
  if (!context.url || !context.anonKey) return null;

  return createFinding({
    id: `supabase_anon_self_check_${fingerprint(context.url)}`,
    type: "supabase_rls",
    title: "Supabase public key found; RLS needs a self-check",
    severity: "medium",
    confidence: "informational",
    reasonCode: "supabase_anon_key_rls_unverified",
    tier: "public_by_design",
    location: "client_bundle",
    rlsInference: "unverifiable",
    runbookCode: "RLS_SELF_CHECK",
    summary:
      "A Supabase anon/publishable key appears in the public client bundle, which is expected, but VibeCheck could not verify table policies in this scan.",
    explanation:
      "Supabase anon keys are designed for browsers. They are safe only when RLS and bucket policies prevent anonymous users from reading private data.",
    limitation:
      "VibeCheck did not store the anon key and did not prove data exposure. This is a configuration self-check prompt.",
    evidence: [
      {
        label: "Supabase project",
        value: escapeEvidence(context.url),
        fingerprint: fingerprint(context.url)
      },
      {
        label: "RLS verification",
        value: "Not run or unavailable in this scan"
      }
    ]
  });
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
    findings.push(createFinding({
      id: `supabase_schema_${fingerprint(context.url)}`,
      type: "supabase_rls",
      title: "Supabase schema surface appears enumerable",
      severity: "low",
      confidence: "likely",
      reasonCode: "supabase_postgrest_schema_enumerable",
      tier: "public_by_design",
      location: "supabase_rest",
      rlsInference: "unverifiable",
      runbookCode: "RLS_SELF_CHECK",
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
      ]
    }));
  }

  const discoveredSensitive = discoveredTables.filter((table) => SENSITIVE_TABLES.has(table));
  const discoveredOther = discoveredTables.filter((table) => !SENSITIVE_TABLES.has(table));
  const probeTables = [...new Set([...discoveredSensitive, ...discoveredOther, ...COMMON_PROBE_TABLES, "todos"])].slice(0, 2);
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
      const sensitiveTable = SENSITIVE_TABLES.has(table);
      findings.push(createFinding({
        id: `supabase_read_${table}_${fingerprint(tableUrl)}`,
        type: "supabase_rls",
        title: sensitiveTable
          ? `Anonymous read probe allowed on sensitive Supabase table "${table}"`
          : `Anonymous read probe allowed on Supabase table "${table}"`,
        severity: sensitiveTable ? "critical" : "high",
        confidence: hasCountHeader ? "confirmed" : "likely",
        reasonCode: "supabase_anon_read_probe_allowed",
        tier: sensitiveTable ? "critical" : "public_by_design",
        location: "supabase_rest",
        rlsInference: sensitiveTable ? "confirmed_open" : "anon_read_possible",
        runbookCode: sensitiveTable ? "RLS_LOCKDOWN_INCIDENT" : "RLS_SELF_CHECK",
        summary: sensitiveTable
          ? "A read-only probe was allowed against a table name that commonly contains private data."
          : "A read-only, count-style probe was allowed with the public Supabase anonymous key.",
        explanation: sensitiveTable
          ? "Anyone with the public anon key may be able to read this table unless policies intentionally allow it. Sensitive table names often contain user, billing, membership, or account data."
          : "Anon/publishable keys are expected in frontend apps, but tables still need RLS and least-privilege policies unless they are intentionally public.",
        limitation:
          "VibeCheck used a HEAD request and did not request, store, or display database rows. This finding reports that the anonymous read probe was allowed for the table, not that rows were downloaded.",
        evidence: [
          {
            label: "Read-only probe",
            value: escapeEvidence(`HEAD /rest/v1/${table}?select=* returned ${probe.status}`),
            fingerprint: fingerprint(tableUrl),
            metadata: {
              countHeaderPresent: hasCountHeader
            }
          }
        ]
      }));
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
      findings.push(createFinding({
        id: `supabase_storage_${fingerprint(storageUrl)}`,
        type: "supabase_rls",
        title: "Supabase storage buckets appear listable with anon key",
        severity: "medium",
        confidence: "likely",
        reasonCode: "supabase_storage_buckets_listable",
        tier: "public_by_design",
        location: "supabase_storage",
        rlsInference: "anon_read_possible",
        runbookCode: "RLS_SELF_CHECK",
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
        ]
      }));
    }
  }

  return findings;
}
