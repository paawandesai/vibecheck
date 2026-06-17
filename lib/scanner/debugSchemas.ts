import type { Finding } from "@/lib/types";
import { createFinding } from "@/lib/report/findingModel";
import { escapeEvidence, fingerprint, safeUrlForStorage } from "@/lib/scanner/redaction";
import { safeFetch, type SafeFetchOptions, type ScanBudget } from "@/lib/scanner/safeFetch";

const DEBUG_SCHEMA_PATHS = ["/openapi.json", "/swagger.json", "/api/graphql"] as const;
const GRAPHQL_MARKERS = [
  "graphiql",
  "graphql playground",
  "apollo sandbox",
  "__schema",
  "querytype",
  "mutationtype",
  "subscriptiontype"
];

interface SchemaSignal {
  kind: "openapi" | "graphql";
  operationCount: number;
  schemaKeys: number;
}

function countKeys(value: unknown) {
  if (!value || typeof value !== "object") return 0;
  return Object.keys(value as Record<string, unknown>).length;
}

function richJsonSchema(text: string): SchemaSignal | null {
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    const paths = parsed.paths;
    if (
      (typeof parsed.openapi === "string" || typeof parsed.swagger === "string") &&
      paths &&
      typeof paths === "object"
    ) {
      const operationCount = Object.values(paths as Record<string, unknown>).reduce<number>(
        (count, value) => count + countKeys(value),
        0
      );
      if (operationCount > 0) {
        return {
          kind: "openapi",
          operationCount,
          schemaKeys: countKeys(parsed.components) + countKeys(parsed.definitions)
        };
      }
    }

    const data = parsed.data as Record<string, unknown> | undefined;
    const schema = data?.__schema ?? parsed.__schema;
    if (schema && typeof schema === "object") {
      return {
        kind: "graphql",
        operationCount: countKeys((schema as Record<string, unknown>).queryType),
        schemaKeys: countKeys(schema)
      };
    }
  } catch {
    return null;
  }

  return null;
}

function richGraphqlMarker(text: string): SchemaSignal | null {
  const lower = text.toLowerCase();
  const markerCount = GRAPHQL_MARKERS.filter((marker) => lower.includes(marker)).length;
  if (markerCount < 2) return null;

  return {
    kind: "graphql",
    operationCount: markerCount,
    schemaKeys: markerCount
  };
}

function classifySchema(text: string) {
  return richJsonSchema(text) ?? richGraphqlMarker(text);
}

function findingForSchema(url: string, status: number, contentType: string, signal: SchemaSignal): Finding {
  const storedUrl = safeUrlForStorage(url);
  return createFinding({
    id: `debug_schema_${fingerprint(storedUrl)}`,
    type: "debug_schema",
    title: signal.kind === "openapi"
      ? "Public OpenAPI or Swagger schema is exposed"
      : "Public GraphQL schema or explorer is exposed",
    severity: "medium",
    confidence: "likely",
    reasonCode: signal.kind === "openapi" ? "public_openapi_schema" : "public_graphql_schema",
    tier: "unknown",
    location: "public_web_path",
    rlsInference: "not_applicable",
    runbookCode: "DEBUG_SCHEMA_RESTRICT",
    summary: "A predictable public debug/schema path returned rich API metadata.",
    explanation:
      "Schema and explorer routes can help anonymous visitors map routes, operations, object names, and private-looking API capabilities even when the operations themselves still require auth.",
    limitation:
      "VibeCheck made one unauthenticated GET request to this predictable path and stored only schema metadata, not the schema body.",
    evidence: [
      {
        label: "Schema path",
        value: escapeEvidence(storedUrl),
        fingerprint: fingerprint(storedUrl),
        metadata: {
          status,
          contentType: contentType.slice(0, 80),
          schemaKind: signal.kind,
          operationCount: signal.operationCount,
          schemaKeys: signal.schemaKeys
        }
      }
    ]
  });
}

export async function checkDebugSchemas(
  targetOrigin: string,
  budget: ScanBudget,
  safeFetchOptions: Pick<SafeFetchOptions, "fetchImpl" | "resolveHostname"> = {}
) {
  const findings: Finding[] = [];

  for (const path of DEBUG_SCHEMA_PATHS) {
    try {
      const url = new URL(path, targetOrigin);
      const res = await safeFetch(url, budget, {
        method: "GET",
        headers: {
          Accept: "application/json,text/html;q=0.9,*/*;q=0.8"
        },
        timeoutMs: 8000,
        maxBytes: 90_000,
        allowTruncate: true,
        ...safeFetchOptions
      });
      if (!res.ok || res.status !== 200) continue;

      const signal = classifySchema(res.text);
      if (!signal) continue;

      findings.push(findingForSchema(res.url, res.status, res.headers.get("content-type") ?? "", signal));
    } catch (err) {
      if ((err as Error).message.includes("budget exceeded")) throw err;
      continue;
    }
  }

  return findings;
}
