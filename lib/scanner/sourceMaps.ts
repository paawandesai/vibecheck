import type { Finding, PublicAsset } from "@/lib/types";
import { fixPromptsFor } from "@/lib/scanner/fixPrompts";
import { escapeEvidence, fingerprint, safeUrlForStorage } from "@/lib/scanner/redaction";
import { safeFetch, type ScanBudget } from "@/lib/scanner/safeFetch";

const SOURCE_MAP_PATTERN = /[#@]\s*sourceMappingURL=([^\s*]+)/g;

export function findSourceMapReferences(assets: PublicAsset[]) {
  const refs = new Map<string, { mapUrl: string; assetUrl: string }>();

  for (const asset of assets) {
    if (asset.type !== "script" && asset.type !== "html") continue;
    let match: RegExpExecArray | null;
    SOURCE_MAP_PATTERN.lastIndex = 0;
    while ((match = SOURCE_MAP_PATTERN.exec(asset.body))) {
      const raw = match[1].trim().replace(/^["']|["']$/g, "");
      if (!raw || raw.startsWith("data:")) continue;
      try {
        const mapUrl = new URL(raw, asset.url);
        mapUrl.hash = "";
        refs.set(mapUrl.toString(), {
          mapUrl: mapUrl.toString(),
          assetUrl: asset.url
        });
      } catch {
        // Ignore malformed target-provided source map references.
      }
    }
  }

  return [...refs.values()].slice(0, 4);
}

function looksLikeSourceMap(text: string) {
  try {
    const parsed = JSON.parse(text) as { version?: unknown; sources?: unknown; mappings?: unknown };
    return typeof parsed.version === "number" && Array.isArray(parsed.sources) && "mappings" in parsed;
  } catch {
    return false;
  }
}

export async function checkSourceMaps(assets: PublicAsset[], budget: ScanBudget) {
  const findings: Finding[] = [];
  const refs = findSourceMapReferences(assets);

  for (const ref of refs) {
    const response = await safeFetch(ref.mapUrl, budget, {
      maxBytes: 160_000,
      timeoutMs: 8000,
      allowTruncate: true
    });

    if (!response.ok) continue;

    const confirmed = !response.truncated && looksLikeSourceMap(response.text);
    const reasonCode = confirmed
      ? "public_source_map_confirmed"
      : "public_source_map_accessible_unconfirmed_shape";

    findings.push({
      id: `source_map_${fingerprint(ref.mapUrl)}`,
      type: "source_map",
      title: "Publicly accessible source map detected",
      severity: "medium",
      confidence: confirmed ? "confirmed" : "likely",
      reasonCode,
      summary:
        "A sourceMappingURL reference points to a publicly reachable source map file.",
      explanation:
        "Public source maps can reveal source paths, original source snippets, and implementation details that make attacks easier.",
      limitation:
        "VibeCheck confirms accessibility and source map shape when possible. It stores only the URL fingerprint and metadata, never the source map contents.",
      evidence: [
        {
          label: "Source map URL",
          value: escapeEvidence(safeUrlForStorage(response.url)),
          fingerprint: fingerprint(ref.mapUrl),
          metadata: {
            truncated: response.truncated,
            shapeConfirmed: confirmed
          }
        },
        {
          label: "Referenced by",
          value: escapeEvidence(ref.assetUrl)
        }
      ],
      fixPrompts: fixPromptsFor("source_map")
    });
  }

  return findings;
}
