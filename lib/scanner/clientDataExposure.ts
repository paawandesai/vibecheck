import type { Finding, PublicAsset } from "@/lib/types";
import { createFinding } from "@/lib/report/findingModel";
import { escapeEvidence, fingerprint, safeUrlForStorage } from "@/lib/scanner/redaction";

interface PayloadCandidate {
  asset: PublicAsset;
  kind: "next_data" | "rsc";
  raw: string;
  parsed?: unknown;
}

interface PayloadStats {
  payloadBytes: number;
  objectCount: number;
  maxArrayRecords: number;
  sensitiveKeys: Set<string>;
  emailLikeCount: number;
  phoneLikeCount: number;
  secretLikeCount: number;
}

const NEXT_DATA_SCRIPT_PATTERN =
  /<script\b[^>]*\bid=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/gi;
const RSC_SCRIPT_PATTERN =
  /<script\b[^>]*>([\s\S]*?(?:self\.)?__next_f\.push[\s\S]*?)<\/script>/gi;
const RAW_OBJECT_PATTERN = /\{(?=[^{}]{0,500}["'][A-Za-z0-9_$-]+["']\s*:)/g;
const RAW_KEY_PATTERN =
  /["']([A-Za-z0-9_$-]*(?:email|phone|ssn|address|token|secret|password|role|customer|patient|user|session|auth|billing|invoice)[A-Za-z0-9_$-]*)["']\s*:/gi;
const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_PATTERN = /\b(?:\+?\d[\s().-]?){9,}\b/g;
const SECRET_LIKE_PATTERN =
  /\b(?:sk_(?:live|test)_[A-Za-z0-9]{16,}|sk-or-v1-[A-Za-z0-9_-]{20,}|sk-lf-[A-Za-z0-9_-]{20,}|pcsk_[A-Za-z0-9_-]{20,}|lsv2_(?:pt|sk)_[A-Za-z0-9._-]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g;

function tryParseJson(raw: string) {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}

function addSensitiveKey(keys: Set<string>, key: string) {
  if (RAW_KEY_PATTERN.test(`"${key}":`)) keys.add(key);
  RAW_KEY_PATTERN.lastIndex = 0;
}

function walkJson(value: unknown, stats: PayloadStats, depth = 0, seen = { count: 0 }) {
  if (depth > 12 || seen.count > 1500 || value == null) return;

  if (Array.isArray(value)) {
    const objectRecords = value.filter((item) => item && typeof item === "object").length;
    stats.maxArrayRecords = Math.max(stats.maxArrayRecords, objectRecords);
    for (const item of value.slice(0, 75)) walkJson(item, stats, depth + 1, seen);
    return;
  }

  if (typeof value !== "object") return;

  seen.count += 1;
  stats.objectCount += 1;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    addSensitiveKey(stats.sensitiveKeys, key);
    walkJson(child, stats, depth + 1, seen);
  }
}

function rawSensitiveKeys(raw: string) {
  const keys = new Set<string>();
  RAW_KEY_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = RAW_KEY_PATTERN.exec(raw))) {
    keys.add(match[1]);
    if (keys.size >= 20) break;
  }
  return keys;
}

function analyzePayload(raw: string, parsed?: unknown): PayloadStats {
  const stats: PayloadStats = {
    payloadBytes: Buffer.byteLength(raw, "utf8"),
    objectCount: raw.match(RAW_OBJECT_PATTERN)?.length ?? 0,
    maxArrayRecords: 0,
    sensitiveKeys: rawSensitiveKeys(raw),
    emailLikeCount: raw.match(EMAIL_PATTERN)?.length ?? 0,
    phoneLikeCount: raw.match(PHONE_PATTERN)?.length ?? 0,
    secretLikeCount: raw.match(SECRET_LIKE_PATTERN)?.length ?? 0
  };

  if (parsed !== undefined) walkJson(parsed, stats);
  return stats;
}

function extractNextData(asset: PublicAsset) {
  const payloads: PayloadCandidate[] = [];
  NEXT_DATA_SCRIPT_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = NEXT_DATA_SCRIPT_PATTERN.exec(asset.body))) {
    const raw = match[1].trim();
    if (raw) payloads.push({ asset, kind: "next_data", raw, parsed: tryParseJson(raw) });
  }
  return payloads;
}

function extractRscPayloads(asset: PublicAsset) {
  if (!asset.body.includes("__next_f.push")) return [];

  const payloads: PayloadCandidate[] = [];
  RSC_SCRIPT_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = RSC_SCRIPT_PATTERN.exec(asset.body))) {
    const raw = match[1].trim();
    if (raw) payloads.push({ asset, kind: "rsc", raw });
  }

  if (!payloads.length) payloads.push({ asset, kind: "rsc", raw: asset.body });
  return payloads;
}

function shouldFlag(stats: PayloadStats) {
  const hasPrivateShape =
    stats.sensitiveKeys.size >= 2 ||
    stats.emailLikeCount >= 1 ||
    stats.phoneLikeCount >= 1 ||
    stats.secretLikeCount >= 1;
  const looksDumped =
    stats.payloadBytes >= 2_000 ||
    stats.objectCount >= 10 ||
    stats.maxArrayRecords >= 3;

  return hasPrivateShape && looksDumped;
}

function isCritical(stats: PayloadStats) {
  if (stats.secretLikeCount > 0) return true;
  const repeatedRecords = stats.maxArrayRecords >= 3 || stats.objectCount >= 20;
  const strongPii =
    stats.emailLikeCount >= 3 ||
    stats.phoneLikeCount >= 3 ||
    (stats.sensitiveKeys.has("email") && stats.sensitiveKeys.size >= 3);

  return repeatedRecords && strongPii;
}

function displayKind(kind: PayloadCandidate["kind"]) {
  return kind === "next_data" ? "__NEXT_DATA__" : "React Server Component payload";
}

function findingForPayload(candidate: PayloadCandidate, stats: PayloadStats): Finding {
  const critical = isCritical(stats);
  const keys = [...stats.sensitiveKeys].sort().slice(0, 10);
  const kindLabel = displayKind(candidate.kind);
  const assetUrl = safeUrlForStorage(candidate.asset.url);
  const idBase = `${candidate.kind}:${assetUrl}:${fingerprint(candidate.raw)}`;

  return createFinding({
    id: `client_data_exposure_${fingerprint(idBase)}`,
    type: "client_data_exposure",
    title: critical
      ? "Sensitive-looking records are serialized to the client"
      : "Large client hydration payload contains private-looking fields",
    severity: critical ? "critical" : "medium",
    confidence: critical ? "confirmed" : "likely",
    reasonCode: critical
      ? `${candidate.kind}_sensitive_record_dump`
      : `${candidate.kind}_private_shape_in_client_payload`,
    tier: critical ? "critical" : "unknown",
    location: "client_bundle",
    rlsInference: "not_applicable",
    runbookCode: "CLIENT_DATA_MINIMIZE",
    summary: `${kindLabel} includes a large serialized payload with private-looking data shape signals.`,
    explanation:
      "Server-rendered apps can accidentally send whole records to the browser even when the UI shows only a few fields. Minimize props and RSC payloads before serialization.",
    limitation:
      "VibeCheck inspected public HTML and client assets only. It stored payload size, key names, and counts, not the raw serialized data.",
    evidence: [
      {
        label: "Asset",
        value: escapeEvidence(assetUrl),
        fingerprint: fingerprint(assetUrl),
        metadata: {
          payloadType: candidate.kind,
          payloadBytes: stats.payloadBytes,
          objectCount: stats.objectCount,
          maxArrayRecords: stats.maxArrayRecords
        }
      },
      {
        label: "Private-looking keys",
        value: keys.length ? escapeEvidence(keys.join(", ")) : "none",
        metadata: {
          sensitiveKeyCount: stats.sensitiveKeys.size,
          emailLikeCount: stats.emailLikeCount,
          phoneLikeCount: stats.phoneLikeCount,
          secretLikeCount: stats.secretLikeCount
        }
      }
    ]
  });
}

export function checkClientDataExposure(assets: PublicAsset[]) {
  const findings = new Map<string, Finding>();
  for (const asset of assets) {
    const candidates = [...extractNextData(asset), ...extractRscPayloads(asset)];
    for (const candidate of candidates) {
      const stats = analyzePayload(candidate.raw, candidate.parsed);
      if (!shouldFlag(stats)) continue;
      const finding = findingForPayload(candidate, stats);
      findings.set(finding.id, finding);
    }
  }

  return [...findings.values()];
}
