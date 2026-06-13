import type { Finding, PublicAsset, Severity, SupabaseContext } from "@/lib/types";
import { fixPromptsFor } from "@/lib/scanner/fixPrompts";
import { escapeEvidence, fingerprint, redactSecret } from "@/lib/scanner/redaction";

interface SecretPattern {
  provider: string;
  reasonCode: string;
  severity: Severity;
  regex: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    provider: "Stripe/Clerk secret key",
    reasonCode: "stripe_clerk_secret_key_in_client_bundle",
    severity: "critical",
    regex: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g
  },
  {
    provider: "OpenAI API key",
    reasonCode: "openai_key_in_client_bundle",
    severity: "critical",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g
  },
  {
    provider: "Anthropic API key",
    reasonCode: "anthropic_key_in_client_bundle",
    severity: "critical",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g
  },
  {
    provider: "Gemini API key",
    reasonCode: "gemini_key_in_client_bundle",
    severity: "critical",
    regex: /\bAIzaSy[A-Za-z0-9_-]{33}\b/g
  },
  {
    provider: "Groq API key",
    reasonCode: "groq_key_in_client_bundle",
    severity: "critical",
    regex: /\bgsk_[A-Za-z0-9]{32}\b/g
  },
  {
    provider: "Replicate API token",
    reasonCode: "replicate_key_in_client_bundle",
    severity: "critical",
    regex: /\br8_[A-Za-z0-9]{34}\b/g
  },
  {
    provider: "HuggingFace token",
    reasonCode: "huggingface_token_in_client_bundle",
    severity: "critical",
    regex: /\bhf_[A-Za-z0-9]{34}\b/g
  }
];

const SUPABASE_URL_PATTERN = /https:\/\/[a-z0-9-]+\.supabase\.co/gi;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
const AWS_ACCESS_KEY_PATTERN = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const AWS_SECRET_NEARBY_PATTERN = /aws[_-]?secret[_-]?access[_-]?key["'\s:=]+([A-Za-z0-9/+=]{35,})/i;

function decodeJwtPayload(token: string) {
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const json = Buffer.from(payload, "base64url").toString("utf8");
    return JSON.parse(json) as { role?: string; iss?: string; ref?: string };
  } catch {
    return null;
  }
}

function secretFinding(provider: string, reasonCode: string, severity: Severity, value: string, asset: PublicAsset): Finding {
  const fp = fingerprint(value);
  return {
    id: `client_secret_${reasonCode}_${fp}`,
    type: "client_secret",
    title: `${provider} appears in a public client asset`,
    severity,
    confidence: "confirmed",
    reasonCode,
    summary: "A high-confidence secret pattern was found in publicly served HTML or JavaScript.",
    explanation:
      "Secrets in browser-delivered code can be copied by anyone who can load the app. Rotate the key and move privileged calls behind a server-side boundary.",
    limitation:
      "This finding is based on public client assets only. It does not prove the key is currently active, and VibeCheck stores only redacted evidence plus a fingerprint.",
    evidence: [
      {
        label: "Asset",
        value: escapeEvidence(asset.url)
      },
      {
        label: "Redacted value",
        value: escapeEvidence(redactSecret(value)),
        fingerprint: fp
      }
    ],
    fixPrompts: fixPromptsFor("client_secret")
  };
}

function findAwsPairs(asset: PublicAsset) {
  const findings: Finding[] = [];
  const accessKeys = asset.body.match(AWS_ACCESS_KEY_PATTERN) ?? [];
  const secretMatch = asset.body.match(AWS_SECRET_NEARBY_PATTERN);
  if (!accessKeys.length || !secretMatch?.[1]) return findings;

  const combined = `${accessKeys[0]}:${secretMatch[1]}`;
  findings.push(
    secretFinding("AWS access key pair", "aws_key_pair_in_client_bundle", "critical", combined, asset)
  );
  return findings;
}

export function analyzeSecrets(assets: PublicAsset[]) {
  const findings = new Map<string, Finding>();
  const supabaseContext: SupabaseContext = {
    serviceRoleKeyFingerprints: []
  };

  for (const asset of assets) {
    for (const url of asset.body.match(SUPABASE_URL_PATTERN) ?? []) {
      supabaseContext.url ??= url.toLowerCase();
    }

    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.regex.exec(asset.body))) {
        const finding = secretFinding(
          pattern.provider,
          pattern.reasonCode,
          pattern.severity,
          match[0],
          asset
        );
        findings.set(finding.id, finding);
      }
    }

    for (const token of asset.body.match(JWT_PATTERN) ?? []) {
      const payload = decodeJwtPayload(token);
      if (payload?.role === "anon") {
        supabaseContext.anonKey ??= token;
      }
      if (payload?.role === "service_role") {
        supabaseContext.serviceRoleKeyFingerprints.push(fingerprint(token));
        const finding = secretFinding(
          "Supabase service-role key",
          "supabase_service_role_key_in_client_bundle",
          "critical",
          token,
          asset
        );
        findings.set(finding.id, finding);
      }
    }

    for (const finding of findAwsPairs(asset)) {
      findings.set(finding.id, finding);
    }
  }

  return {
    findings: [...findings.values()],
    supabaseContext
  };
}
