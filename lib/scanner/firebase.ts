import type { Finding, PublicAsset } from "@/lib/types";
import { createFinding } from "@/lib/report/findingModel";
import { escapeEvidence, fingerprint, safeUrlForStorage } from "@/lib/scanner/redaction";

const FIREBASE_INIT_PATTERN = /\b(?:firebase\.)?initializeApp\s*\(/;
const FIREBASE_IMPORT_PATTERN = /(?:from\s+["']firebase\/app["']|@firebase\/app|firebaseapp\.com|firebasestorage\.app|firebasestorage\.googleapis\.com)/;
const FIREBASE_KEY_PATTERNS = {
  apiKey: /\bapiKey\s*:\s*["'][^"']{12,}["']/,
  authDomain: /\bauthDomain\s*:\s*["'][^"']+\.firebaseapp\.com["']/,
  projectId: /\bprojectId\s*:\s*["'][^"']+["']/,
  storageBucket: /\bstorageBucket\s*:\s*["'][^"']+["']/,
  messagingSenderId: /\bmessagingSenderId\s*:\s*["'][^"']+["']/,
  appId: /\bappId\s*:\s*["'][^"']+["']/
};

function firebaseSignals(body: string) {
  const keys = Object.entries(FIREBASE_KEY_PATTERNS)
    .filter(([, pattern]) => pattern.test(body))
    .map(([key]) => key);
  const hasFirebaseContext = FIREBASE_INIT_PATTERN.test(body) || FIREBASE_IMPORT_PATTERN.test(body);
  const hasCoreConfig = keys.includes("apiKey") && (keys.includes("authDomain") || keys.includes("projectId"));

  return {
    keys,
    hasFirebaseContext,
    hasCoreConfig
  };
}

export function checkFirebaseConfig(assets: PublicAsset[]) {
  const findings = new Map<string, Finding>();

  for (const asset of assets) {
    const signals = firebaseSignals(asset.body);
    if (!signals.hasFirebaseContext || !signals.hasCoreConfig) continue;

    const assetUrl = safeUrlForStorage(asset.url);
    const keyList = signals.keys.slice(0, 8).join(", ");
    const finding = createFinding({
      id: `firebase_config_${fingerprint(`${assetUrl}:${keyList}`)}`,
      type: "firebase_config",
      title: "Firebase browser config detected; audit Security Rules",
      severity: "medium",
      confidence: "likely",
      reasonCode: "firebase_config_in_client_bundle",
      tier: "public_by_design",
      location: "client_bundle",
      rlsInference: "unverifiable",
      runbookCode: "FIREBASE_RULES_SELF_CHECK",
      summary: "The public client bundle includes Firebase initialization config.",
      explanation:
        "Firebase web config is often expected in browser apps. The security question is whether Firestore, Realtime Database, and Storage Rules prevent anonymous access to private data.",
      limitation:
        "VibeCheck did not query Firebase data or test rules. It only detected public initialization config and stored config-key names, not the config values.",
      evidence: [
        {
          label: "Asset",
          value: escapeEvidence(assetUrl),
          fingerprint: fingerprint(assetUrl),
          metadata: {
            detectedConfigKeys: signals.keys.length,
            hasApiKey: signals.keys.includes("apiKey"),
            hasAuthDomain: signals.keys.includes("authDomain"),
            hasProjectId: signals.keys.includes("projectId")
          }
        },
        {
          label: "Config keys",
          value: escapeEvidence(keyList)
        }
      ]
    });

    findings.set(finding.id, finding);
  }

  return [...findings.values()];
}
