import type { Finding, PublicAsset, Severity } from "@/lib/types";
import { fixPromptsFor } from "@/lib/scanner/fixPrompts";
import { escapeEvidence, fingerprint } from "@/lib/scanner/redaction";

function header(asset: PublicAsset, name: string) {
  return asset.headers?.[name.toLowerCase()] ?? "";
}

function finding(
  targetUrl: string,
  reasonCode: string,
  title: string,
  severity: Severity,
  summary: string,
  explanation: string,
  observed: string
): Finding {
  return {
    id: `security_header_${reasonCode}_${fingerprint(targetUrl)}`,
    type: "security_header",
    title,
    severity,
    confidence: "confirmed",
    reasonCode,
    summary,
    explanation,
    limitation:
      "VibeCheck checked the public response headers only. It did not inspect server configuration.",
    evidence: [
      {
        label: "URL",
        value: escapeEvidence(targetUrl)
      },
      {
        label: "Observed header",
        value: escapeEvidence(observed || "(missing)")
      }
    ],
    fixPrompts: fixPromptsFor("security_header")
  };
}

export function checkSecurityHeaders(pageAsset: PublicAsset, targetOrigin: string) {
  const findings: Finding[] = [];
  const csp = header(pageAsset, "content-security-policy");
  const hsts = header(pageAsset, "strict-transport-security");
  const nosniff = header(pageAsset, "x-content-type-options");
  const frameOptions = header(pageAsset, "x-frame-options");
  const referrer = header(pageAsset, "referrer-policy");
  const targetUrl = pageAsset.url;

  if (!csp) {
    findings.push(
      finding(
        targetUrl,
        "missing_content_security_policy",
        "Missing Content Security Policy",
        "medium",
        "The public page does not send a Content-Security-Policy header.",
        "A CSP helps reduce the blast radius of XSS and unwanted third-party script execution.",
        csp
      )
    );
  } else if (csp.includes("*") || csp.includes("'unsafe-eval'")) {
    findings.push(
      finding(
        targetUrl,
        "weak_content_security_policy",
        "Weak Content Security Policy",
        "low",
        "The Content-Security-Policy appears overly permissive.",
        "Wildcard sources or unsafe eval make browser-side injection issues easier to exploit.",
        csp
      )
    );
  }

  if (targetOrigin.startsWith("https://") && !hsts) {
    findings.push(
      finding(
        targetUrl,
        "missing_hsts",
        "Missing HSTS header",
        "low",
        "The HTTPS site does not send Strict-Transport-Security.",
        "HSTS helps browsers keep future requests on HTTPS and reduces downgrade risk.",
        hsts
      )
    );
  }

  if (nosniff.toLowerCase() !== "nosniff") {
    findings.push(
      finding(
        targetUrl,
        "missing_nosniff",
        "Missing X-Content-Type-Options nosniff",
        "low",
        "The response does not send X-Content-Type-Options: nosniff.",
        "nosniff helps browsers avoid interpreting files as a different content type.",
        nosniff
      )
    );
  }

  if (!frameOptions && !csp.includes("frame-ancestors")) {
    findings.push(
      finding(
        targetUrl,
        "missing_frame_protection",
        "Missing frame embedding protection",
        "low",
        "The page does not appear to block framing.",
        "Frame protections reduce clickjacking risk for sensitive app surfaces.",
        frameOptions || csp
      )
    );
  }

  if (!referrer || referrer.toLowerCase() === "unsafe-url") {
    findings.push(
      finding(
        targetUrl,
        "weak_referrer_policy",
        "Missing or weak Referrer-Policy",
        "low",
        "The page has no Referrer-Policy or uses an unsafe policy.",
        "A stricter referrer policy avoids leaking full paths and query strings to other origins.",
        referrer
      )
    );
  }

  return findings;
}
