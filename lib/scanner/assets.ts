import type { PublicAsset } from "@/lib/types";
import { safeUrlForStorage } from "@/lib/scanner/redaction";
import { safeFetch, type ScanBudget } from "@/lib/scanner/safeFetch";

const SCRIPT_SRC_PATTERN = /<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi;
const MAX_SCRIPT_ASSETS = 8;

function headersToRecord(headers: Headers) {
  return Object.fromEntries(headers.entries());
}

export function extractScriptUrls(html: string, pageUrl: string) {
  const base = new URL(pageUrl);
  const scripts = new Set<string>();
  let match: RegExpExecArray | null;

  while ((match = SCRIPT_SRC_PATTERN.exec(html))) {
    try {
      const scriptUrl = new URL(match[1], base);
      scriptUrl.hash = "";
      if (scriptUrl.origin === base.origin) {
        scripts.add(scriptUrl.toString());
      }
    } catch {
      // Ignore malformed script URLs from hostile target content.
    }
  }

  return [...scripts].slice(0, MAX_SCRIPT_ASSETS);
}

export async function collectPublicAssets(targetUrl: string, budget: ScanBudget) {
  const page = await safeFetch(targetUrl, budget, {
    maxBytes: 850_000,
    timeoutMs: 9000
  });

  const assets: PublicAsset[] = [
    {
      url: safeUrlForStorage(page.url),
      type: "html",
      body: page.text,
      truncated: page.truncated,
      status: page.status,
      headers: headersToRecord(page.headers)
    }
  ];

  const scriptUrls = extractScriptUrls(page.text, page.url);
  for (const scriptUrl of scriptUrls) {
    const script = await safeFetch(scriptUrl, budget, {
      maxBytes: 1_100_000,
      timeoutMs: 9000,
      allowTruncate: true
    });
    assets.push({
      url: safeUrlForStorage(script.url),
      type: "script",
      body: script.text,
      truncated: script.truncated,
      status: script.status,
      headers: headersToRecord(script.headers)
    });
  }

  return assets;
}
