import type { PublicAsset, StackBackend, StackConfidence, StackFramework, StackHost, StackProfile } from "@/lib/types";

function header(asset: PublicAsset | undefined, name: string) {
  const lowerName = name.toLowerCase();
  const headers = asset?.headers ?? {};
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lowerName) return value;
  }
  return "";
}

function hostnameFromOrigin(targetOrigin: string) {
  try {
    return new URL(targetOrigin).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function detectHost(hostname: string, headerAsset: PublicAsset | undefined, signals: string[]): StackHost {
  const server = header(headerAsset, "server").toLowerCase();
  if (header(headerAsset, "x-vercel-id") || hostname.endsWith(".vercel.app")) {
    signals.push(header(headerAsset, "x-vercel-id") ? "x-vercel-id header" : "vercel.app hostname");
    return "vercel";
  }
  if (header(headerAsset, "x-nf-request-id") || server.includes("netlify") || hostname.endsWith(".netlify.app")) {
    signals.push(header(headerAsset, "x-nf-request-id") ? "x-nf-request-id header" : "netlify host hint");
    return "netlify";
  }
  if (hostname.endsWith(".pages.dev")) {
    signals.push("pages.dev hostname");
    return "cloudflare_pages";
  }
  if (hostname.endsWith(".github.io")) {
    signals.push("github.io hostname");
    return "github_pages";
  }
  if (hostname.endsWith(".kiloapps.io")) {
    signals.push("kiloapps.io hostname");
    return "kilo";
  }
  return "unknown";
}

function detectFramework(assets: PublicAsset[], signals: string[]): StackFramework {
  if (
    assets.some(
      (asset) =>
        asset.url.includes("/_next/") ||
        asset.body.includes("__NEXT_DATA__") ||
        asset.body.includes("self.__next_f")
    )
  ) {
    signals.push("Next.js asset marker");
    return "next";
  }
  if (assets.some((asset) => /react(?:\.production)?\.min\.js|react-dom|createRoot/.test(asset.body))) {
    signals.push("React bundle marker");
    return "react";
  }
  if (assets.length <= 1) return "static";
  return "unknown";
}

function detectBackend(headerAsset: PublicAsset | undefined, assets: PublicAsset[], signals: string[]): StackBackend {
  const server = header(headerAsset, "server").toLowerCase();
  const cookie = header(headerAsset, "set-cookie").toLowerCase();
  const bodyHints = assets.some((asset) => /csrfmiddlewaretoken|csrftoken|django/i.test(asset.body));

  if (/gunicorn|uvicorn|wsgi|django/.test(server) || cookie.includes("csrftoken") || bodyHints) {
    signals.push("Django/backend header or CSRF marker");
    return "django";
  }
  if (/node|next\.js/.test(server)) {
    signals.push("Node server header");
    return "node";
  }
  return "unknown";
}

function confidenceFor(host: StackHost, framework: StackFramework, backend: StackBackend, signals: string[]): StackConfidence {
  if (signals.some((signal) => signal.includes("header") || signal.includes("Next.js"))) return "confirmed";
  if (host !== "unknown" || framework !== "unknown" || backend !== "unknown") return "likely";
  return "unknown";
}

export function detectStack(input: {
  targetOrigin: string;
  headerAsset?: PublicAsset;
  assets?: PublicAsset[];
}): StackProfile {
  const assets = input.assets ?? [];
  const hostname = hostnameFromOrigin(input.targetOrigin);
  const signals: string[] = [];
  const host = detectHost(hostname, input.headerAsset, signals);
  const framework = detectFramework(assets, signals);
  const backend = detectBackend(input.headerAsset, assets, signals);
  const confidence = confidenceFor(host, framework, backend, signals);

  return {
    host,
    framework,
    backend,
    confidence,
    signals
  };
}
