import type { PublicAsset } from "@/lib/types";

const API_PATH_PATTERN = /(?:"|'|`|\()((?:https?:\/\/[^"'`\s)]+)?\/api\/[A-Za-z0-9._~:/?#[\]@!$&*+,;=%-]*)/g;

export function discoverReferencedApiPaths(assets: PublicAsset[], targetOrigin: string, maxPaths: number) {
  const origin = new URL(targetOrigin);
  const paths = new Set<string>();

  for (const asset of assets) {
    let match: RegExpExecArray | null;
    API_PATH_PATTERN.lastIndex = 0;
    while ((match = API_PATH_PATTERN.exec(asset.body))) {
      try {
        const url = new URL(match[1], origin);
        url.hash = "";
        if (url.origin === origin.origin && url.pathname.startsWith("/api/")) {
          paths.add(url.toString());
        }
      } catch {
        // Ignore malformed target-provided strings.
      }
      if (paths.size >= maxPaths) break;
    }
    if (paths.size >= maxPaths) break;
  }

  return [...paths];
}
