import { scanConfig } from "@/lib/env";

const PENDO_TRACK_URL = "https://data.pendo.io/data/track";

export async function pendoTrack(
  event: string,
  properties?: Record<string, string | number | boolean>,
  context?: { ip?: string | null; userAgent?: string | null; url?: string }
) {
  if (!scanConfig.pendoIntegrationKey) return;

  try {
    await fetch(PENDO_TRACK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-pendo-integration-key": scanConfig.pendoIntegrationKey
      },
      body: JSON.stringify({
        type: "track",
        event,
        visitorId: "system",
        accountId: "system",
        timestamp: Date.now(),
        properties: properties ?? {},
        ...(context
          ? {
              context: {
                ...(context.ip ? { ip: context.ip } : {}),
                ...(context.userAgent ? { userAgent: context.userAgent } : {}),
                ...(context.url ? { url: context.url } : {})
              }
            }
          : {})
      })
    });
  } catch {
    // Analytics must never block scans, reports, or waitlist submission.
  }
}
