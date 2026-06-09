/**
 * Server-side Pendo Track Event utility.
 * Sends track events to the Pendo Data API via HTTP POST.
 * Failures are logged but never break application flow.
 */

const PENDO_TRACK_URL = "https://data.pendo.io/data/track";
const PENDO_INTEGRATION_KEY = "fb435e51-7e2c-4f56-9042-9d30ed1f7053";

export async function pendoTrack(
  event: string,
  properties?: Record<string, string | number | boolean>,
  context?: { ip?: string | null; userAgent?: string | null; url?: string }
) {
  try {
    await fetch(PENDO_TRACK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-pendo-integration-key": PENDO_INTEGRATION_KEY,
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
                ...(context.url ? { url: context.url } : {}),
              },
            }
          : {}),
      }),
    });
  } catch (err) {
    console.error("[Pendo] Failed to send track event:", event, err);
  }
}
