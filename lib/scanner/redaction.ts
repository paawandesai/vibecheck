import crypto from "node:crypto";

export function fingerprint(value: string) {
  return crypto.createHash("sha256").update(value).digest("hex").slice(0, 20);
}

export function redactSecret(value: string) {
  if (value.length <= 12) return "[redacted]";
  return `${value.slice(0, 6)}...[redacted]...${value.slice(-4)}`;
}

export function escapeEvidence(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function safeUrlForStorage(url: string | URL) {
  const parsed = typeof url === "string" ? new URL(url) : url;
  return `${parsed.origin}${parsed.pathname}`;
}

export function hashEmail(email: string) {
  return crypto.createHash("sha256").update(email.trim().toLowerCase()).digest("hex");
}
