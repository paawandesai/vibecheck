import net from "node:net";

function parseIPv4(address: string) {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((part) => Number(part));
  if (bytes.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) return null;
  return bytes;
}

function ipv4FromMappedIPv6(address: string) {
  const lower = address.toLowerCase();
  if (!lower.startsWith("::ffff:")) return null;
  const tail = lower.slice("::ffff:".length);
  if (tail.includes(".")) return tail;

  const groups = tail.split(":");
  if (groups.length !== 2) return null;
  const high = Number.parseInt(groups[0], 16);
  const low = Number.parseInt(groups[1], 16);
  if (!Number.isFinite(high) || !Number.isFinite(low)) return null;
  return `${(high >> 8) & 255}.${high & 255}.${(low >> 8) & 255}.${low & 255}`;
}

export function unsafeHostnameReason(hostname: string) {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!normalized) return "missing hostname";
  if (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized === "metadata.google.internal" ||
    normalized === "metadata" ||
    normalized.endsWith(".internal")
  ) {
    return "local or metadata hostname";
  }

  const mapped = ipv4FromMappedIPv6(normalized);
  const ipVersion = net.isIP(mapped ?? normalized);
  if (ipVersion === 4) {
    const bytes = parseIPv4(mapped ?? normalized);
    if (!bytes) return "invalid IPv4 literal";
    const [a, b] = bytes;
    if (a === 0) return "software/private IPv4 range";
    if (a === 10) return "private IPv4 range";
    if (a === 127) return "loopback IPv4 range";
    if (a === 169 && b === 254) return "link-local or metadata IPv4 range";
    if (a === 172 && b >= 16 && b <= 31) return "private IPv4 range";
    if (a === 192 && b === 168) return "private IPv4 range";
    if (a === 100 && b >= 64 && b <= 127) return "carrier-grade NAT IPv4 range";
    if (a === 198 && (b === 18 || b === 19)) return "benchmark IPv4 range";
    if (a >= 224) return "multicast or reserved IPv4 range";
    return null;
  }

  if (ipVersion === 6) {
    if (normalized === "::1" || normalized === "::") return "loopback or unspecified IPv6 range";
    if (normalized.startsWith("fc") || normalized.startsWith("fd")) return "unique local IPv6 range";
    if (/^fe[89ab]/.test(normalized)) return "link-local IPv6 range";
    if (mapped) return unsafeHostnameReason(mapped);
  }

  return null;
}

export function assertSafeHostname(hostname: string) {
  const reason = unsafeHostnameReason(hostname);
  if (reason) {
    throw new Error(`Blocked unsafe target: ${reason}`);
  }
}
