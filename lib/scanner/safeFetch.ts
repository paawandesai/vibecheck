import dns from "node:dns/promises";
import { assertSafeHostname, unsafeHostnameReason } from "@/lib/scanner/ip";

export interface SafeFetchResult {
  url: string;
  status: number;
  ok: boolean;
  headers: Headers;
  text: string;
  truncated: boolean;
}

export interface SafeFetchOptions {
  method?: "GET" | "HEAD";
  headers?: HeadersInit;
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  allowTruncate?: boolean;
  fetchImpl?: typeof fetch;
  resolveHostname?: (hostname: string) => Promise<Array<{ address: string }>>;
}

export class ScanBudget {
  private used = 0;

  constructor(private readonly maxRequests: number) {}

  take() {
    this.used += 1;
    if (this.used > this.maxRequests) {
      throw new Error("Scan request budget exceeded");
    }
  }

  count() {
    return this.used;
  }
}

export function normalizeScannerUrl(input: string | URL, base?: URL) {
  const parsed = typeof input === "string" ? new URL(input, base) : input;
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http and https URLs can be scanned");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URLs with embedded credentials are not allowed");
  }
  assertSafeHostname(parsed.hostname);
  if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
    throw new Error("Custom ports are disabled for the MVP scanner");
  }
  parsed.hash = "";
  return parsed;
}

export function normalizeRedirectUrl(location: string, previousUrl: URL) {
  return normalizeScannerUrl(location, previousUrl);
}

async function assertSafeResolvedAddresses(
  url: URL,
  resolveHostname: (hostname: string) => Promise<Array<{ address: string }>> = (hostname) =>
    dns.lookup(hostname, { all: true, verbatim: true })
) {
  if (unsafeHostnameReason(url.hostname)) {
    assertSafeHostname(url.hostname);
  }

  const records = await resolveHostname(url.hostname);
  for (const record of records) {
    assertSafeHostname(record.address);
  }
}

function scannerHeaders(headers?: HeadersInit) {
  const result = new Headers(headers);
  result.delete("cookie");
  result.delete("Cookie");
  return result;
}

async function readBody(response: Response, maxBytes: number, allowTruncate: boolean) {
  if (!response.body) return { text: "", truncated: false };

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (!value) continue;

    total += value.byteLength;
    if (total > maxBytes) {
      if (!allowTruncate) {
        await reader.cancel();
        throw new Error("Response exceeded scanner size limit");
      }

      const remaining = Math.max(0, maxBytes - (total - value.byteLength));
      if (remaining > 0) chunks.push(value.slice(0, remaining));
      truncated = true;
      await reader.cancel();
      break;
    }

    chunks.push(value);
  }

  return {
    text: Buffer.concat(chunks).toString("utf8"),
    truncated
  };
}

export async function safeFetch(
  input: string | URL,
  budget: ScanBudget,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  let currentUrl = normalizeScannerUrl(input);
  const maxRedirects = options.maxRedirects ?? 3;

  for (let redirectCount = 0; redirectCount <= maxRedirects; redirectCount += 1) {
    budget.take();
    await assertSafeResolvedAddresses(currentUrl, options.resolveHostname);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 8000);

    try {
      const response = await (options.fetchImpl ?? fetch)(currentUrl, {
        method: options.method ?? "GET",
        headers: scannerHeaders(options.headers),
        redirect: "manual",
        signal: controller.signal
      });

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("location");
        if (!location) throw new Error("Redirect response did not include a location");
        currentUrl = normalizeRedirectUrl(location, currentUrl);
        continue;
      }

      const body = options.method === "HEAD"
        ? { text: "", truncated: false }
        : await readBody(response, options.maxBytes ?? 900_000, options.allowTruncate ?? false);

      return {
        url: currentUrl.toString(),
        status: response.status,
        ok: response.ok,
        headers: response.headers,
        text: body.text,
        truncated: body.truncated
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  throw new Error("Too many redirects while scanning target");
}
