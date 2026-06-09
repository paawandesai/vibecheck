import assert from "node:assert/strict";
import test from "node:test";
import { normalizeRedirectUrl, normalizeScannerUrl } from "@/lib/scanner/safeFetch";
import { unsafeHostnameReason } from "@/lib/scanner/ip";

test("blocks localhost and private network targets", () => {
  const blocked = [
    "http://localhost",
    "http://localhost:3000",
    "http://127.0.0.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.1.1",
    "http://169.254.169.254",
    "http://[::1]",
    "http://[::ffff:127.0.0.1]"
  ];

  for (const url of blocked) {
    assert.throws(() => normalizeScannerUrl(url), /Blocked unsafe target|Invalid URL/);
  }
});

test("blocks non-http protocols, credentials, and custom ports", () => {
  assert.throws(() => normalizeScannerUrl("file:///etc/passwd"), /Only http and https/);
  assert.throws(() => normalizeScannerUrl("ftp://example.com"), /Only http and https/);
  assert.throws(() => normalizeScannerUrl("https://user:pass@example.com"), /embedded credentials/);
  assert.throws(() => normalizeScannerUrl("https://example.com:8443"), /Custom ports/);
});

test("validates redirect targets before following them", () => {
  const previous = new URL("https://example.com");
  assert.throws(() => normalizeRedirectUrl("http://127.0.0.1/admin", previous), /Blocked unsafe/);
  assert.equal(normalizeRedirectUrl("/next", previous).toString(), "https://example.com/next");
});

test("classifies direct unsafe hostnames", () => {
  assert.equal(unsafeHostnameReason("metadata.google.internal"), "local or metadata hostname");
  assert.equal(unsafeHostnameReason("example.com"), null);
});
