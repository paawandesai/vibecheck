"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export function ScanForm() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [authorizedSupabaseProbe, setAuthorizedSupabaseProbe] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState("");

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsScanning(true);
    setError("");

    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, authorizedSupabaseProbe })
    });
    const payload = (await response.json()) as { reportUrl?: string; error?: string };
    setIsScanning(false);

    if (!response.ok || !payload.reportUrl) {
      setError(payload.error ?? "Scan failed. Check the URL and try again.");
      return;
    }

    router.push(payload.reportUrl);
  }

  return (
    <section className="scan-panel" aria-labelledby="scan-heading">
      <h2 id="scan-heading">Paste your app URL</h2>
      <form className="scan-form" onSubmit={onSubmit}>
        <label className="field-label">
          Deployed URL
          <div className="input-row">
            <input
              type="url"
              required
              placeholder="https://your-app.vercel.app"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
            />
            <button className="primary-button" type="submit" disabled={isScanning}>
              {isScanning ? "Scanning..." : "Scan free"}
            </button>
          </div>
        </label>

        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={authorizedSupabaseProbe}
            onChange={(event) => setAuthorizedSupabaseProbe(event.target.checked)}
          />
          <span>
            I own this app or have explicit permission to test it. Run owner-authorized Supabase
            read/storage checks using bounded HEAD/count-style probes without fetching rows or
            object contents.
          </span>
        </label>

        <p className="scan-note">
          VibeCheck blocks private-network targets and stores redacted evidence only.
        </p>
        {error ? <p className="form-error">{error}</p> : null}
      </form>
    </section>
  );
}
