import { ScanForm } from "@/components/ScanForm";

export default function HomePage() {
  return (
    <main>
      <section className="hero-band">
        <div className="hero-grid">
          <div className="hero-copy">
            <p className="eyebrow">60-second security report</p>
            <h1>VibeCheck</h1>
            <p className="lede">
              Paste your vibe-coded app URL and get a read-only public-surface report with
              redacted evidence, grouped findings, confidence labels, and copy-paste fixes.
            </p>
          </div>
          <ScanForm />
        </div>
      </section>

      <section className="trust-band" aria-label="Scanner safety statement">
        <div className="trust-grid">
          <article>
            <h2>Read-only by design</h2>
            <p>
              VibeCheck checks public pages, client bundles, source-map references, exposed
              infrastructure paths, headers, bounded CORS preflights on referenced APIs, public
              schema/debug routes, Firebase web config, client hydration payloads, and
              owner-authorized Supabase read/storage probes.
            </p>
          </article>
          <article>
            <h2>Modern leak coverage</h2>
            <p>
              It looks for exposed AI-era secrets, over-fetched client data, public OpenAPI or
              GraphQL surfaces, weak browser defenses, and access-control self-check signals,
              including client_data_exposure, debug_schema_surface, and firebase_config findings.
            </p>
          </article>
          <article>
            <h2>Evidence stays redacted</h2>
            <p>
              Reports store fingerprints and sanitized metadata, not raw secrets, source maps,
              source code, database rows, cookies, sensitive query strings, or raw PII samples.
            </p>
          </article>
        </div>
      </section>
    </main>
  );
}
