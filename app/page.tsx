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
              Paste your vibe-coded app URL and get a read-only report with redacted evidence,
              confidence labels, and copy-paste fixes.
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
              infrastructure paths, headers, bounded CORS preflights on referenced APIs, public API
              shape metadata, and owner-authorized Supabase read/storage probes.
            </p>
          </article>
          <article>
            <h2>Bounded deep checks</h2>
            <p>
              It does not exploit, mutate, brute force, bypass auth, write to databases, or fetch
              database rows and object contents. Bounded checks beat noisy claims.
            </p>
          </article>
          <article>
            <h2>Evidence stays redacted</h2>
            <p>
              Reports store fingerprints and sanitized metadata, not raw secrets, source maps,
              source code, database rows, cookies, or sensitive query strings.
            </p>
          </article>
        </div>
      </section>
    </main>
  );
}
