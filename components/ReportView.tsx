"use client";

import type { ScanReport, Severity } from "@/lib/types";
import { WaitlistForm } from "@/components/WaitlistForm";

const severityClass: Record<Severity, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info"
};

async function record(name: "share_clicked" | "stripe_clicked", reportId: string) {
  await fetch("/api/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, reportId })
  }).catch(() => undefined);
}

export function ReportView({ report, stripeLink }: { report: ScanReport; stripeLink?: string }) {
  async function copyShareLink() {
    await navigator.clipboard.writeText(window.location.href);
    await record("share_clicked", report.id);
  }

  return (
    <div className="report-shell">
      <div className="report-title">
        <div>
          <p className="eyebrow">Scanned with VibeCheck</p>
          <h1>Security report</h1>
          <p className="lede">{report.targetOrigin}</p>
        </div>
        <div className="grade" aria-label={`Overall grade ${report.grade}`}>
          <strong>{report.grade}</strong>
          <span>{report.score}/100</span>
        </div>
      </div>

      <section className="meta-grid" aria-label="Report metadata">
        <div className="metric">
          <span>Mode</span>
          <strong>{report.scanner.mode.replace("_", "-")}</strong>
        </div>
        <div className="metric">
          <span>Findings</span>
          <strong>{report.findings.length}</strong>
        </div>
        <div className="metric">
          <span>Requests</span>
          <strong>{report.scanner.requestCount}</strong>
        </div>
        <div className="metric">
          <span>Created</span>
          <strong>{new Date(report.createdAt).toLocaleString()}</strong>
        </div>
      </section>

      <section className="empty-state">
        <strong>What this scan does and does not do</strong>
        <p>
          VibeCheck performs limited, read-only checks against public app surfaces. It does not
          exploit, mutate, brute force, bypass auth, write to databases, or store sensitive target
          content.
        </p>
      </section>

      <section className="finding-list" aria-label="Findings">
        {report.findings.length === 0 ? (
          <article className="finding-card">
            <h2>No findings from the v1 checks</h2>
            <p>
              The locked MVP checks did not find client-bundle secrets, publicly accessible source
              maps, or authorized Supabase anonymous-read risk.
            </p>
          </article>
        ) : (
          report.findings.map((finding) => (
            <article className="finding-card" key={finding.id}>
              <div className="finding-top">
                <div>
                  <h2>{finding.title}</h2>
                  <p>{finding.summary}</p>
                </div>
                <div className="pill-row">
                  <span className={`pill ${severityClass[finding.severity]}`}>
                    {finding.severity}
                  </span>
                  <span className="pill">{finding.confidence}</span>
                </div>
              </div>

              <p>{finding.explanation}</p>
              <div className="evidence">
                {finding.evidence.map((item) => (
                  <div className="evidence-row" key={`${finding.id}-${item.label}`}>
                    <span>{item.label}</span>
                    <code>{item.value}</code>
                  </div>
                ))}
              </div>

              <p><strong>Limitation:</strong> {finding.limitation}</p>
              <div className="prompt-grid">
                {Object.entries(finding.fixPrompts).map(([builder, prompt]) => (
                  <div className="prompt" key={`${finding.id}-${builder}`}>
                    <h3>{builder}</h3>
                    <p>{prompt}</p>
                  </div>
                ))}
              </div>
            </article>
          ))
        )}
      </section>

      <section className="cta-row" aria-label="Conversion actions">
        <div>
          <h2>Want this on every deploy?</h2>
          <p>
            Reserve early access for deploy-time rescans and alerts when something leaks.
          </p>
          <WaitlistForm reportId={report.id} />
        </div>
        <div className="pill-row">
          <button className="secondary-button" type="button" onClick={copyShareLink}>
            Copy share link
          </button>
          {stripeLink ? (
            <a
              className="secondary-button"
              href={stripeLink}
              onClick={() => void record("stripe_clicked", report.id)}
            >
              Founding member
            </a>
          ) : null}
        </div>
      </section>
    </div>
  );
}
