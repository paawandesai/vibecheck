"use client";

import type { Finding, Remediation, ReportState, ScanReport, Severity } from "@/lib/types";
import { normalizeReportForDisplay } from "@/lib/report/classification";
import { WaitlistForm } from "@/components/WaitlistForm";

const severityClass: Record<Severity, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info"
};

const stateLabel: Record<ReportState, string> = {
  clean: "Clean on visible surfaces",
  fixable: "Fixable",
  incident: "Incident runbook",
  incomplete: "Incomplete"
};

async function record(name: "share_clicked", reportId: string) {
  await fetch("/api/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, reportId })
  }).catch(() => undefined);
}

function checkedCopy(report: ScanReport) {
  const skipped = [
    ...(report.scanner.checksSkipped ?? []),
    ...(report.scanner.checksDisabled ?? []).map((check) => `${check} disabled`)
  ];
  return {
    checked: report.scanner.checksRun?.length
      ? report.scanner.checksRun.join(", ")
      : "No checks completed",
    couldNotSee: skipped.length
      ? skipped.join(", ")
      : "Authenticated areas, private repositories, server-only logs, and any disabled checks."
  };
}

function remediationLabel(remediation: Remediation) {
  if (remediation.type === "dashboard_instruction") return "Dashboard";
  return remediation.type;
}

function RemediationBlock({
  remediation,
  onCopy
}: {
  remediation: Remediation;
  onCopy: (snippet: string) => void;
}) {
  return (
    <div className="remediation">
      <div className="remediation-top">
        <div>
          <span className="pill">{remediationLabel(remediation)}</span>
          <strong>{remediation.targetLocation}</strong>
        </div>
        <button className="secondary-button compact-button" type="button" onClick={() => onCopy(remediation.snippet)}>
          Copy fix
        </button>
      </div>
      {remediation.beginnerContext ? <p>{remediation.beginnerContext}</p> : null}
      <pre><code>{remediation.snippet}</code></pre>
    </div>
  );
}

function FindingEvidence({ finding }: { finding: Finding }) {
  return (
    <details className="finding-details">
      <summary>Evidence and limitation</summary>
      <div className="evidence">
        {finding.evidence.map((item) => (
          <div className="evidence-row" key={`${finding.id}-${item.label}`}>
            <span>{item.label}</span>
            <code>{item.value}</code>
          </div>
        ))}
      </div>
      <p><strong>Limitation:</strong> {finding.limitation}</p>
    </details>
  );
}

function IncidentRunbook({
  findings,
  onCopy
}: {
  findings: Finding[];
  onCopy: (snippet: string) => void;
}) {
  const primary = findings[0];
  const stopBleeding = primary.remediations.filter(
    (item) => item.type === "shell" || item.type === "dashboard_instruction"
  );
  const assess = primary.remediations.filter((item) => item.type === "sql");
  const remediate = primary.remediations.filter(
    (item) => item.type === "config" || item.type === "code"
  );

  return (
    <section className="runbook state-incident" aria-label="Incident runbook">
      <div className="runbook-heading">
        <p className="eyebrow">State 3</p>
        <h2>Incident runbook</h2>
        <p>
          {primary.title}. {primary.explanation}
        </p>
      </div>
      <ol className="runbook-steps">
        <li>
          <h3>Stop the bleeding</h3>
          <p>Find where the key or exposure is used before deleting anything, then rotate it safely.</p>
          {stopBleeding.map((remediation, index) => (
            <RemediationBlock
              key={`${primary.id}-stop-${index}`}
              remediation={remediation}
              onCopy={onCopy}
            />
          ))}
        </li>
        <li>
          <h3>Assess blast radius</h3>
          <p>Review logs from the suspected exposure window. Look for IP addresses, endpoints, or access patterns you do not recognize.</p>
          {assess.map((remediation, index) => (
            <RemediationBlock
              key={`${primary.id}-assess-${index}`}
              remediation={remediation}
              onCopy={onCopy}
            />
          ))}
        </li>
        <li>
          <h3>Remediate</h3>
          <p>Move privileged access behind server code, redeploy, revoke the exposed value, and rescan.</p>
          {remediate.map((remediation, index) => (
            <RemediationBlock
              key={`${primary.id}-remediate-${index}`}
              remediation={remediation}
              onCopy={onCopy}
            />
          ))}
        </li>
      </ol>
      {findings.map((finding) => (
        <article className="finding-card compact-finding" key={finding.id}>
          <div className="finding-top">
            <div>
              <h2>{finding.title}</h2>
              <p>{finding.summary}</p>
            </div>
            <div className="pill-row">
              <span className={`pill ${severityClass[finding.severity]}`}>{finding.severity}</span>
              <span className="pill">{finding.confidence}</span>
            </div>
          </div>
          <FindingEvidence finding={finding} />
        </article>
      ))}
    </section>
  );
}

function FixableChecklist({
  findings,
  onCopy
}: {
  findings: Finding[];
  onCopy: (snippet: string) => void;
}) {
  return (
    <section className="finding-list" aria-label="Fixable findings">
      {findings.map((finding) => (
        <article className="finding-card" key={finding.id}>
          <div className="finding-top">
            <div>
              <h2>{finding.title}</h2>
              <p>{finding.summary}</p>
            </div>
            <div className="pill-row">
              <span className={`pill ${severityClass[finding.severity]}`}>{finding.severity}</span>
              <span className="pill">{finding.confidence}</span>
            </div>
          </div>
          <p>{finding.explanation}</p>
          <div className="remediation-list">
            {finding.remediations.map((remediation, index) => (
              <RemediationBlock
                key={`${finding.id}-remediation-${index}`}
                remediation={remediation}
                onCopy={onCopy}
              />
            ))}
          </div>
          <FindingEvidence finding={finding} />
        </article>
      ))}
    </section>
  );
}

export function ReportView({ report }: { report: ScanReport }) {
  const normalized = normalizeReportForDisplay(report);
  const checks = checkedCopy(normalized);
  const incidentFindings = normalized.findings.filter((finding) => finding.tier === "critical");
  const fixableFindings = normalized.findings.filter((finding) => finding.tier !== "critical");

  async function copyShareLink() {
    await navigator.clipboard.writeText(window.location.href);
    await record("share_clicked", normalized.id);
  }

  async function copySnippet(snippet: string) {
    await navigator.clipboard.writeText(snippet);
  }

  return (
    <div className="report-shell">
      <div className="report-title">
        <div>
          <p className="eyebrow">Scanned with VibeCheck</p>
          <h1>{stateLabel[normalized.state]}</h1>
          <p className="lede">{normalized.targetOrigin}</p>
        </div>
        <div className={`state-badge state-${normalized.state}`} aria-label={`Report state ${stateLabel[normalized.state]}`}>
          <strong>{stateLabel[normalized.state]}</strong>
          <span>{normalized.grade} · {normalized.score}/100</span>
        </div>
      </div>

      <section className={`state-panel state-${normalized.state}`} aria-label="Report state summary">
        <p className="eyebrow">State summary</p>
        <h2>{normalized.stateSummary}</h2>
        <p>{normalized.stateReason}</p>
      </section>

      <section className="meta-grid" aria-label="Report metadata">
        <div className="metric">
          <span>Mode</span>
          <strong>{normalized.scanner.mode.replace("_", "-")}</strong>
        </div>
        <div className="metric">
          <span>Findings</span>
          <strong>{normalized.findings.length}</strong>
        </div>
        <div className="metric">
          <span>Requests</span>
          <strong>
            {normalized.scanner.requestCount}
            {normalized.scanner.requestBudget ? `/${normalized.scanner.requestBudget}` : ""}
          </strong>
        </div>
        <div className="metric">
          <span>Created</span>
          <strong>{new Date(normalized.createdAt).toLocaleString()}</strong>
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

      {normalized.state === "clean" ? (
        <section className="empty-state state-clean" aria-label="Clean report details">
          <h2>No findings on visible surfaces</h2>
          <p>
            The enabled checks did not find client-bundle secrets, public source maps, exposed
            infrastructure, unsafe CORS, public API shape risk, weak security headers, or authorized
            Supabase anonymous-read risk.
          </p>
          <details open>
            <summary>What we checked</summary>
            <p>{checks.checked}</p>
          </details>
          <details>
            <summary>What we could not see</summary>
            <p>{checks.couldNotSee}</p>
          </details>
        </section>
      ) : null}

      {normalized.state === "incomplete" ? (
        <section className="empty-state state-incomplete" aria-label="Incomplete report details">
          <h2>The scan did not finish</h2>
          <p>
            Do not treat this as clean. Retry after the limit or network issue clears, or reduce
            disabled checks only if you are intentionally narrowing the scan.
          </p>
          <details open>
            <summary>What completed before stopping</summary>
            <p>{checks.checked}</p>
          </details>
        </section>
      ) : null}

      {normalized.state === "incident" && incidentFindings.length > 0 ? (
        <IncidentRunbook findings={incidentFindings} onCopy={copySnippet} />
      ) : null}

      {normalized.state === "fixable" || (normalized.state === "incident" && fixableFindings.length > 0) ? (
        <FixableChecklist findings={fixableFindings} onCopy={copySnippet} />
      ) : null}

      <section className="empty-state" aria-label="Checks run">
        <details>
          <summary>What we checked</summary>
          <p>{checks.checked}</p>
        </details>
        <details>
          <summary>What we could not see</summary>
          <p>{checks.couldNotSee}</p>
        </details>
      </section>

      <section className="cta-row" aria-label="Conversion actions">
        <div>
          <h2>Want this on every deploy?</h2>
          <p>
            Reserve early access for deploy-time rescans and alerts when something leaks.
          </p>
          <WaitlistForm reportId={normalized.id} />
        </div>
        <div className="pill-row">
          <button className="secondary-button" type="button" onClick={copyShareLink}>
            Copy share link
          </button>
        </div>
      </section>
    </div>
  );
}
