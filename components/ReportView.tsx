"use client";

import type { EvidenceItem, Finding, FindingDisplayGroup, Remediation, ReportState, ScanReport, Severity } from "@/lib/types";
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
  const statuses = Object.entries(report.scanner.checkStatuses ?? {});
  if (statuses.length) {
    const formatStatus = ([checkId, item]: (typeof statuses)[number]) => {
      const budget =
        typeof item.maxRequests === "number"
          ? ` (${item.requestsUsed}/${item.maxRequests} requests)`
          : item.requestsUsed
            ? ` (${item.requestsUsed} requests)`
            : "";
      const reason = item.reason ? `: ${item.reason}` : "";
      return `${checkId} ${item.status}${budget}${reason}`;
    };
    const completed = statuses.filter(([, item]) => item.status === "completed").map(formatStatus);
    const notSeen = statuses
      .filter(([, item]) => item.status === "skipped" || item.status === "disabled" || item.status === "incomplete")
      .map(formatStatus);

    return {
      checked: completed.length ? completed.join(", ") : "No checks completed",
      couldNotSee: notSeen.length
        ? notSeen.join(", ")
        : "Authenticated areas, private repositories, server-only logs, and any disabled checks."
    };
  }

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
      <p>{remediation.beginnerContext}</p>
      <pre><code>{remediation.snippet}</code></pre>
    </div>
  );
}

function plural(count: number, word: string) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

function findingsMetric(rawCount: number, groupCount: number) {
  return `${plural(rawCount, "finding")} · ${plural(groupCount, "group")}`;
}

function EvidenceDetails({
  id,
  evidence,
  limitation
}: {
  id: string;
  evidence: EvidenceItem[];
  limitation: string;
}) {
  return (
    <details className="finding-details">
      <summary>Evidence and limitation</summary>
      <div className="evidence">
        {evidence.map((item) => (
          <div className="evidence-row" key={`${id}-${item.label}-${item.value}`}>
            <span>{item.label}</span>
            <code>{item.value}</code>
          </div>
        ))}
      </div>
      <p><strong>Limitation:</strong> {limitation}</p>
    </details>
  );
}

function memberEvidence(finding: Finding) {
  const item = finding.evidence[0];
  return item ? `${item.label}: ${item.value}` : finding.reasonCode;
}

function FindingMembers({ group }: { group: FindingDisplayGroup }) {
  return (
    <ul className="finding-members" aria-label={`${group.title} members`}>
      {group.members.map((member) => (
        <li key={member.id}>
          <span>{member.title}</span>
          <code>{memberEvidence(member)}</code>
        </li>
      ))}
    </ul>
  );
}

function IncidentRunbook({
  groups,
  onCopy
}: {
  groups: FindingDisplayGroup[];
  onCopy: (snippet: string) => void;
}) {
  const primaryGroup = groups[0];
  const primary = primaryGroup.representative;
  const isAssessment = (item: Remediation) =>
    item.targetLocation.toLowerCase().includes("logs") ||
    item.snippet.includes("auth.audit_log_entries");
  const stopBleeding = primary.remediations.filter(
    (item) =>
      (item.type === "shell" || item.type === "dashboard_instruction") && !isAssessment(item)
  );
  const assess = primary.remediations.filter(isAssessment);
  const remediate = primary.remediations.filter(
    (item) => item.type === "config" || item.type === "code" || (item.type === "sql" && !isAssessment(item))
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
          <p>
            If active abuse is suspected, rotate or revoke immediately even if downtime happens.
            Otherwise, locate usage first so you can rotate safely.
          </p>
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
      {groups.map((group) => (
        <article className="finding-card compact-finding" key={group.bundleKey}>
          <div className="finding-top">
            <div>
              <h2>{group.title}</h2>
              <p>{group.representative.summary}</p>
            </div>
            <div className="pill-row">
              <span className={`pill ${severityClass[group.severity]}`}>{group.severity}</span>
              <span className="pill">{group.confidence}</span>
              <span className="pill">{plural(group.members.length, "item")}</span>
            </div>
          </div>
          <FindingMembers group={group} />
          <EvidenceDetails id={group.bundleKey} evidence={group.evidence} limitation={group.representative.limitation} />
        </article>
      ))}
    </section>
  );
}

function FixableChecklist({
  groups,
  onCopy
}: {
  groups: FindingDisplayGroup[];
  onCopy: (snippet: string) => void;
}) {
  return (
    <section className="finding-list" aria-label="Fixable findings">
      {groups.map((group) => (
        <article className="finding-card" key={group.bundleKey}>
          <div className="finding-top">
            <div>
              <h2>{group.title}</h2>
              <p>{group.representative.summary}</p>
            </div>
            <div className="pill-row">
              <span className={`pill ${severityClass[group.severity]}`}>{group.severity}</span>
              <span className="pill">{group.confidence}</span>
              <span className="pill">{plural(group.members.length, "item")}</span>
            </div>
          </div>
          <p>{group.representative.explanation}</p>
          <FindingMembers group={group} />
          <div className="remediation-list">
            {group.remediations.map((remediation, index) => (
              <RemediationBlock
                key={`${group.bundleKey}-remediation-${index}`}
                remediation={remediation}
                onCopy={onCopy}
              />
            ))}
          </div>
          <EvidenceDetails id={group.bundleKey} evidence={group.evidence} limitation={group.representative.limitation} />
        </article>
      ))}
    </section>
  );
}

export function ReportView({ report }: { report: ScanReport }) {
  const normalized = normalizeReportForDisplay(report);
  const checks = checkedCopy(normalized);
  const incidentGroups = normalized.displayGroups.filter((group) =>
    group.members.some((finding) => finding.tier === "critical")
  );
  const fixableGroups = normalized.displayGroups.filter((group) =>
    group.members.every((finding) => finding.tier !== "critical")
  );

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
          <span>Hygiene score {normalized.grade} · {normalized.score}/100</span>
        </div>
      </div>

      <section className={`state-panel state-${normalized.state}`} aria-label="Report state summary">
        <p className="eyebrow">State summary</p>
        <h2>{normalized.stateSummary}</h2>
        <p>{normalized.stateReason}</p>
        <p>
          State reflects the most urgent routed finding. Hygiene score is the aggregate of enabled
          checks.
        </p>
      </section>

      <section className="meta-grid" aria-label="Report metadata">
        <div className="metric">
          <span>Mode</span>
          <strong>{normalized.scanner.mode.replace("_", "-")}</strong>
        </div>
        <div className="metric">
          <span>Findings</span>
          <strong>{findingsMetric(normalized.aggregate.findingCount, normalized.displayGroupCount)}</strong>
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
          VibeCheck checks public pages, client bundles, source-map references, exposed
          infrastructure paths, browser security headers, bounded CORS preflights on referenced API
          routes, public API response-shape metadata, and owner-authorized Supabase read/storage
          probes. It does not exploit, mutate, brute force, bypass auth, write to databases, or store
          sensitive target content.
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
          <details>
            <summary>What we could not see</summary>
            <p>{checks.couldNotSee}</p>
          </details>
        </section>
      ) : null}

      {normalized.state === "incident" && incidentGroups.length > 0 ? (
        <IncidentRunbook groups={incidentGroups} onCopy={copySnippet} />
      ) : null}

      {normalized.state === "fixable" || (normalized.state === "incident" && fixableGroups.length > 0) ? (
        <FixableChecklist groups={fixableGroups} onCopy={copySnippet} />
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
