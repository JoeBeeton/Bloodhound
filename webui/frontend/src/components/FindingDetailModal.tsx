import { Modal } from "./Modal";
import { ScoreImpactBadge } from "./ScoreImpactBadge";
import type { Finding, OrgFinding, Severity } from "../lib/types";

const SEVERITY_TEXT: Record<Severity, string> = {
  CRITICAL: "text-severity-critical",
  HIGH: "text-severity-high",
  MEDIUM: "text-severity-medium",
  LOW: "text-severity-low",
  INFO: "text-severity-info",
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="font-mono text-[10px] uppercase tracking-widest text-slate-500">{label}</p>
      <div className="mt-0.5 break-all font-mono text-xs text-slate-200">{children}</div>
    </div>
  );
}

function formatDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

/**
 * Full detail for a single finding, opened by clicking any finding card anywhere in the
 * app (target detail, subdomain detail, dashboard top-findings widget). Accepts either
 * Finding or OrgFinding (the org-wide widget's shape carries an extra targetHostname but
 * is otherwise identical) so one component works everywhere findings are rendered.
 */
export function FindingDetailModal({ finding, onClose }: { finding: Finding | OrgFinding; onClose: () => void }) {
  const evidenceEntries = Object.entries(finding.evidence ?? {}).filter(
    ([key]) => key !== "contributingFindings" && key !== "cveDetails",
  );
  // CompoundRiskAnalysisService puts a structured list of the specific findings a compound
  // finding was derived from under this evidence key - rendered as its own labeled section
  // below instead of raw JSON, since "which findings is this based on" is the whole point
  // of a compound finding, not incidental evidence.
  const contributingFindings = finding.evidence?.contributingFindings as
    | Array<{ findingId: string; ruleId: string; severity: string; affectedAsset: string }>
    | undefined;
  // VulnerabilityCorrelationScheduler embeds real CVE descriptions (from osv.dev) here for
  // TECH_KNOWN_CVE/TECH_KNOWN_EXPLOITED_VULNERABILITY findings - rendered as readable prose
  // below rather than buried in the raw evidence dump, since "what actually is this CVE" is
  // the point of the finding. A CVE with no OSV entry is simply absent from this array.
  const cveDetails = finding.evidence?.cveDetails as
    | Array<{ cveId: string; description: string; source: string }>
    | undefined;

  return (
    <Modal title={finding.title} onClose={onClose} wide>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <span className={`font-mono text-xs font-bold uppercase tracking-widest ${SEVERITY_TEXT[finding.severity]}`}>
          {finding.severity}
        </span>
        <span className="font-mono text-xs uppercase tracking-widest text-slate-400">{finding.category}</span>
        <span className="font-mono text-xs uppercase tracking-widest text-slate-500">{finding.status}</span>
        {finding.category === "COMPOUND" && (
          <span className="rounded border border-neon-magenta/50 px-1 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-neon-magenta">
            Chain
          </span>
        )}
        <ScoreImpactBadge impact={finding.scoreImpact} />
      </div>

      <p className="mb-4 text-sm leading-relaxed text-slate-300">{finding.description}</p>

      <div className="mb-4 grid grid-cols-2 gap-3 rounded border border-slate-800 bg-void/40 p-3 sm:grid-cols-3">
        <Field label="Finding ID">{finding.displayId}</Field>
        <Field label="Rule ID">{finding.ruleId}</Field>
        <Field label="Module">{finding.moduleType}</Field>
        <Field label="Affected asset">{finding.affectedAsset}</Field>
        {"targetHostname" in finding && <Field label="Target">{finding.targetHostname}</Field>}
        <Field label="First seen">{formatDate(finding.firstSeenAt)}</Field>
        <Field label="Last seen">{formatDate(finding.lastSeenAt)}</Field>
      </div>

      {finding.remediationAdvice && (
        <div className="mb-4 rounded border border-neon-cyan/20 bg-neon-cyan/5 p-3">
          <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-neon-cyan">Remediation</p>
          <p className="text-sm text-slate-200">{finding.remediationAdvice}</p>
        </div>
      )}

      {cveDetails && cveDetails.length > 0 && (
        <div className="mb-4 space-y-3">
          {cveDetails.map((cve) => (
            <div key={cve.cveId} className="rounded border border-slate-800 bg-void/40 p-3">
              <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-slate-400">
                {cve.cveId} <span className="text-slate-600">via {cve.source}</span>
              </p>
              <p className="text-sm leading-relaxed text-slate-300">{cve.description}</p>
            </div>
          ))}
        </div>
      )}

      {contributingFindings && contributingFindings.length > 0 && (
        <div className="mb-4 rounded border border-neon-magenta/20 bg-neon-magenta/5 p-3">
          <p className="mb-2 font-mono text-[10px] uppercase tracking-widest text-neon-magenta">
            Based on {contributingFindings.length} contributing findings
          </p>
          <div className="space-y-1.5">
            {contributingFindings.map((cf) => (
              <div key={cf.findingId} className="flex flex-wrap items-center gap-2 font-mono text-xs">
                <span className={SEVERITY_TEXT[cf.severity as Severity] ?? "text-slate-300"}>{cf.severity}</span>
                <span className="text-slate-200">{cf.ruleId}</span>
                <span className="text-slate-500">on</span>
                <span className="break-all text-slate-400">{cf.affectedAsset}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {evidenceEntries.length > 0 && (
        <div>
          <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-slate-500">Evidence</p>
          <dl className="space-y-1 rounded border border-slate-800 bg-void/60 p-3">
            {evidenceEntries.map(([key, value]) => (
              <div key={key} className="flex gap-2 font-mono text-xs">
                <dt className="shrink-0 text-slate-500">{key}:</dt>
                <dd className="break-all text-slate-300">
                  {typeof value === "object" ? JSON.stringify(value) : String(value)}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </Modal>
  );
}
