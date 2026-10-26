import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { apiFetch, readErrorMessage } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import { Modal } from "./Modal";
import { ScoreImpactBadge } from "./ScoreImpactBadge";
import type { Finding, OrgFinding, Severity } from "../lib/types";

/**
 * A product review found FindingReconciler's automatic OPEN->RESOLVED transition (fires only
 * once a scan no longer detects an issue) was the only way a finding's status ever changed - a
 * false positive or an accepted-risk finding just sat as OPEN indefinitely, with no way for an
 * analyst to say "reviewed, doesn't need action". Dismiss and Accept Risk are both sticky
 * overrides, honored by FindingReconciler forever until a human explicitly reopens one (see
 * V48__findings_dismissed_status.sql's own comment) - the distinction between them is "not
 * actually an issue" (Dismiss) versus "real, but we're knowingly not acting on it" (Accept
 * Risk), each optionally carrying a free-text reason (see V118__finding_status_reason.sql) so
 * that judgment call isn't lost the moment the button is clicked.
 */
/** Exported for TargetDetailPage's own bulk-dismiss action - same endpoint, fired N times in parallel there (see its own triggerBulkDismiss, mirroring the page's existing triggerBulkScan/triggerBulkRemove pattern) rather than needing a dedicated bulk backend endpoint. No reason on the bulk path - there's no per-finding text input in that flow. */
export async function dismissFinding(id: string, reason?: string): Promise<void> {
  const res = await apiFetch(`/api/v1/findings/${id}/dismiss`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason: reason || null }),
  });
  if (!res.ok) throw new Error(await readErrorMessage(res, "Failed to dismiss finding."));
}

async function acceptRiskFinding(id: string, reason?: string): Promise<void> {
  const res = await apiFetch(`/api/v1/findings/${id}/accept-risk`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason: reason || null }),
  });
  if (!res.ok) throw new Error(await readErrorMessage(res, "Failed to accept risk for finding."));
}

async function reopenFinding(id: string): Promise<void> {
  const res = await apiFetch(`/api/v1/findings/${id}/reopen`, { method: "POST" });
  if (!res.ok) throw new Error(await readErrorMessage(res, "Failed to reopen finding."));
}

/** True for any evidence/affectedAsset value worth rendering as a clickable link rather than
 * plain text - e.g. ExposedPathDecisionLogic's "url" evidence, BucketBruteForceModule's
 * "checkUrl", or ZapAlertMapper/NucleiFindingMapper's affectedAsset (both set it to the exact
 * URL the alert/match came from, not just a bare hostname). Every such value here is a URL this
 * app's own worker constructed and requested against an already-tracked target, not arbitrary
 * attacker text, and the http(s):// prefix check rules out a javascript: URI. */
function isLinkableUrl(value: unknown): value is string {
  return typeof value === "string" && /^https?:\/\//.test(value);
}

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
  const { user } = useAuth();
  const canDismiss = user?.role === "ADMIN" || user?.role === "ANALYST";
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");

  // Findings are shown from 5+ different pages (target detail, subdomain detail, dashboard,
  // the org-wide Findings page, scan detail) each with their own query key prefix - a broad
  // predicate match rather than enumerating every one keeps this working regardless of which
  // page opened this modal, and doesn't need updating if a future page adds it too.
  function invalidateAnyFindingsQuery() {
    queryClient.invalidateQueries({
      predicate: (query) => typeof query.queryKey[0] === "string" && query.queryKey[0].toLowerCase().includes("finding"),
    });
  }

  const dismissMutation = useMutation({
    mutationFn: () => dismissFinding(finding.id, reason),
    onSuccess: () => {
      invalidateAnyFindingsQuery();
      onClose(); // the finding prop is a snapshot passed in by the caller - it won't reflect the
      // new status on its own, and this modal has no live subscription of its own to refresh it in
      // place, so closing (onto the now-invalidated, refetching list behind it) is the simplest
      // way to avoid showing a stale status label.
    },
  });

  const acceptRiskMutation = useMutation({
    mutationFn: () => acceptRiskFinding(finding.id, reason),
    onSuccess: () => {
      invalidateAnyFindingsQuery();
      onClose();
    },
  });

  const reopenMutation = useMutation({
    mutationFn: () => reopenFinding(finding.id),
    onSuccess: () => {
      invalidateAnyFindingsQuery();
      onClose();
    },
  });

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
        {canDismiss && finding.status === "OPEN" && (
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => dismissMutation.mutate()}
              disabled={dismissMutation.isPending || acceptRiskMutation.isPending}
              className="rounded border border-slate-700 px-3 py-1 font-mono text-xs uppercase tracking-widest text-slate-300 transition hover:border-neon-cyan/50 hover:text-neon-cyan disabled:opacity-50"
            >
              {dismissMutation.isPending ? "Dismissing…" : "Dismiss"}
            </button>
            <button
              onClick={() => acceptRiskMutation.mutate()}
              disabled={dismissMutation.isPending || acceptRiskMutation.isPending}
              className="rounded border border-slate-700 px-3 py-1 font-mono text-xs uppercase tracking-widest text-slate-300 transition hover:border-neon-amber/50 hover:text-neon-amber disabled:opacity-50"
            >
              {acceptRiskMutation.isPending ? "Accepting…" : "Accept Risk"}
            </button>
          </div>
        )}
        {canDismiss && (finding.status === "DISMISSED" || finding.status === "ACCEPTED_RISK") && (
          <button
            onClick={() => reopenMutation.mutate()}
            disabled={reopenMutation.isPending}
            className="ml-auto rounded border border-slate-700 px-3 py-1 font-mono text-xs uppercase tracking-widest text-slate-300 transition hover:border-neon-cyan/50 hover:text-neon-cyan disabled:opacity-50"
          >
            {reopenMutation.isPending ? "Reopening…" : "Reopen"}
          </button>
        )}
      </div>
      {canDismiss && finding.status === "OPEN" && (
        <div className="mb-4">
          <label htmlFor="finding-status-reason" className="mb-1 block font-mono text-[10px] uppercase tracking-widest text-slate-500">
            Reason (optional - shown on the finding if dismissed or risk-accepted)
          </label>
          <input
            id="finding-status-reason"
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="e.g. false positive, third-party infrastructure"
            className="w-full rounded border border-slate-700 bg-void/60 px-2 py-1 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-neon-cyan/50 focus:outline-none"
          />
        </div>
      )}
      {finding.statusReason && (finding.status === "DISMISSED" || finding.status === "ACCEPTED_RISK") && (
        <p className="mb-4 font-mono text-xs text-slate-400">
          <span className="uppercase tracking-widest text-slate-500">Reason: </span>
          {finding.statusReason}
        </p>
      )}
      {(dismissMutation.isError || acceptRiskMutation.isError || reopenMutation.isError) && (
        <p role="alert" className="mb-4 font-mono text-xs text-severity-critical">
          {((dismissMutation.error ?? acceptRiskMutation.error ?? reopenMutation.error) as Error)?.message ??
            "Failed to update finding status."}
        </p>
      )}

      <p className="mb-4 text-sm leading-relaxed text-slate-300">{finding.description}</p>

      <div className="mb-4 grid grid-cols-2 gap-3 rounded border border-slate-800 bg-void/40 p-3 sm:grid-cols-3">
        <Field label="Finding ID">{finding.displayId}</Field>
        <Field label="Rule ID">{finding.ruleId}</Field>
        <Field label="Module">{finding.moduleType}</Field>
        <Field label="Affected asset">
          {isLinkableUrl(finding.affectedAsset) ? (
            <a
              href={finding.affectedAsset}
              target="_blank"
              rel="noopener noreferrer"
              className="text-neon-cyan hover:underline"
            >
              {finding.affectedAsset}
            </a>
          ) : (
            finding.affectedAsset
          )}
        </Field>
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
                {cve.cveId} <span className="text-muted">via {cve.source}</span>
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
                  {isLinkableUrl(value) ? (
                    <a href={value} target="_blank" rel="noopener noreferrer" className="text-neon-cyan hover:underline">
                      {value}
                    </a>
                  ) : typeof value === "object" ? (
                    JSON.stringify(value)
                  ) : (
                    String(value)
                  )}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </Modal>
  );
}
