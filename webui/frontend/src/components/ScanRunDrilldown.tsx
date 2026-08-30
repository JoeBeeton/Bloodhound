import { useState } from "react";
import { Link } from "react-router-dom";
import { groupJobsByModule } from "../lib/scanJobs";
import type { ScanJobStatus, ScanRunDetail } from "../lib/types";

const STATUS_STYLES: Record<string, string> = {
  COMPLETE: "text-neon-cyan",
  FAILED: "text-severity-critical",
  PENDING: "text-slate-500",
  CLAIMED: "text-neon-amber",
  RUNNING: "text-neon-amber",
  // A product review found this component - embedded on the target detail page to show the
  // latest scan's per-module breakdown - had no style for a cancelled job, falling back to the
  // same flat text-slate-400 an unrecognized status gets. text-muted, not PENDING's own
  // text-slate-500, so a cancelled module doesn't read as "still waiting to run".
  CANCELLED: "text-muted",
};

/** The one error detail worth surfacing inline for a module group - the failure that hasn't
 * exhausted its retries yet is still "in progress, might resolve itself" (matches
 * ScanDetailPage's own JobGroupSection convention), so a genuinely FAILED job's message beats
 * one that's merely between retry attempts. */
function representativeFailure(jobs: ScanJobStatus[]): ScanJobStatus | undefined {
  return jobs.find((j) => j.status === "FAILED" && j.errorDetail) ?? jobs.find((j) => j.status === "FAILED");
}

/**
 * A run only "completed" in the loose sense that every module reached a
 * terminal state - PARTIAL_FAILURE means at least one didn't. This is the
 * per-module breakdown showing exactly which ones and why, using
 * scan_jobs.error_detail (populated by the job-failure path since Phase 1
 * Milestone 2, but never surfaced anywhere in the UI until now). Grouped by
 * moduleType (see groupJobsByModule) rather than one row per job - a Tier 2
 * deep scan dispatches one job per host, so a failed 16-host module would
 * otherwise dump 16 near-identical rows into this inline summary.
 */
export function ScanRunDrilldown({ run }: { run: ScanRunDetail }) {
  const [expanded, setExpanded] = useState(false);
  const groups = groupJobsByModule(run.jobs);
  const failedGroups = groups.filter((g) => g.jobs.some((j) => j.status === "FAILED"));
  if (failedGroups.length === 0) {
    return null;
  }

  return (
    <div className="w-full">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="font-mono text-xs uppercase tracking-widest text-severity-critical underline decoration-dotted underline-offset-4 transition hover:text-severity-critical/70"
      >
        {expanded
          ? "Hide details ▴"
          : `Why? (${failedGroups.length} module${failedGroups.length === 1 ? "" : "s"} failed) ▾`}
      </button>
      {expanded && (
        <div className="mt-3 space-y-2 rounded-lg border border-severity-critical/30 bg-void/60 p-4 font-mono text-xs">
          {groups.map((group) => {
            const failedInGroup = group.jobs.filter((j) => j.status === "FAILED");
            const status = failedInGroup.length > 0 ? "FAILED" : group.jobs[0].status;
            const failure = representativeFailure(group.jobs);
            return (
              <div key={group.moduleType} className="border-b border-slate-800 pb-2 last:border-0 last:pb-0">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-300">
                    {group.moduleType}
                    {group.jobs.length > 1 && <span className="text-slate-500"> ({group.jobs.length} hosts)</span>}
                  </span>
                  <span className={STATUS_STYLES[status] ?? "text-slate-400"}>
                    {failedInGroup.length > 0
                      ? group.jobs.length > 1
                        ? `${failedInGroup.length}/${group.jobs.length} FAILED`
                        : "FAILED"
                      : status}
                  </span>
                </div>
                {failure && (
                  <div className="mt-1 text-slate-400">
                    Failed after {failure.attemptCount}/{failure.maxAttempts} attempts
                    {failure.errorDetail ? `: ${failure.errorDetail}` : "."}
                  </div>
                )}
              </div>
            );
          })}
          <Link
            to={`/scans/${run.id}`}
            className="mt-1 inline-block font-mono text-[11px] uppercase tracking-widest text-neon-cyan hover:underline"
          >
            View full attempt history →
          </Link>
        </div>
      )}
    </div>
  );
}
