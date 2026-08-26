import { useState } from "react";
import { Link } from "react-router-dom";
import type { ScanRunDetail } from "../lib/types";

const STATUS_STYLES: Record<string, string> = {
  COMPLETE: "text-neon-cyan",
  FAILED: "text-severity-critical",
  PENDING: "text-slate-500",
  CLAIMED: "text-neon-amber",
  RUNNING: "text-neon-amber",
};

/**
 * A run only "completed" in the loose sense that every module reached a
 * terminal state - PARTIAL_FAILURE means at least one didn't. This is the
 * per-module breakdown showing exactly which ones and why, using
 * scan_jobs.error_detail (populated by the job-failure path since Phase 1
 * Milestone 2, but never surfaced anywhere in the UI until now).
 */
export function ScanRunDrilldown({ run }: { run: ScanRunDetail }) {
  const [expanded, setExpanded] = useState(false);
  const failedJobs = run.jobs.filter((j) => j.status === "FAILED");
  if (failedJobs.length === 0) {
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
          : `Why? (${failedJobs.length} module${failedJobs.length === 1 ? "" : "s"} failed) ▾`}
      </button>
      {expanded && (
        <div className="mt-3 space-y-2 rounded-lg border border-severity-critical/30 bg-void/60 p-4 font-mono text-xs">
          {run.jobs.map((job) => (
            <div key={job.id} className="border-b border-slate-800 pb-2 last:border-0 last:pb-0">
              <div className="flex items-center justify-between gap-3">
                <span className="text-slate-300">{job.moduleType}</span>
                <span className={STATUS_STYLES[job.status] ?? "text-slate-400"}>{job.status}</span>
              </div>
              {job.status === "FAILED" && (
                <div className="mt-1 text-slate-400">
                  Failed after {job.attemptCount}/{job.maxAttempts} attempts
                  {job.errorDetail ? `: ${job.errorDetail}` : "."}
                </div>
              )}
            </div>
          ))}
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
