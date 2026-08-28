import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { CenteredState } from "../components/CenteredState";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { moduleLabel } from "../lib/moduleLabel";
import type { ScanJobAttempt, ScanJobStatus, ScanRunDetail } from "../lib/types";

async function fetchRun(runId: string): Promise<ScanRunDetail> {
  const res = await apiFetch(`/api/v1/runs/${runId}`);
  if (!res.ok) throw new Error("Failed to load scan.");
  return res.json();
}

const RUN_STATUS_STYLES: Record<string, string> = {
  RUNNING: "text-neon-amber",
  COMPLETE: "text-neon-cyan",
  PARTIAL_FAILURE: "text-severity-critical",
};

const JOB_STATUS_STYLES: Record<string, string> = {
  PENDING: "text-slate-500",
  CLAIMED: "text-neon-amber",
  RUNNING: "text-neon-amber",
  COMPLETE: "text-neon-cyan",
  FAILED: "text-severity-critical",
};

const OUTCOME_STYLES: Record<string, string> = {
  SUCCESS: "text-neon-cyan",
  FAILED: "text-severity-critical",
  TIMED_OUT_REAPED: "text-neon-amber",
};

function formatDuration(startedAt: string, endedAt: string | null): string {
  const end = endedAt ? new Date(endedAt).getTime() : Date.now();
  const seconds = Math.max(0, Math.round((end - new Date(startedAt).getTime()) / 1000));
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

/** Every attempt this job ever made, oldest first - not just the final error scan_jobs.error_detail carries. */
function AttemptHistory({ attempts }: { attempts: ScanJobAttempt[] }) {
  if (attempts.length === 0) {
    return <p className="mt-1 font-mono text-[11px] text-slate-600">Not yet claimed by a worker.</p>;
  }
  return (
    <div className="mt-2 space-y-1.5 border-l-2 border-slate-800 pl-3">
      {attempts.map((a) => (
        <div key={a.attemptNumber} className="font-mono text-[11px]">
          <div className="flex items-center gap-2">
            <span className="text-slate-500">#{a.attemptNumber}</span>
            <span className="text-slate-400">{a.claimedBy}</span>
            <span className="text-slate-600">{formatDuration(a.startedAt, a.endedAt)}</span>
            <span className={a.outcome ? OUTCOME_STYLES[a.outcome] ?? "text-slate-400" : "text-neon-amber animate-pulse"}>
              {a.outcome ?? "IN PROGRESS"}
            </span>
          </div>
          {a.errorDetail && <p className="mt-0.5 text-slate-500">{a.errorDetail}</p>}
        </div>
      ))}
    </div>
  );
}

interface JobGroup {
  moduleType: string;
  jobs: ScanJobStatus[];
}

/** Tier 2 dispatches one job per authorized host (see ScanRunService#createDeepScan) - a
 * 15-subdomain target's deep scan is 3 modules * 16 hosts = 48 flat rows, which is unreadable
 * as one undifferentiated list. Tier 1's one-job-per-module scans (the common case) stay
 * completely unaffected: a group of size 1 renders exactly as a bare JobRow always has. */
export function groupJobsByModule(jobs: ScanJobStatus[]): JobGroup[] {
  const byType = new Map<string, ScanJobStatus[]>();
  for (const j of jobs) {
    const list = byType.get(j.moduleType) ?? [];
    list.push(j);
    byType.set(j.moduleType, list);
  }
  return Array.from(byType.entries()).map(([moduleType, groupJobs]) => ({ moduleType, jobs: groupJobs }));
}

function JobGroupSection({ group }: { group: JobGroup }) {
  const failedCount = group.jobs.filter((j) => j.status === "FAILED").length;
  const doneCount = group.jobs.filter((j) => j.status === "COMPLETE" || j.status === "FAILED").length;
  // Nothing to review by default when every host in this module cleanly succeeded - the
  // analyst's attention belongs on groups with something still running or gone wrong. Keyed by
  // moduleType (stable across this page's 3s poll while RUNNING) so a manual toggle sticks.
  const [collapsed, setCollapsed] = useState(() => failedCount === 0 && doneCount === group.jobs.length);
  return (
    <div className="border-b border-slate-800 py-3 last:border-0">
      <button onClick={() => setCollapsed((v) => !v)} className="flex w-full items-center justify-between gap-3 text-left">
        <span className="font-mono text-sm text-slate-200">
          {moduleLabel(group.moduleType)}
          <span className="ml-2 text-xs text-slate-500">{collapsed ? "▸" : "▾"}</span>
        </span>
        <span
          className={`font-mono text-xs uppercase tracking-widest ${
            failedCount > 0 ? "text-severity-critical" : doneCount === group.jobs.length ? "text-neon-cyan" : "text-neon-amber"
          }`}
        >
          {doneCount}/{group.jobs.length} complete
          {failedCount > 0 && ` · ${failedCount} failed`}
        </span>
      </button>
      {!collapsed && (
        <div className="mt-1 border-l-2 border-slate-800 pl-3">
          {group.jobs.map((job) => (
            <JobRow key={job.id} job={job} />
          ))}
        </div>
      )}
    </div>
  );
}

function JobRow({ job }: { job: ScanJobStatus }) {
  // A clean single-attempt success doesn't need its history spelled out - only jobs that
  // actually had something happen (a retry, a failure, more than one attempt) show it.
  const worthShowingHistory = job.attempts.length > 1 || job.status === "FAILED" || job.attempts.some((a) => a.outcome === "TIMED_OUT_REAPED");
  return (
    <div className="border-b border-slate-800 py-3 last:border-0">
      <div className="flex items-center justify-between gap-3">
        <span className="font-mono text-sm text-slate-200">
          {moduleLabel(job.moduleType)}
          {job.host && <span className="ml-2 text-xs text-neon-cyan/70">{job.host}</span>}
        </span>
        <span className={`font-mono text-xs uppercase tracking-widest ${JOB_STATUS_STYLES[job.status] ?? "text-slate-400"}`}>
          {job.status}
          {job.attemptCount > 0 && ` · ${job.attemptCount}/${job.maxAttempts} attempts`}
        </span>
      </div>
      {job.status === "FAILED" && job.errorDetail && (
        <p className="mt-1 font-mono text-[11px] text-severity-critical">{job.errorDetail}</p>
      )}
      {worthShowingHistory && <AttemptHistory attempts={job.attempts} />}
    </div>
  );
}

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const runId = id!;

  const query = useQuery({
    queryKey: ["run", runId],
    queryFn: () => fetchRun(runId),
    refetchInterval: (q) => (q.state.data?.status === "RUNNING" ? 3000 : false),
  });

  if (query.isLoading) {
    return (
      <Shell>
        <CenteredState>
          <p className="font-mono text-sm text-slate-400">Loading…</p>
        </CenteredState>
      </Shell>
    );
  }

  if (query.isError || !query.data) {
    return (
      <Shell>
        <CenteredState>
          <ErrorState message="Failed to load this scan." onRetry={() => query.refetch()} />
        </CenteredState>
      </Shell>
    );
  }

  const run = query.data;
  const failedCount = run.jobs.filter((j) => j.status === "FAILED").length;

  return (
    <Shell>
      <div className="w-full max-w-3xl text-left">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Scan</p>
            <h1 className="font-display text-2xl font-bold text-neon-cyan">
              <Link to={`/targets/${run.targetId}`} className="hover:underline">
                {run.targetHostname}
              </Link>
            </h1>
          </div>
          <Link to="/scans" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
            ← Active scans
          </Link>
        </div>

        <div className="mb-4 flex flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-neon-cyan/10 bg-panel/60 px-4 py-3 font-mono text-xs">
          <span className={`uppercase tracking-widest ${RUN_STATUS_STYLES[run.status] ?? "text-slate-400"}`}>
            {run.status}
          </span>
          <span className="text-slate-500">triggered by {run.triggeredBy}</span>
          <span className="text-slate-500">started {new Date(run.startedAt).toLocaleString()}</span>
          {run.completedAt && (
            <span className="text-slate-500">duration {formatDuration(run.startedAt, run.completedAt)}</span>
          )}
          {failedCount > 0 && (
            <span className="text-severity-critical">
              {failedCount} module{failedCount === 1 ? "" : "s"} failed
            </span>
          )}
        </div>

        <div className="rounded-lg border border-neon-cyan/20 bg-panel/80 px-4">
          {groupJobsByModule(run.jobs).map((group) =>
            group.jobs.length === 1 ? (
              <JobRow key={group.moduleType} job={group.jobs[0]} />
            ) : (
              <JobGroupSection key={group.moduleType} group={group} />
            ),
          )}
        </div>
      </div>
    </Shell>
  );
}
