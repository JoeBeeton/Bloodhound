import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CenteredState } from "../components/CenteredState";
import { ErrorState } from "../components/ErrorState";
import { FindingCard } from "../components/FindingCard";
import { FindingDetailModal } from "../components/FindingDetailModal";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { apiFetch, totalCountFromResponse } from "../lib/apiClient";
import { moduleLabel } from "../lib/moduleLabel";
import { groupJobsByModule, type JobGroup } from "../lib/scanJobs";
import type { Finding, ScanJobAttempt, ScanJobStatus, ScanRunDetail } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

async function fetchRun(runId: string): Promise<ScanRunDetail> {
  const res = await apiFetch(`/api/v1/runs/${runId}`);
  if (!res.ok) throw new Error("Failed to load scan.");
  return res.json();
}

/**
 * A product review found CANCELLED already treated as a real terminal status everywhere in the
 * UI (this page's own RUN_STATUS_STYLES, ScansPage's status filter/badge) despite there being no
 * way to actually produce one - a scan started by mistake, or one stuck on a dead worker, ran
 * until it finished on its own with no way to stop it. 409 (not a silent failure) means the run
 * finished on its own between the button being shown and this request landing - see
 * RunController#cancel.
 */
async function cancelRun(runId: string): Promise<ScanRunDetail> {
  const res = await apiFetch(`/api/v1/runs/${runId}/cancel`, { method: "POST" });
  if (!res.ok) throw new Error(res.status === 409 ? "This scan already finished." : "Failed to cancel scan.");
  return res.json();
}

interface FindingsPage {
  items: Finding[];
  totalCount: number;
}

/**
 * Same target-scoped "current open findings" endpoint TargetDetailPage uses, resolved through
 * the run's target rather than a path param (see FindingController.forRun) - a scan run doesn't
 * have its own separate findings set, so this shows the target's current state in the context of
 * this run, matching the endpoint's existing semantics.
 */
async function fetchRunFindings(runId: string): Promise<FindingsPage> {
  const res = await apiFetch(`/api/v1/runs/${runId}/findings?limit=500`);
  if (!res.ok) throw new Error("Failed to load findings.");
  const items: Finding[] = await res.json();
  return { items, totalCount: totalCountFromResponse(res, items.length) };
}

const RUN_STATUS_STYLES: Record<string, string> = {
  RUNNING: "text-neon-amber",
  COMPLETE: "text-neon-cyan",
  PARTIAL_FAILURE: "text-severity-critical",
  CANCELLED: "text-slate-500",
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
    return <p className="mt-1 font-mono text-[11px] text-muted">Not yet claimed by a worker.</p>;
  }
  return (
    <div className="mt-2 space-y-1.5 border-l-2 border-slate-800 pl-3">
      {attempts.map((a) => (
        <div key={a.attemptNumber} className="font-mono text-[11px]">
          <div className="flex items-center gap-2">
            <span className="text-slate-500">#{a.attemptNumber}</span>
            <span className="text-slate-400">{a.claimedBy}</span>
            <span className="text-muted">{formatDuration(a.startedAt, a.endedAt)}</span>
            <span className={a.outcome ? OUTCOME_STYLES[a.outcome] ?? "text-slate-400" : "text-neon-amber animate-pulse"}>
              {a.outcome ?? "IN PROGRESS"}
            </span>
          </div>
          {a.errorDetail && <p className="mt-0.5 text-slate-500">{a.errorDetail}</p>}
          {a.logOutput && <AttemptLogToggle logOutput={a.logOutput} />}
        </div>
      ))}
    </div>
  );
}

/** Collapsed by default - most attempts a user looks at never need the full log, and a 500-line
 * capture rendered open by default on every attempt would overwhelm a job with several retries. */
function AttemptLogToggle({ logOutput }: { logOutput: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-1">
      <button
        onClick={() => setOpen((v) => !v)}
        className="font-mono text-[10px] uppercase tracking-widest text-neon-cyan/70 transition hover:text-neon-cyan"
      >
        {open ? "▾ hide logs" : "▸ view logs"}
      </button>
      {open && (
        <pre className="mt-1 max-h-64 overflow-y-auto whitespace-pre-wrap rounded border border-neon-cyan/10 bg-void/60 p-2 text-[10px] text-slate-400">
          {logOutput}
        </pre>
      )}
    </div>
  );
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
  const queryClient = useQueryClient();
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  // Cancelling stops the scan permanently and can't be undone (see RunController#cancel's own
  // javadoc for exactly what does/doesn't get interrupted) - same confirmation-modal pattern as
  // every other irreversible-but-self-service action in this app (ApiKeysPage's revoke,
  // TargetsPage's remove).
  const [confirmingCancel, setConfirmingCancel] = useState(false);

  const query = useQuery({
    queryKey: ["run", runId],
    queryFn: () => fetchRun(runId),
    refetchInterval: (q) => (q.state.data?.status === "RUNNING" ? 3000 : false),
  });
  usePageTitle(query.data ? `Scan: ${query.data.targetHostname}` : null);

  const findingsQuery = useQuery({
    queryKey: ["run-findings", runId],
    queryFn: () => fetchRunFindings(runId),
  });

  const cancelMutation = useMutation({
    mutationFn: () => cancelRun(runId),
    onSuccess: (detail) => {
      setConfirmingCancel(false);
      queryClient.setQueryData(["run", runId], detail);
      queryClient.invalidateQueries({ queryKey: ["scans-active"] });
      queryClient.invalidateQueries({ queryKey: ["scans-recent"] });
    },
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
          <div className="flex items-center gap-4">
            {run.status === "RUNNING" && (
              <button
                onClick={() => setConfirmingCancel(true)}
                className="font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:underline"
              >
                Cancel scan
              </button>
            )}
            <Link to="/scans" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
              ← Active scans
            </Link>
          </div>
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

        <div className="mb-6 rounded-lg border border-neon-cyan/20 bg-panel/80 px-4">
          {groupJobsByModule(run.jobs).map((group) =>
            group.jobs.length === 1 ? (
              <JobRow key={group.moduleType} job={group.jobs[0]} />
            ) : (
              <JobGroupSection key={group.moduleType} group={group} />
            ),
          )}
        </div>

        <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-slate-400">
          Findings {findingsQuery.data ? `(${findingsQuery.data.totalCount})` : ""}
        </h2>
        {findingsQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading findings…</p>}
        {findingsQuery.isError && (
          <ErrorState message="Failed to load findings." onRetry={() => findingsQuery.refetch()} />
        )}
        {findingsQuery.data?.totalCount === 0 && (
          <p className="font-mono text-sm text-slate-400">No findings from this scan's target.</p>
        )}
        <div className="flex flex-col gap-3">
          {findingsQuery.data?.items.map((finding) => (
            <FindingCard key={finding.id} finding={finding} onSelect={() => setSelectedFinding(finding)} />
          ))}
        </div>
      </div>

      {selectedFinding && <FindingDetailModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}

      {confirmingCancel && (
        <Modal title="Cancel scan" onClose={() => setConfirmingCancel(false)}>
          <p className="mb-4 text-sm text-slate-300">
            Cancel this scan of <span className="font-mono text-neon-cyan">{run.targetHostname}</span>? Jobs a worker
            has already claimed will still finish, but no further findings from this run will be collected and no
            score will be computed from it. This cannot be undone.
          </p>
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setConfirmingCancel(false)}
              className="rounded border border-slate-700 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-slate-500"
            >
              Keep running
            </button>
            <button
              onClick={() => cancelMutation.mutate()}
              disabled={cancelMutation.isPending}
              className="rounded border border-severity-critical/50 px-3 py-1.5 font-mono text-xs uppercase tracking-widest text-severity-critical transition hover:bg-severity-critical/10 disabled:opacity-40"
            >
              {cancelMutation.isPending ? "Cancelling…" : "Cancel scan"}
            </button>
          </div>
          {cancelMutation.isError && (
            <p className="mt-2 font-mono text-xs text-severity-critical">
              {(cancelMutation.error as Error).message}
            </p>
          )}
        </Modal>
      )}
    </Shell>
  );
}
