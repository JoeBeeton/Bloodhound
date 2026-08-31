import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CenteredState } from "../components/CenteredState";
import { ErrorState } from "../components/ErrorState";
import { Modal } from "../components/Modal";
import { Shell } from "../components/Shell";
import { WorkerPanel } from "../components/WorkerPanel";
import { apiFetch, totalCountFromResponse } from "../lib/apiClient";
import type { ActiveScan, ActiveScanModule, RecentScan } from "../lib/types";
import { usePageTitle } from "../lib/usePageTitle";

const TERMINAL = new Set(["COMPLETE", "FAILED", "CANCELLED"]);
// Worst-first: a group's badge should reflect the most attention-worthy job in it,
// not just whichever happened to be last in the array.
const STATUS_PRIORITY = ["FAILED", "RUNNING", "CLAIMED", "PENDING", "COMPLETE"];

interface ModuleGroup {
  moduleType: string;
  total: number;
  done: number;
  worstStatus: string;
  hosts: string[];
  /** Hosts a job is actively working on right now (RUNNING or CLAIMED) - shown directly in
   * the UI rather than buried in a hover-only tooltip, since "which host is being scanned"
   * is exactly what's useful to see at a glance while a scan is in progress. */
  runningHosts: string[];
}

/**
 * Tier 2 modules dispatch one job per host now (see ScanRunService#createDeepScan), so
 * `scan.modules` can contain many entries sharing the same moduleType - group them into
 * one badge per module type with an aggregate count/status, instead of rendering (and
 * React-key-colliding on) one badge per host.
 */
function groupModules(modules: ActiveScanModule[]): ModuleGroup[] {
  const byType = new Map<string, ModuleGroup>();
  for (const m of modules) {
    let g = byType.get(m.moduleType);
    if (!g) {
      g = { moduleType: m.moduleType, total: 0, done: 0, worstStatus: m.status, hosts: [], runningHosts: [] };
      byType.set(m.moduleType, g);
    }
    g.total += 1;
    if (TERMINAL.has(m.status)) g.done += 1;
    if (STATUS_PRIORITY.indexOf(m.status) < STATUS_PRIORITY.indexOf(g.worstStatus)) g.worstStatus = m.status;
    if (m.host) g.hosts.push(m.host);
    if (m.host && (m.status === "RUNNING" || m.status === "CLAIMED")) g.runningHosts.push(m.host);
  }
  return Array.from(byType.values());
}

async function fetchActiveScans(): Promise<ActiveScan[]> {
  const res = await apiFetch("/api/v1/scans/active");
  if (!res.ok) throw new Error("Failed to load active scans.");
  return res.json();
}

/**
 * A product review found cancelling a scan required navigating to its own detail page first -
 * an extra click for exactly the page whose whole purpose is "what's running right now, and do
 * I need to do anything about it". Same endpoint/semantics as ScanDetailPage's own cancelRun -
 * see RunController#cancel for what does and doesn't get interrupted.
 */
async function cancelActiveScan(runId: string): Promise<void> {
  const res = await apiFetch(`/api/v1/runs/${runId}/cancel`, { method: "POST" });
  if (!res.ok) throw new Error(res.status === 409 ? "This scan already finished." : "Failed to cancel scan.");
}

interface RecentScansPage {
  items: RecentScan[];
  totalCount: number;
}

const RECENT_SCAN_STATUSES = ["RUNNING", "COMPLETE", "PARTIAL_FAILURE", "FAILED", "CANCELLED"] as const;
const RECENT_PAGE_SIZE = 30;

async function fetchRecentScans(status: string | null, limit: number): Promise<RecentScansPage> {
  const params = new URLSearchParams({ limit: String(limit), offset: "0" });
  if (status) params.set("status", status);
  const res = await apiFetch(`/api/v1/scans/recent?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load recent scans.");
  const items: RecentScan[] = await res.json();
  return { items, totalCount: totalCountFromResponse(res, items.length) };
}

const RECENT_STATUS_STYLES: Record<string, string> = {
  RUNNING: "text-neon-amber",
  COMPLETE: "text-neon-cyan",
  PARTIAL_FAILURE: "text-severity-critical",
  FAILED: "text-severity-critical",
  CANCELLED: "text-slate-500",
};

const INACTIVE_STATUS_CHIP = "border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-200";

/**
 * A product review found this list had no way to narrow past a fixed most-recent-30, despite
 * status/target/time being exactly what someone diagnosing "did target X's scan actually fail
 * last night" would want to filter by. Status is single-select (clicking the active one again
 * clears it) rather than multi-select like FindingsFilterBar's severity/category chips - "which
 * scans failed" is a single yes/no question here, not a multi-value narrowing filter.
 */
function RecentScansSection() {
  const [status, setStatus] = useState<string | null>(null);
  const [visibleCount, setVisibleCount] = useState(RECENT_PAGE_SIZE);

  const query = useQuery({
    queryKey: ["scans-recent", status, visibleCount],
    queryFn: () => fetchRecentScans(status, visibleCount),
  });

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        <span className="mr-1 font-mono text-[10px] uppercase tracking-widest text-slate-500">Status</span>
        {RECENT_SCAN_STATUSES.map((s) => {
          const active = status === s;
          return (
            <button
              key={s}
              aria-pressed={active}
              onClick={() => {
                setStatus(active ? null : s);
                setVisibleCount(RECENT_PAGE_SIZE);
              }}
              className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest transition ${
                active ? "border-neon-cyan bg-neon-cyan/15 text-neon-cyan" : INACTIVE_STATUS_CHIP
              }`}
            >
              {s.replace("_", " ")}
            </button>
          );
        })}
        {status && (
          <button
            onClick={() => {
              setStatus(null);
              setVisibleCount(RECENT_PAGE_SIZE);
            }}
            className="font-mono text-[10px] uppercase tracking-widest text-neon-magenta transition hover:text-neon-magenta/70"
          >
            Clear ✕
          </button>
        )}
      </div>

      {query.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
      {query.isError && <ErrorState message="Failed to load recent scans." onRetry={() => query.refetch()} />}
      {query.data && query.data.items.length === 0 && (
        <p className="font-mono text-sm text-slate-400">
          {status ? `No ${status.replace("_", " ").toLowerCase()} scans found.` : "No scans have run yet."}
        </p>
      )}

      {query.data && query.data.items.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-neon-cyan/20 bg-panel/60">
          {query.data.items.map((scan, i) => (
            <Link
              key={scan.id}
              to={`/scans/${scan.id}`}
              className={`flex items-center justify-between px-4 py-2.5 transition hover:bg-panel ${
                i > 0 ? "border-t border-neon-cyan/10" : ""
              }`}
            >
              <div>
                <p className="font-mono text-sm text-slate-200">{scan.targetHostname}</p>
                <p className="font-mono text-[11px] text-slate-500">
                  {scan.triggeredBy} · {new Date(scan.startedAt).toLocaleString()}
                </p>
              </div>
              <span
                className={`font-mono text-xs uppercase tracking-widest ${
                  RECENT_STATUS_STYLES[scan.status] ?? "text-slate-400"
                }`}
              >
                {scan.status.replace("_", " ")}
              </span>
            </Link>
          ))}
        </div>
      )}

      {query.data && query.data.items.length < query.data.totalCount && (
        <button
          onClick={() => setVisibleCount((c) => c + RECENT_PAGE_SIZE)}
          className="mt-3 font-mono text-xs uppercase tracking-widest text-neon-cyan transition hover:text-neon-cyan/70"
        >
          Load more ▾ ({query.data.totalCount - query.data.items.length} more)
        </button>
      )}
    </div>
  );
}

// This page is specifically about "what's happening right now" - it should feel live.
const POLL_INTERVAL_MS = 4_000;

const MODULE_STATUS_STYLES: Record<string, string> = {
  PENDING: "bg-slate-700 text-slate-400",
  CLAIMED: "bg-neon-amber/20 text-neon-amber",
  RUNNING: "bg-neon-amber/20 text-neon-amber animate-pulse",
  COMPLETE: "bg-neon-cyan/20 text-neon-cyan",
  FAILED: "bg-severity-critical/20 text-severity-critical",
  // A cancelled run drops out of this active-scans list within one poll cycle, so this is a
  // narrow window - added anyway for the same reason every other status-style map in this sweep
  // got it: an undefined entry falls back to the exact same style PENDING gets below.
  CANCELLED: "bg-slate-800 text-muted",
};

function formatElapsed(startedAt: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

function formatEta(etaSeconds: number | null): string {
  if (etaSeconds === null) return "estimating…";
  if (etaSeconds <= 0) return "any moment now";
  if (etaSeconds < 60) return `~${etaSeconds}s remaining`;
  const minutes = Math.round(etaSeconds / 60);
  return `~${minutes}m remaining`;
}

/** A scan whose progress bar is still climbing toward 100% can already have a dead module
 * in it - completedJobs counts FAILED as "done" same as COMPLETE (see ScanRunService), so a
 * plain percentage reads as "on track" even when something's actually broken. Surfacing that
 * distinctly (color, not just a badge buried in the module row) is what makes this list
 * useful to scan at a glance instead of requiring a click into every card. */
export function scanHasFailure(scan: ActiveScan): boolean {
  return scan.modules.some((m) => m.status === "FAILED");
}

function ScanCard({ scan, onRequestCancel }: { scan: ActiveScan; onRequestCancel: (scan: ActiveScan) => void }) {
  const pct = scan.totalJobs > 0 ? Math.round((scan.completedJobs / scan.totalJobs) * 100) : 0;
  const hasFailure = scanHasFailure(scan);
  return (
    // Cancel below is a sibling of the Link, not nested inside it - a <button> inside an <a> is
    // invalid HTML and would fire both the button's onClick and a navigation on the same click.
    // Absolutely positioned into the same top-right corner the ETA/failure text already occupies
    // rather than adding a new row, so the card's height stays exactly what it was.
    <div className="relative">
      <Link
        to={`/scans/${scan.id}`}
        className={`block rounded-lg border bg-panel/80 p-5 pr-24 transition ${
          hasFailure
            ? "border-severity-critical/40 hover:border-severity-critical/70 hover:shadow-[0_0_8px_#ff2e97,0_0_24px_rgba(255,46,151,0.5)]"
            : "border-neon-cyan/20 hover:border-neon-cyan/50 hover:shadow-glow-cyan"
        }`}
      >
      <div className="mb-3 flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-sm text-slate-200">{scan.targetHostname}</p>
          <p className="mt-0.5 font-mono text-[11px] uppercase tracking-widest text-slate-500">
            {scan.triggeredBy} · running {formatElapsed(scan.startedAt)}
          </p>
        </div>
        {hasFailure ? (
          <p className="whitespace-nowrap font-mono text-xs uppercase tracking-widest text-severity-critical">
            ⚠ module failed
          </p>
        ) : (
          <p className="whitespace-nowrap font-mono text-xs uppercase tracking-widest text-neon-amber">
            {formatEta(scan.etaSeconds)}
          </p>
        )}
      </div>

      <div className="mb-3">
        <div className="mb-1 flex items-center justify-between font-mono text-[11px] text-slate-400">
          <span>
            {scan.completedJobs}/{scan.totalJobs} modules complete
          </span>
          <span>{pct}%</span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
          <div
            className={`h-full rounded-full transition-all ${hasFailure ? "bg-severity-critical" : "bg-neon-cyan"}`}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {groupModules(scan.modules).map((g) => (
          <span
            key={g.moduleType}
            className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
              MODULE_STATUS_STYLES[g.worstStatus] ?? "bg-slate-700 text-slate-400"
            }`}
            title={g.hosts.length > 1 ? g.hosts.join(", ") : undefined}
          >
            {g.moduleType}
            {g.total > 1 && ` (${g.done}/${g.total})`}
          </span>
        ))}
      </div>

      {groupModules(scan.modules).some((g) => g.runningHosts.length > 0) && (
        <div className="mt-2 truncate font-mono text-[10px] text-neon-cyan/80">
          <span className="text-slate-500">scanning: </span>
          {groupModules(scan.modules)
            .flatMap((g) => g.runningHosts)
            .join(", ")}
        </div>
      )}
      </Link>
      <button
        type="button"
        onClick={() => onRequestCancel(scan)}
        className="absolute right-5 top-5 rounded border border-slate-700 bg-panel px-2 py-1 font-mono text-[10px] uppercase tracking-widest text-slate-400 transition hover:border-severity-critical/50 hover:text-severity-critical"
      >
        Cancel
      </button>
    </div>
  );
}

export function ScansPage() {
  usePageTitle("Active Scans");
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["scans-active"],
    queryFn: fetchActiveScans,
    refetchInterval: POLL_INTERVAL_MS,
  });
  // Cancelling is destructive-but-self-service and can't be undone (see RunController#cancel's
  // own javadoc for exactly what does/doesn't get interrupted) - same confirm-before-destroying
  // modal pattern as every other irreversible action in this app. Lives here, not inside
  // ScanCard, so the modal is never a DOM descendant of any card's own clickable <Link> - a
  // click anywhere inside it would otherwise bubble up and could be misread as "open this card".
  const [pendingCancel, setPendingCancel] = useState<ActiveScan | null>(null);
  const cancelMutation = useMutation({
    mutationFn: () => cancelActiveScan(pendingCancel!.id),
    onSuccess: () => {
      setPendingCancel(null);
      queryClient.invalidateQueries({ queryKey: ["scans-active"] });
      queryClient.invalidateQueries({ queryKey: ["scans-recent"] });
    },
  });

  return (
    <Shell>
      <div className="flex w-full max-w-5xl flex-col gap-8 text-left lg:flex-row">
        <WorkerPanel pollIntervalMs={POLL_INTERVAL_MS} />

        <div className="min-w-0 flex-1">
          <div className="mb-6 flex items-center justify-between">
            <div>
              <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Live</p>
              <h1 className="font-display text-2xl font-bold text-neon-cyan">Active Scans</h1>
            </div>
            <Link to="/dashboard" className="font-mono text-xs uppercase tracking-widest text-slate-400 hover:text-neon-cyan">
              ← Dashboard
            </Link>
          </div>

          {query.isLoading && (
            <CenteredState>
              <p className="font-mono text-sm text-slate-400">Loading…</p>
            </CenteredState>
          )}

          {query.isError && (
            <ErrorState message="Failed to load active scans." onRetry={() => query.refetch()} />
          )}

          {query.data && query.data.length === 0 && (
            <div className="rounded-lg border border-neon-cyan/10 bg-panel/60 px-6 py-10 text-center">
              <p className="font-mono text-sm text-slate-400">Nothing is currently scanning.</p>
              <p className="mt-1 font-mono text-xs text-muted">
                Scans you trigger, or that run on schedule, will show up here while in progress.
              </p>
            </div>
          )}

          {query.data && query.data.length > 0 && (
            <div className="flex flex-col gap-3">
              {query.data.map((scan) => (
                <ScanCard key={scan.id} scan={scan} onRequestCancel={setPendingCancel} />
              ))}
            </div>
          )}

          {/* A scan that fails drops out of the list above the moment it reaches a terminal
              state (that list is RUNNING-only) - without this, there'd be no way back to a
              failed scan's diagnosis page once it's no longer actively running. */}
          <div className="mt-10">
            <h2 className="mb-3 font-display text-lg font-bold text-neon-magenta">Recent Scans</h2>
            <RecentScansSection />
          </div>
        </div>
      </div>

      {pendingCancel && (
        <Modal title="Cancel scan" onClose={() => setPendingCancel(null)}>
          <p className="mb-4 text-sm text-slate-300">
            Cancel this scan of <span className="font-mono text-neon-cyan">{pendingCancel.targetHostname}</span>? Jobs a
            worker has already claimed will still finish, but no further findings from this run will be collected and
            no score will be computed from it. This cannot be undone.
          </p>
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setPendingCancel(null)}
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
            <p role="alert" className="mt-2 font-mono text-xs text-severity-critical">
              {(cancelMutation.error as Error).message}
            </p>
          )}
        </Modal>
      )}
    </Shell>
  );
}
