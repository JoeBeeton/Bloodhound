import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { CenteredState } from "../components/CenteredState";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { WorkerPanel } from "../components/WorkerPanel";
import { apiFetch } from "../lib/apiClient";
import type { ActiveScan, ActiveScanModule, RecentScan } from "../lib/types";

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

async function fetchRecentScans(): Promise<RecentScan[]> {
  const res = await apiFetch("/api/v1/scans/recent?limit=30");
  if (!res.ok) throw new Error("Failed to load recent scans.");
  return res.json();
}

const RECENT_STATUS_STYLES: Record<string, string> = {
  RUNNING: "text-neon-amber",
  COMPLETE: "text-neon-cyan",
  PARTIAL_FAILURE: "text-severity-critical",
  FAILED: "text-severity-critical",
  CANCELLED: "text-slate-500",
};

function RecentScansSection() {
  const query = useQuery({ queryKey: ["scans-recent"], queryFn: fetchRecentScans });

  if (query.isLoading) {
    return <p className="font-mono text-sm text-slate-400">Loading…</p>;
  }
  if (query.isError) {
    return <ErrorState message="Failed to load recent scans." onRetry={() => query.refetch()} />;
  }
  if (!query.data || query.data.length === 0) {
    return <p className="font-mono text-sm text-slate-400">No scans have run yet.</p>;
  }

  return (
    <div className="overflow-hidden rounded-lg border border-neon-cyan/20 bg-panel/60">
      {query.data.map((scan, i) => (
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

function ScanCard({ scan }: { scan: ActiveScan }) {
  const pct = scan.totalJobs > 0 ? Math.round((scan.completedJobs / scan.totalJobs) * 100) : 0;
  return (
    <Link
      to={`/scans/${scan.id}`}
      className="block rounded-lg border border-neon-cyan/20 bg-panel/80 p-5 transition hover:border-neon-cyan/50 hover:shadow-glow-cyan"
    >
      <div className="mb-3 flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-sm text-slate-200">{scan.targetHostname}</p>
          <p className="mt-0.5 font-mono text-[11px] uppercase tracking-widest text-slate-500">
            {scan.triggeredBy} · running {formatElapsed(scan.startedAt)}
          </p>
        </div>
        <p className="whitespace-nowrap font-mono text-xs uppercase tracking-widest text-neon-amber">
          {formatEta(scan.etaSeconds)}
        </p>
      </div>

      <div className="mb-3">
        <div className="mb-1 flex items-center justify-between font-mono text-[11px] text-slate-400">
          <span>
            {scan.completedJobs}/{scan.totalJobs} modules complete
          </span>
          <span>{pct}%</span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
          <div className="h-full rounded-full bg-neon-cyan transition-all" style={{ width: `${pct}%` }} />
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
  );
}

export function ScansPage() {
  const query = useQuery({
    queryKey: ["scans-active"],
    queryFn: fetchActiveScans,
    refetchInterval: POLL_INTERVAL_MS,
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
              <p className="mt-1 font-mono text-xs text-slate-600">
                Scans you trigger, or that run on schedule, will show up here while in progress.
              </p>
            </div>
          )}

          {query.data && query.data.length > 0 && (
            <div className="flex flex-col gap-3">
              {query.data.map((scan) => (
                <ScanCard key={scan.id} scan={scan} />
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
    </Shell>
  );
}
