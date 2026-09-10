import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import { moduleLabel } from "../lib/moduleLabel";
import { MODULE_STATUS_STYLES } from "../lib/moduleStatusStyles";
import type { ActiveScan } from "../lib/types";

async function fetchActiveScans(): Promise<ActiveScan[]> {
  const res = await apiFetch("/api/v1/scans/active");
  if (!res.ok) throw new Error("Failed to load active scans.");
  return res.json();
}

/** module_type -> how many of that type can be CLAIMED/RUNNING at once - currently just
 * ZAP_ACTIVE_SCAN (one shared zap sidecar). Absent entry means no cap. */
async function fetchQueueLimits(): Promise<Record<string, number>> {
  const res = await apiFetch("/api/v1/scans/queue-limits");
  if (!res.ok) throw new Error("Failed to load queue limits.");
  return res.json();
}

interface QueueRow {
  targetHostname: string;
  status: string;
  /** Tier 2 jobs dispatch one job per host - this is that specific host; null for Tier 1. */
  host: string | null;
}

interface ModuleGroup {
  moduleType: string;
  active: QueueRow[];
  pending: QueueRow[];
  limit: number | undefined;
}

const NOT_QUEUED = new Set(["COMPLETE", "FAILED", "CANCELLED"]);

function groupQueue(scans: ActiveScan[], limits: Record<string, number>): ModuleGroup[] {
  const byType = new Map<string, ModuleGroup>();
  for (const scan of scans) {
    for (const m of scan.modules) {
      if (NOT_QUEUED.has(m.status)) continue;
      let g = byType.get(m.moduleType);
      if (!g) {
        g = { moduleType: m.moduleType, active: [], pending: [], limit: limits[m.moduleType] };
        byType.set(m.moduleType, g);
      }
      const row: QueueRow = { targetHostname: scan.targetHostname, status: m.status, host: m.host };
      (m.status === "PENDING" ? g.pending : g.active).push(row);
    }
  }
  // Busiest (most jobs total) first - that's the module type an admin is most likely wondering about.
  return Array.from(byType.values()).sort((a, b) => b.active.length + b.pending.length - (a.active.length + a.pending.length));
}

function QueueRowItem({ row }: { row: QueueRow }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded border border-white/5 bg-void/40 px-2 py-1">
      <span className="truncate font-mono text-[11px] text-slate-300" title={row.host ?? row.targetHostname}>
        {row.host ?? row.targetHostname}
      </span>
      <span className={`shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-widest ${MODULE_STATUS_STYLES[row.status] ?? MODULE_STATUS_STYLES.PENDING}`}>
        {row.status}
      </span>
    </div>
  );
}

function ModuleGroupCard({ group }: { group: ModuleGroup }) {
  const atCap = group.limit !== undefined && group.active.length >= group.limit;
  return (
    <div className="rounded-lg border border-neon-cyan/10 bg-panel/60 p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="font-mono text-xs font-bold uppercase tracking-widest text-slate-200">{moduleLabel(group.moduleType)}</p>
        <span className="shrink-0 font-mono text-[10px] uppercase tracking-widest text-slate-500">
          {group.limit !== undefined ? `${group.active.length}/${group.limit} active` : `${group.active.length} active`}
          {group.pending.length > 0 && ` · ${group.pending.length} queued`}
        </span>
      </div>
      <div className="flex flex-col gap-1">
        {group.active.map((row, i) => (
          <QueueRowItem key={`active-${i}`} row={row} />
        ))}
        {group.pending.map((row, i) => (
          <QueueRowItem key={`pending-${i}`} row={row} />
        ))}
      </div>
      {/* Explains, not just shows, why a PENDING job in this group isn't just picked up
          immediately - a live report mistook this cap for a broken claim/distribution mechanism. */}
      {atCap && (
        <p className="mt-2 border-t border-white/5 pt-2 font-mono text-[10px] text-slate-500">
          All {group.limit} {moduleLabel(group.moduleType)} slot{group.limit === 1 ? "" : "s"} in use - queued jobs wait for one to free up,
          regardless of how many workers are idle.
        </p>
      )}
    </div>
  );
}

/** Poll interval matches WorkerPanel/the rest of the Map page - all "what's happening right
 * now" views share one cadence, no reason for a second timer. */
export function JobQueuePanel({ pollIntervalMs }: { pollIntervalMs: number }) {
  const activeQuery = useQuery({ queryKey: ["scans-active"], queryFn: fetchActiveScans, refetchInterval: pollIntervalMs });
  // Limits are static config, not "live" state - a slow, independent poll (or none at all)
  // would be enough, but reusing the same query key/cadence elsewhere keeps this simple and
  // the call itself is cheap (a two-line in-memory map, no DB query).
  const limitsQuery = useQuery({ queryKey: ["scans-queue-limits"], queryFn: fetchQueueLimits, refetchInterval: pollIntervalMs * 6 });

  const groups = useMemo(
    () => groupQueue(activeQuery.data ?? [], limitsQuery.data ?? {}),
    [activeQuery.data, limitsQuery.data],
  );

  return (
    <div className="w-full">
      <p className="mb-3 font-mono text-xs uppercase tracking-[0.3em] text-neon-magenta">Job Queue</p>

      {activeQuery.isLoading && <p className="font-mono text-xs text-slate-500">Loading…</p>}
      {activeQuery.isError && <p className="font-mono text-xs text-severity-critical/80">Failed to load the job queue.</p>}

      {activeQuery.data && (
        <>
          {groups.length === 0 ? (
            <p className="font-mono text-xs text-muted">Nothing queued or running right now.</p>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {groups.map((g) => (
                <ModuleGroupCard key={g.moduleType} group={g} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
