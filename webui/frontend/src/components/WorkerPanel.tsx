import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/apiClient";
import { workerEndpoint } from "../lib/attackSurfaceGraph";
import { moduleLabel } from "../lib/moduleLabel";
import type { WorkerStatus } from "../lib/types";

async function fetchWorkers(): Promise<WorkerStatus[]> {
  const res = await apiFetch("/api/v1/workers");
  if (!res.ok) throw new Error("Failed to load workers.");
  return res.json();
}

const STATUS_STYLES: Record<WorkerStatus["status"], string> = {
  IDLE: "border-slate-700 text-slate-400",
  BUSY: "border-neon-amber/50 text-neon-amber",
  OFFLINE: "border-severity-critical/40 text-severity-critical/80",
};

const STATUS_DOT: Record<WorkerStatus["status"], string> = {
  IDLE: "bg-slate-500",
  BUSY: "bg-neon-amber animate-pulse",
  OFFLINE: "bg-severity-critical",
};

function WorkerRow({ worker }: { worker: WorkerStatus }) {
  // Same hostname:port split the Attack Surface Map already shows for a worker node - the raw
  // "hostname-randomsuffix" id (see WorkerApplication#workerId) is real but not something an
  // analyst needs to read at a glance here; it's still available in the tooltip.
  const endpoint = workerEndpoint(worker.workerId);
  return (
    <div className={`rounded-lg border bg-panel/60 px-3 py-2.5 ${STATUS_STYLES[worker.status]}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-baseline gap-1.5 truncate font-mono text-xs text-slate-200" title={worker.workerId}>
          {endpoint.hostname}
          <span className="text-[10px] text-slate-500">:{endpoint.port}</span>
        </span>
        <span className={`h-2 w-2 shrink-0 rounded-full ${STATUS_DOT[worker.status]}`} />
      </div>
      <p className="mt-1 font-mono text-[10px] uppercase tracking-widest">{worker.status}</p>
      {worker.status === "BUSY" && worker.targetHostname && (
        <div className="mt-1.5 border-t border-white/5 pt-1.5">
          <p className="truncate font-mono text-[11px] text-slate-300" title={worker.currentHost ?? worker.targetHostname}>
            {worker.currentHost ?? worker.targetHostname}
          </p>
          {worker.currentHost && worker.currentHost !== worker.targetHostname && (
            <p className="truncate font-mono text-[9px] text-slate-500">of {worker.targetHostname}</p>
          )}
          <p className="truncate font-mono text-[10px] text-neon-amber/80">{moduleLabel(worker.moduleType)}</p>
        </div>
      )}
      {worker.status === "BUSY" && !worker.targetHostname && (
        <p className="mt-1.5 border-t border-white/5 pt-1.5 font-mono text-[10px] text-slate-500">
          busy on another organization&apos;s scan
        </p>
      )}
    </div>
  );
}

/** Poll interval matches ScansPage's own - both are "what's happening right now" views, no reason for a second timer. */
export function WorkerPanel({ pollIntervalMs }: { pollIntervalMs: number }) {
  const query = useQuery({
    queryKey: ["workers"],
    queryFn: fetchWorkers,
    refetchInterval: pollIntervalMs,
  });

  return (
    <div className="w-full shrink-0 lg:w-56">
      <p className="mb-3 font-mono text-xs uppercase tracking-[0.3em] text-neon-magenta">Workers</p>

      {query.isLoading && <p className="font-mono text-xs text-slate-500">Loading…</p>}
      {query.isError && <p className="font-mono text-xs text-severity-critical/80">Failed to load workers.</p>}

      {query.data && (
        <div className="flex flex-col gap-2">
          {query.data.map((w) => (
            <WorkerRow key={w.workerId} worker={w} />
          ))}
          {query.data.length === 0 && <p className="font-mono text-xs text-muted">No workers seen yet.</p>}
        </div>
      )}
    </div>
  );
}
